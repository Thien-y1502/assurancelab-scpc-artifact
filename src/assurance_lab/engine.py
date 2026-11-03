from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable, Mapping

from .models import (
    AuditDecision,
    DecisionState,
    Evidence,
    BusinessOracle,
    ServiceContract,
)
from .provenance import evidence_hash
from .semantics import aggregate_states


class AssuranceEngine:
    """Deterministic contract evaluator.

    The alpha intentionally prefers uncertainty to optimistic acceptance. It
    does not infer a control from a similarly worded assertion and it never
    treats stale, missing, or conflicting evidence as PASS.
    """

    def __init__(self, rule_version: str = "engine-v0.1", *, require_integrity: bool = False, require_signature: bool = False, require_replay: bool = False, require_independence: bool = False, require_provenance: bool = True, bind_subject: bool = True, max_future_skew_seconds: float | None = None, require_dependency_binding: bool = False, require_business_oracle: bool = False, require_business_linkage: bool = False) -> None:
        self.rule_version = rule_version
        self.require_integrity = require_integrity
        self.require_signature = require_signature
        self.require_replay = require_replay
        self.require_independence = require_independence
        self.require_provenance = require_provenance
        self.bind_subject = bind_subject
        self.max_future_skew = None if max_future_skew_seconds is None else timedelta(seconds=max_future_skew_seconds)
        self.require_dependency_binding = require_dependency_binding
        self.require_business_oracle = require_business_oracle
        self.require_business_linkage = require_business_linkage

    def evaluate(
        self,
        contract: ServiceContract,
        evidence: Iterable[Evidence],
        *,
        now: datetime,
        standard_pack_versions: tuple[str, ...] = (),
        business_oracle: BusinessOracle | None = None,
    ) -> AuditDecision:
        evidence_items = tuple(evidence)
        subject_mismatches = tuple(item for item in evidence_items if item.subject != contract.service_id)
        scoped_evidence = tuple(item for item in evidence_items if not self.bind_subject or item.subject == contract.service_id)
        by_assertion: dict[str, list[Evidence]] = defaultdict(list)
        for item in scoped_evidence:
            by_assertion[item.assertion].append(item)

        control_results: dict[str, DecisionState] = {}
        dependency_results: dict[str, DecisionState] = {}
        objective_results: dict[str, DecisionState] = {}
        reasons: list[str] = []
        used_ids: list[str] = []
        if subject_mismatches and self.bind_subject:
            reasons.append("subject_binding:ignored=" + ",".join(item.evidence_id for item in subject_mismatches))

        for control in contract.controls:
            matches = by_assertion.get(control.assertion, [])
            result, detail, ids = self._evaluate_assertion(
                matches, control.expected_value, now, self.require_integrity, self.require_signature, self.require_replay, self.require_independence, self.require_provenance, self.max_future_skew
            )
            control_results[control.control_id] = result
            used_ids.extend(ids)
            reasons.append(f"control:{control.control_id}:{detail}")

        bound_dependencies = {item.dependency_id for item in contract.dependency_requirements}
        unbound_dependencies = tuple(sorted(set(contract.dependencies) - bound_dependencies))
        if unbound_dependencies:
            detail = "dependency_binding:unbound=" + ",".join(unbound_dependencies)
            reasons.append(detail)
            if self.require_dependency_binding:
                dependency_results["__unbound__"] = DecisionState.UNKNOWN
        for dependency in contract.dependency_requirements:
            matches = by_assertion.get(dependency.assertion, [])
            result, detail, ids = self._evaluate_assertion(
                matches, dependency.expected_value, now, self.require_integrity, self.require_signature, self.require_replay, self.require_independence, self.require_provenance, self.max_future_skew
            )
            dependency_results[dependency.dependency_id] = result
            used_ids.extend(ids)
            reasons.append(f"dependency:{dependency.dependency_id}:{detail}")

        for objective in contract.objectives:
            matches = by_assertion.get(objective.metric, [])
            if not matches:
                result, detail, ids = DecisionState.UNKNOWN, "missing", ()
            else:
                result, detail, ids = self._evaluate_objective(
                    matches, objective.target, objective.comparator, now, self.require_integrity, self.require_signature, self.require_replay, self.require_independence, self.require_provenance, self.max_future_skew
                )
            objective_results[objective.objective_id] = result
            used_ids.extend(ids)
            reasons.append(f"objective:{objective.objective_id}:{detail}")

        business_linkage_result: DecisionState | None = None
        if self.require_business_linkage and contract.controls and contract.objectives:
            if not contract.control_objective_links:
                business_linkage_result = DecisionState.UNKNOWN
                reasons.append("business_linkage:missing")
            else:
                linked_controls = {item.control_id for item in contract.control_objective_links}
                linked_objectives = {item.objective_id for item in contract.control_objective_links}
                unbound_controls = tuple(sorted({item.control_id for item in contract.controls} - linked_controls))
                unbound_objectives = tuple(sorted({item.objective_id for item in contract.objectives} - linked_objectives))
                if unbound_controls or unbound_objectives:
                    business_linkage_result = DecisionState.UNKNOWN
                    if unbound_controls:
                        reasons.append("business_linkage:unbound_controls=" + ",".join(unbound_controls))
                    if unbound_objectives:
                        reasons.append("business_linkage:unbound_objectives=" + ",".join(unbound_objectives))
                else:
                    business_linkage_result = DecisionState.PASS
                    reasons.append(f"business_linkage:bound={len(contract.control_objective_links)}")

        oracle_result: DecisionState | None = None
        if self.require_business_oracle or business_oracle is not None:
            if business_oracle is None:
                oracle_result = DecisionState.UNKNOWN
                reasons.append("business_oracle:missing")
            else:
                try:
                    raw_result = business_oracle(contract)
                    if isinstance(raw_result, DecisionState):
                        oracle_result = raw_result
                    elif isinstance(raw_result, bool):
                        oracle_result = DecisionState.PASS if raw_result else DecisionState.FAIL
                    else:
                        oracle_result = DecisionState.UNKNOWN
                        reasons.append("business_oracle:invalid_result")
                except Exception as exc:  # fail closed at the assurance boundary
                    oracle_result = DecisionState.UNKNOWN
                    reasons.append(f"business_oracle:exception:{type(exc).__name__}")
            state = self._aggregate(control_results, dependency_results, objective_results, oracle_result, business_linkage_result)
        else:
            state = self._aggregate(control_results, dependency_results, objective_results, business_linkage=business_linkage_result)
        if not evidence_items:
            state = DecisionState.NOT_TESTED
        return AuditDecision(
            service_id=contract.service_id,
            state=state,
            checked_at=now,
            rule_version=self.rule_version,
            standard_pack_versions=standard_pack_versions,
            evidence_ids=tuple(dict.fromkeys(used_ids)),
            reasons=tuple(reasons),
            control_results=control_results,
            dependency_results=dependency_results,
            objective_results=objective_results,
            business_oracle_result=oracle_result,
            business_linkage_result=business_linkage_result,
        )

    @staticmethod
    def _evaluate_assertion(
        matches: list[Evidence], expected: object, now: datetime, require_integrity: bool, require_signature: bool, require_replay: bool, require_independence: bool, require_provenance: bool, max_future_skew: timedelta | None
    ) -> tuple[DecisionState, str, tuple[str, ...]]:
        if not matches:
            return DecisionState.UNKNOWN, "missing", ()
        values = {repr(item.value) for item in matches}
        if len(values) > 1:
            return DecisionState.CONFLICT, "conflicting_values", tuple(i.evidence_id for i in matches)
        if max_future_skew is not None and any(item.observed_at > now + max_future_skew for item in matches):
            return DecisionState.UNKNOWN, "future_clock_skew", tuple(i.evidence_id for i in matches)
        if require_integrity and any(not AssuranceEngine._integrity_ok(item) for item in matches):
            return DecisionState.UNKNOWN, "integrity_unverified", tuple(i.evidence_id for i in matches)
        if require_signature and any(not bool(item.metadata.get("_signature_verified", False)) for item in matches):
            return DecisionState.UNKNOWN, "signature_unverified", tuple(i.evidence_id for i in matches)
        if require_replay and any(not bool(item.metadata.get("_replay_verified", False)) for item in matches):
            return DecisionState.UNKNOWN, "replay_unverified", tuple(i.evidence_id for i in matches)
        if require_independence and any(not item.independent for item in matches):
            return DecisionState.UNKNOWN, "independence_unverified", tuple(i.evidence_id for i in matches)
        if require_provenance and any(not item.provenance.strip() for item in matches):
            return DecisionState.UNKNOWN, "provenance_missing", tuple(i.evidence_id for i in matches)
        if any(item.is_expired(now) for item in matches):
            return DecisionState.EXPIRED, "expired", tuple(i.evidence_id for i in matches)
        value = matches[-1].value
        return (
            DecisionState.PASS if value == expected else DecisionState.FAIL,
            "matched" if value == expected else f"expected={expected!r},observed={value!r}",
            tuple(i.evidence_id for i in matches),
        )

    @staticmethod
    def _evaluate_objective(
        matches: list[Evidence], target: float, comparator: str, now: datetime, require_integrity: bool, require_signature: bool, require_replay: bool, require_independence: bool, require_provenance: bool, max_future_skew: timedelta | None
    ) -> tuple[DecisionState, str, tuple[str, ...]]:
        values = {float(item.value) for item in matches}
        if len(values) > 1:
            return DecisionState.CONFLICT, "conflicting_values", tuple(i.evidence_id for i in matches)
        if max_future_skew is not None and any(item.observed_at > now + max_future_skew for item in matches):
            return DecisionState.UNKNOWN, "future_clock_skew", tuple(i.evidence_id for i in matches)
        if require_integrity and any(not AssuranceEngine._integrity_ok(item) for item in matches):
            return DecisionState.UNKNOWN, "integrity_unverified", tuple(i.evidence_id for i in matches)
        if require_signature and any(not bool(item.metadata.get("_signature_verified", False)) for item in matches):
            return DecisionState.UNKNOWN, "signature_unverified", tuple(i.evidence_id for i in matches)
        if require_replay and any(not bool(item.metadata.get("_replay_verified", False)) for item in matches):
            return DecisionState.UNKNOWN, "replay_unverified", tuple(i.evidence_id for i in matches)
        if require_independence and any(not item.independent for item in matches):
            return DecisionState.UNKNOWN, "independence_unverified", tuple(i.evidence_id for i in matches)
        if require_provenance and any(not item.provenance.strip() for item in matches):
            return DecisionState.UNKNOWN, "provenance_missing", tuple(i.evidence_id for i in matches)
        if any(item.is_expired(now) for item in matches):
            return DecisionState.EXPIRED, "expired", tuple(i.evidence_id for i in matches)
        value = next(iter(values))
        ok = {">=": value >= target, "<=": value <= target, "==": value == target}.get(comparator)
        if ok is None:
            raise ValueError(f"unsupported comparator: {comparator}")
        return (
            DecisionState.PASS if ok else DecisionState.FAIL,
            f"observed={value},target={comparator}{target}",
            tuple(i.evidence_id for i in matches),
        )

    @staticmethod
    def _aggregate(
        controls: Mapping[str, DecisionState], dependencies: Mapping[str, DecisionState], objectives: Mapping[str, DecisionState], business_oracle: DecisionState | None = None, business_linkage: DecisionState | None = None
    ) -> DecisionState:
        values = list(controls.values()) + list(dependencies.values()) + list(objectives.values())
        if business_oracle is not None:
            values.append(business_oracle)
        if business_linkage is not None:
            values.append(business_linkage)
        return aggregate_states(values)

    @staticmethod
    def _integrity_ok(item: Evidence) -> bool:
        if not bool(item.metadata.get("_integrity_verified", False)):
            return False
        return item.integrity_hash == evidence_hash(item)

