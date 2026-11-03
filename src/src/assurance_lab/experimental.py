from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from .adapters import MappingEvidenceAdapter
from .baselines import manual_checklist, naive_business_threshold, risk_score, rule_match, static_crosswalk
from .benchmark import ecommerce_contract
from .engine import AssuranceEngine
from .models import DecisionState, Evidence
from .provenance import sha256_record


@dataclass(frozen=True)
class ExperimentalCase:
    case_id: str
    seed: int
    capacity_level: int
    backup_level: int
    payment_level: int
    privileged_level: int
    expected_state: DecisionState
    evidence: tuple[Evidence, ...]


def independent_oracle(capacity_fraction: float, rto_minutes: float, rpo_minutes: float, payment_available: bool, privileged_reviewed: bool) -> DecisionState:
    """Independent business oracle; intentionally does not call AssuranceEngine."""
    ok = (
        capacity_fraction >= 0.80
        and rto_minutes <= 60.0
        and rpo_minutes <= 5.0
        and payment_available
        and privileged_reviewed
    )
    return DecisionState.PASS if ok else DecisionState.FAIL


def generate_factorial_cases(replicates: int = 20, now: datetime | None = None) -> tuple[ExperimentalCase, ...]:
    now = now or datetime(2026, 10, 29)
    cases: list[ExperimentalCase] = []
    case_number = 0
    for factors in itertools.product((0, 1), repeat=4):
        capacity_level, backup_level, payment_level, privileged_level = factors
        for replicate in range(replicates):
            seed = case_number * 7919 + replicate
            rng = random.Random(seed)
            capacity = (0.93 if capacity_level else 0.56) + rng.uniform(-0.015, 0.015)
            rto = (24.0 if capacity_level else 86.0) + rng.uniform(-2.0, 2.0)
            rpo = (2.0 if backup_level else 22.0) + rng.uniform(-0.5, 0.5)
            payment = bool(payment_level)
            privileged = bool(privileged_level)
            expected = independent_oracle(capacity, rto, rpo, payment, privileged)
            observed_iso = now.isoformat()
            if now.tzinfo is None:
                observed_iso += "+00:00"
            expires_iso = (now + timedelta(hours=1)).isoformat()
            if now.tzinfo is None:
                expires_iso += "+00:00"
            records = [
                {"evidence_id": f"{case_number}:backup", "subject": "checkout", "assertion": "backup_fresh", "value": bool(backup_level), "observed_at": observed_iso, "expires_at": expires_iso, "kind": "test", "provenance": "factorial-v0.1"},
                {"evidence_id": f"{case_number}:payment", "subject": "checkout", "assertion": "payment_available", "value": payment, "observed_at": observed_iso, "expires_at": expires_iso, "kind": "test", "provenance": "factorial-v0.1"},
                {"evidence_id": f"{case_number}:privileged", "subject": "checkout", "assertion": "privileged_reviewed", "value": privileged, "observed_at": observed_iso, "expires_at": expires_iso, "kind": "test", "provenance": "factorial-v0.1"},
                {"evidence_id": f"{case_number}:capacity", "subject": "checkout", "assertion": "capacity_fraction", "value": capacity, "observed_at": observed_iso, "expires_at": expires_iso, "kind": "test", "provenance": "factorial-v0.1"},
                {"evidence_id": f"{case_number}:rto", "subject": "checkout", "assertion": "rto_minutes", "value": rto, "observed_at": observed_iso, "expires_at": expires_iso, "kind": "test", "provenance": "factorial-v0.1"},
                {"evidence_id": f"{case_number}:rpo", "subject": "checkout", "assertion": "rpo_minutes", "value": rpo, "observed_at": observed_iso, "expires_at": expires_iso, "kind": "test", "provenance": "factorial-v0.1"},
                {"evidence_id": f"{case_number}:integrity", "subject": "checkout", "assertion": "payment_integrity", "value": 1.0, "observed_at": observed_iso, "expires_at": expires_iso, "kind": "test", "provenance": "factorial-v0.1"},
            ]
            adapter = MappingEvidenceAdapter()
            evidence = adapter.read(records)
            cases.append(ExperimentalCase(f"F{case_number:04d}", seed, *factors, expected, evidence))
            case_number += 1
    return tuple(cases)


def evaluate_factorial(cases: tuple[ExperimentalCase, ...], now: datetime) -> dict[str, object]:
    contract = ecommerce_contract()
    engine = AssuranceEngine()
    methods: dict[str, list[DecisionState]] = {name: [] for name in ("manual-checklist", "static-crosswalk", "risk-score", "rule-match", "naive-business-threshold", "assurance-lab")}
    oracle: list[DecisionState] = []
    rows: list[dict[str, object]] = []
    for case in cases:
        oracle.append(case.expected_state)
        decisions = {
            "manual-checklist": manual_checklist(contract, case.evidence).state,
            "static-crosswalk": static_crosswalk(contract, case.evidence).state,
            "risk-score": risk_score(contract, case.evidence).state,
            "rule-match": rule_match(contract, case.evidence).state,
            "naive-business-threshold": naive_business_threshold(contract, case.evidence).state,
            "assurance-lab": engine.evaluate(contract, case.evidence, now=now).state,
        }
        for name, state in decisions.items():
            methods[name].append(state)
        rows.append({"case_id": case.case_id, "oracle": case.expected_state.value, **{name: state.value for name, state in decisions.items()}})
    return {"rows": rows, "oracle": oracle, "methods": methods}

