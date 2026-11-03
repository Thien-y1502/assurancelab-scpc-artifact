from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .engine import AssuranceEngine
from .models import AuditDecision, DecisionState, Evidence, ServiceContract


@dataclass(frozen=True)
class BaselineOutput:
    name: str
    state: DecisionState
    explanation: str


def manual_checklist(contract: ServiceContract, evidence: Iterable[Evidence]) -> BaselineOutput:
    evidence_list = tuple(evidence)
    assertions = {item.assertion for item in evidence_list if item.value is True}
    ok = all(control.assertion in assertions for control in contract.controls)
    return BaselineOutput("manual-checklist", DecisionState.PASS if ok else DecisionState.FAIL, "presence-only controls")


def static_crosswalk(contract: ServiceContract, evidence: Iterable[Evidence]) -> BaselineOutput:
    evidence_list = tuple(evidence)
    by_assertion: dict[str, list[Evidence]] = {}
    for item in evidence_list:
        by_assertion.setdefault(item.assertion, []).append(item)
    if any(not by_assertion.get(control.assertion) for control in contract.controls):
        return BaselineOutput("static-crosswalk", DecisionState.UNKNOWN, "missing mapped evidence")
    ok = all(any(item.value == control.expected_value for item in by_assertion[control.assertion]) for control in contract.controls)
    return BaselineOutput("static-crosswalk", DecisionState.PASS if ok else DecisionState.FAIL, "control mapping without business objectives")


def risk_score(contract: ServiceContract, evidence: Iterable[Evidence], threshold: float = 0.8) -> BaselineOutput:
    evidence_list = tuple(evidence)
    satisfied = sum(any(item.assertion == control.assertion and item.value == control.expected_value for item in evidence_list) for control in contract.controls)
    score = satisfied / max(len(contract.controls), 1)
    return BaselineOutput("risk-score", DecisionState.PASS if score >= threshold else DecisionState.FAIL, f"score={score:.3f},threshold={threshold:.3f}")


def rule_match(contract: ServiceContract, evidence: Iterable[Evidence]) -> BaselineOutput:
    evidence_list = tuple(evidence)
    satisfied = {item.assertion for item in evidence_list if item.value is True}
    missing = [control.control_id for control in contract.controls if control.assertion not in satisfied]
    if missing:
        return BaselineOutput("rule-match", DecisionState.UNKNOWN, f"missing={','.join(missing)}")
    return BaselineOutput("rule-match", DecisionState.PASS, "event rules matched")


def naive_business_threshold(contract: ServiceContract, evidence: Iterable[Evidence]) -> BaselineOutput:
    """Strong business-aware baseline that ignores evidence validity semantics.

    It takes the latest record per assertion, evaluates the same explicit
    business thresholds, and never returns UNKNOWN/EXPIRED/CONFLICT. This is a
    deliberately strong comparator for Paper 1 adversarial tests.
    """
    latest: dict[str, Evidence] = {}
    for item in evidence:
        previous = latest.get(item.assertion)
        if previous is None or item.observed_at >= previous.observed_at:
            latest[item.assertion] = item
    for control in contract.controls:
        if control.assertion not in latest or latest[control.assertion].value != control.expected_value:
            return BaselineOutput("naive-business-threshold", DecisionState.FAIL, f"control={control.control_id}")
    for objective in contract.objectives:
        item = latest.get(objective.metric)
        if item is None:
            return BaselineOutput("naive-business-threshold", DecisionState.FAIL, f"objective={objective.objective_id}")
        if not objective.evaluate(item.value):
            return BaselineOutput("naive-business-threshold", DecisionState.FAIL, f"objective={objective.objective_id}")
    return BaselineOutput("naive-business-threshold", DecisionState.PASS, "latest values; validity ignored")


def proposed_engine(contract: ServiceContract, evidence: Iterable[Evidence], now: datetime) -> AuditDecision:
    return AssuranceEngine().evaluate(contract, evidence, now=now)


def classification_metrics(predicted: Iterable[DecisionState], oracle: Iterable[DecisionState]) -> dict[str, float]:
    pairs = list(zip(predicted, oracle))
    if not pairs:
        raise ValueError("at least one classification pair is required")
    false_assurance = sum(pred == DecisionState.PASS and truth != DecisionState.PASS for pred, truth in pairs) / len(pairs)
    false_rejection = sum(pred != DecisionState.PASS and truth == DecisionState.PASS for pred, truth in pairs) / len(pairs)
    accuracy = sum(pred == truth for pred, truth in pairs) / len(pairs)
    return {"n": float(len(pairs)), "accuracy": accuracy, "false_assurance_rate": false_assurance, "false_rejection_rate": false_rejection}

