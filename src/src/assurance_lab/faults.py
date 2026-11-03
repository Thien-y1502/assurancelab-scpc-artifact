from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from .benchmark import ecommerce_contract
from .ledger import EvidenceLedger
from .models import DecisionState, Evidence, EvidenceKind
from .provenance import sha256_record


@dataclass(frozen=True)
class FaultScenario:
    scenario_id: str
    seed: int
    fault: str
    capacity_fraction: float
    rto_minutes: float
    rpo_minutes: float
    payment_available: bool
    privileged_reviewed: bool
    payment_integrity: float
    expected_state: DecisionState


def generate_fault_scenario(seed: int, scenario_id: str | None = None) -> FaultScenario:
    rng = random.Random(seed)
    fault = rng.choice(("nominal", "payment_outage", "capacity_drop", "restore_delay", "backup_stale", "config_drift", "payment_corruption"))
    values = {
        "capacity_fraction": 0.90,
        "rto_minutes": 25.0,
        "rpo_minutes": 2.0,
        "payment_available": True,
        "privileged_reviewed": True,
        "payment_integrity": 1.0,
    }
    if fault == "payment_outage":
        values["payment_available"] = False
    elif fault == "capacity_drop":
        values["capacity_fraction"] = 0.45
    elif fault == "restore_delay":
        values["rto_minutes"] = 95.0
    elif fault == "backup_stale":
        values["rpo_minutes"] = 24.0
    elif fault == "config_drift":
        values["privileged_reviewed"] = False
    elif fault == "payment_corruption":
        values["payment_integrity"] = 0.0
    expected = DecisionState.PASS if (
        values["capacity_fraction"] >= 0.80
        and values["rto_minutes"] <= 60
        and values["rpo_minutes"] <= 5
        and values["payment_available"]
        and values["privileged_reviewed"]
        and values["payment_integrity"] == 1.0
    ) else DecisionState.FAIL
    return FaultScenario(
        scenario_id=scenario_id or f"seed-{seed}",
        seed=seed,
        fault=fault,
        expected_state=expected,
        **values,
    )


def scenario_evidence(scenario: FaultScenario, now: datetime) -> tuple[Evidence, ...]:
    values = {
        "backup_fresh": scenario.rpo_minutes <= 5,
        "payment_available": scenario.payment_available,
        "privileged_reviewed": scenario.privileged_reviewed,
        "capacity_fraction": scenario.capacity_fraction,
        "rto_minutes": scenario.rto_minutes,
        "rpo_minutes": scenario.rpo_minutes,
        "payment_integrity": scenario.payment_integrity,
    }
    evidence: list[Evidence] = []
    for assertion, value in values.items():
        evidence_id = f"{scenario.scenario_id}:{assertion}"
        payload = {"id": evidence_id, "assertion": assertion, "value": value, "seed": scenario.seed}
        evidence.append(
            Evidence(
                evidence_id=evidence_id,
                subject="ecommerce-checkout",
                assertion=assertion,
                value=value,
                observed_at=now,
                expires_at=now + timedelta(hours=1),
                kind=EvidenceKind.TEST,
                provenance="assurance-lab.fault-replay.v0.1",
                integrity_hash=sha256_record(payload),
                metadata={"seed": scenario.seed, "fault": scenario.fault},
            )
        )
    return tuple(evidence)


def replay_scenario(seed: int, now: datetime) -> tuple[FaultScenario, EvidenceLedger]:
    scenario = generate_fault_scenario(seed)
    ledger = EvidenceLedger()
    for item in scenario_evidence(scenario, now):
        ledger.append(item, appended_at=now)
    return scenario, ledger

