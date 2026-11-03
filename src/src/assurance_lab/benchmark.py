from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .engine import AssuranceEngine
from .models import (
    BusinessObjective,
    ControlRequirement,
    DependencyRequirement,
    DecisionState,
    Evidence,
    EvidenceKind,
    ServiceContract,
)
from .provenance import sha256_record


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    description: str
    evidence: tuple[Evidence, ...]
    oracle_state: DecisionState


def ecommerce_contract() -> ServiceContract:
    return ServiceContract(
        service_id="ecommerce-checkout",
        name="Payment and order checkout",
        controls=(
            ControlRequirement("backup-rpo", "Backup within RPO", "backup_fresh", True),
            ControlRequirement("payment-available", "Payment dependency available", "payment_available", True),
            ControlRequirement("privileged-review", "Privileged access review current", "privileged_reviewed", True),
        ),
        objectives=(
            BusinessObjective("mbco", "capacity_fraction", 0.80, ">="),
            BusinessObjective("rto", "rto_minutes", 60.0, "<="),
            BusinessObjective("rpo", "rpo_minutes", 5.0, "<="),
            BusinessObjective("payment-integrity", "payment_integrity", 1.0, "=="),
        ),
        dependencies=("identity", "payment", "inventory", "database", "dns", "queue"),
        dependency_requirements=(DependencyRequirement("payment", "payment_available", True),),
    )


def _evidence(eid: str, assertion: str, value: object, now: datetime, *, ttl_minutes: int = 60) -> Evidence:
    record = {"id": eid, "assertion": assertion, "value": value}
    return Evidence(
        evidence_id=eid,
        subject="ecommerce-checkout",
        assertion=assertion,
        value=value,
        observed_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=ttl_minutes),
        kind=EvidenceKind.TEST,
        provenance="assurance-lab.synthetic-v0.1",
        integrity_hash=sha256_record(record),
    )


def _complete(now: datetime) -> tuple[Evidence, ...]:
    values = {
        "backup_fresh": True,
        "payment_available": True,
        "privileged_reviewed": True,
        "capacity_fraction": 0.95,
        "rto_minutes": 22.0,
        "rpo_minutes": 1.0,
        "payment_integrity": 1.0,
    }
    return tuple(_evidence(f"e-{key}", key, value, now) for key, value in values.items())


def scenarios(now: datetime | None = None) -> tuple[Scenario, ...]:
    now = now or datetime.now(timezone.utc)
    complete = _complete(now)
    by_key = {item.assertion: item for item in complete}

    def with_values(sid: str, description: str, overrides: dict[str, object], expected: DecisionState):
        items = tuple(
            _evidence(f"{sid}-{key}", key, overrides.get(key, item.value), now)
            for key, item in by_key.items()
        )
        return Scenario(sid, description, items, expected)

    expired_backup = _evidence("s-expired-backup", "backup_fresh", True, now, ttl_minutes=-1)
    stale_items = tuple(item for item in complete if item.assertion != "backup_fresh") + (expired_backup,)
    return (
        Scenario("S0", "nominal healthy checkout", complete, DecisionState.PASS),
        with_values("S1", "payment dependency outage", {"payment_available": False}, DecisionState.FAIL),
        with_values("S2", "capacity below MBCO", {"capacity_fraction": 0.40}, DecisionState.FAIL),
        with_values("S3", "RTO breach after restore", {"rto_minutes": 95.0}, DecisionState.FAIL),
        with_values("S4", "RPO breach despite apparent control presence", {"rpo_minutes": 24.0}, DecisionState.FAIL),
        Scenario("S5", "stale backup evidence", stale_items, DecisionState.EXPIRED),
        Scenario("S6", "missing privileged-access evidence", tuple(item for item in complete if item.assertion != "privileged_reviewed"), DecisionState.UNKNOWN),
        Scenario("S7", "conflicting payment evidence", complete + (_evidence("s7-conflict", "payment_available", False, now),), DecisionState.CONFLICT),
    )


def run_benchmark(now: datetime | None = None) -> list[dict[str, object]]:
    contract = ecommerce_contract()
    engine = AssuranceEngine()
    rows: list[dict[str, object]] = []
    for scenario in scenarios(now):
        decision = engine.evaluate(contract, scenario.evidence, now=now or datetime.now(timezone.utc))
        rows.append(
            {
                "scenario_id": scenario.scenario_id,
                "description": scenario.description,
                "oracle": scenario.oracle_state.value,
                "observed": decision.state.value,
                "match": decision.state == scenario.oracle_state,
                "evidence_count": len(scenario.evidence),
            }
        )
    return rows

