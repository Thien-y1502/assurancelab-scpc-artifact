from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping


class DecisionState(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    EXPIRED = "EXPIRED"
    CONFLICT = "CONFLICT"
    NOT_TESTED = "NOT_TESTED"


class EvidenceKind(str, Enum):
    RUNTIME = "runtime"
    SCHEDULED = "scheduled"
    TEST = "test"
    DOCUMENT = "document"
    HUMAN = "human"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    subject: str
    assertion: str
    value: Any
    observed_at: datetime
    expires_at: datetime | None
    kind: EvidenceKind
    provenance: str
    integrity_hash: str
    independent: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at


@dataclass(frozen=True)
class ControlRequirement:
    control_id: str
    title: str
    assertion: str
    expected_value: Any = True
    critical: bool = True


@dataclass(frozen=True)
class DependencyRequirement:
    dependency_id: str
    assertion: str
    expected_value: Any = True
    critical: bool = True


@dataclass(frozen=True)
class BusinessObjective:
    objective_id: str
    metric: str
    target: float
    comparator: str
    critical: bool = True

    def evaluate(self, value: Any) -> bool:
        numeric = float(value)
        if self.comparator == ">=":
            return numeric >= self.target
        if self.comparator == "<=":
            return numeric <= self.target
        if self.comparator == "==":
            return numeric == self.target
        raise ValueError(f"unsupported comparator: {self.comparator}")


class BusinessLinkRelation(str, Enum):
    """Typed relation between a technical control and a business objective."""

    SUPPORTS = "supports"
    REQUIRED_FOR = "required_for"
    MEASURES = "measures"


@dataclass(frozen=True)
class ControlObjectiveLink:
    control_id: str
    objective_id: str
    relation: BusinessLinkRelation = BusinessLinkRelation.SUPPORTS
    provenance: str = ""
    scope_conditions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.control_id.strip() or not self.objective_id.strip():
            raise ValueError("control-objective link endpoints are required")
        if not isinstance(self.relation, BusinessLinkRelation):
            raise ValueError("control-objective link relation must be typed")
        if not self.provenance.strip():
            raise ValueError("control-objective link provenance is required")
        if not any(condition.strip() for condition in self.scope_conditions):
            raise ValueError("control-objective link scope is required")


BusinessOracle = Callable[["ServiceContract"], DecisionState | bool]


@dataclass(frozen=True)
class ServiceContract:
    service_id: str
    name: str
    controls: tuple[ControlRequirement, ...]
    objectives: tuple[BusinessObjective, ...]
    dependencies: tuple[str, ...] = ()
    dependency_requirements: tuple[DependencyRequirement, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    control_objective_links: tuple[ControlObjectiveLink, ...] = ()

    def __post_init__(self) -> None:
        dependency_ids = tuple(item.dependency_id for item in self.dependency_requirements)
        if len(set(dependency_ids)) != len(dependency_ids):
            raise ValueError("duplicate dependency requirement")
        missing = [item for item in dependency_ids if item not in self.dependencies]
        if missing:
            raise ValueError("dependency requirement is not declared: " + ",".join(missing))
        control_ids = {item.control_id for item in self.controls}
        objective_ids = {item.objective_id for item in self.objectives}
        link_keys = {(item.control_id, item.objective_id, item.relation) for item in self.control_objective_links}
        if len(link_keys) != len(self.control_objective_links):
            raise ValueError("duplicate control-objective link")
        invalid_links = [
            item for item in self.control_objective_links
            if item.control_id not in control_ids or item.objective_id not in objective_ids
        ]
        if invalid_links:
            raise ValueError("control-objective link references an undeclared endpoint")


@dataclass(frozen=True)
class AuditDecision:
    service_id: str
    state: DecisionState
    checked_at: datetime
    rule_version: str
    standard_pack_versions: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    control_results: Mapping[str, DecisionState]
    dependency_results: Mapping[str, DecisionState]
    objective_results: Mapping[str, DecisionState]
    business_oracle_result: DecisionState | None = None
    business_linkage_result: DecisionState | None = None

