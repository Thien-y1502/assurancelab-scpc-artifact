from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class CrosswalkRelation(str, Enum):
    EQUIVALENT = "equivalent"
    BROADER_THAN = "broader_than"
    NARROWER_THAN = "narrower_than"
    PARTIAL_OVERLAP = "partially_overlaps"
    SUPPORTS = "supports"
    CONFLICTS_WITH = "conflicts_with"
    NOT_COMPARABLE = "not_comparable"

    @property
    def symmetric(self) -> bool:
        return self in {
            CrosswalkRelation.EQUIVALENT,
            CrosswalkRelation.PARTIAL_OVERLAP,
            CrosswalkRelation.CONFLICTS_WITH,
            CrosswalkRelation.NOT_COMPARABLE,
        }


class StandardStatus(str, Enum):
    PUBLISHED = "published"
    DRAFT = "draft"
    WITHDRAWN = "withdrawn"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StandardPack:
    identifier: str
    edition: str
    effective_date: str
    jurisdiction: str
    source_provenance: str
    status: StandardStatus = StandardStatus.UNKNOWN
    applicability_conditions: tuple[str, ...] = ()
    requirements: Mapping[str, str] = field(default_factory=dict)
    evidence_expectations: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def version(self) -> str:
        return f"{self.identifier}:{self.edition}"


@dataclass(frozen=True)
class Crosswalk:
    source_pack: str
    source_requirement: str
    target_pack: str
    target_requirement: str
    relation: CrosswalkRelation
    rationale: str
    provenance: str
    evidence_refs: tuple[str, ...] = ()
    scope_conditions: tuple[str, ...] = ()

    def normalized_scope(self) -> tuple[str, ...]:
        """Return a deterministic scope key; empty labels are not evidence."""
        return tuple(sorted({value.strip() for value in self.scope_conditions if value.strip()}))

    def endpoint_key(self) -> tuple[tuple[str, str], tuple[str, str]]:
        """Return an unordered endpoint key for symmetric relations."""
        endpoints = ((self.source_pack, self.source_requirement), (self.target_pack, self.target_requirement))
        return tuple(sorted(endpoints))  # type: ignore[return-value]

    def semantic_key(self) -> tuple[object, ...]:
        """Return a duplicate-detection key that respects relation symmetry."""
        endpoints: object = self.endpoint_key() if self.relation.symmetric else (
            (self.source_pack, self.source_requirement),
            (self.target_pack, self.target_requirement),
        )
        return (endpoints, self.relation, self.normalized_scope())

    def validate(self) -> None:
        if not self.source_pack.strip() or not self.source_requirement.strip() or not self.target_pack.strip() or not self.target_requirement.strip():
            raise ValueError("crosswalk endpoints are required")
        if not self.rationale.strip():
            raise ValueError("crosswalk rationale is required")
        if not self.provenance.strip():
            raise ValueError("crosswalk provenance is required")
        if self.source_pack == self.target_pack and self.source_requirement == self.target_requirement:
            raise ValueError("a requirement cannot crosswalk to itself")
        if self.relation in {
            CrosswalkRelation.EQUIVALENT,
            CrosswalkRelation.PARTIAL_OVERLAP,
            CrosswalkRelation.CONFLICTS_WITH,
        }:
            if not self.evidence_refs:
                raise ValueError(f"{self.relation.value} crosswalk requires requirement-level evidence references")
            if not self.normalized_scope():
                raise ValueError(f"{self.relation.value} crosswalk requires explicit scope conditions")


