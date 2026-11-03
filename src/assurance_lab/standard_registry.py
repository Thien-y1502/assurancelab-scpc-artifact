from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .standards import Crosswalk, CrosswalkRelation, StandardPack, StandardStatus


@dataclass(frozen=True)
class RegistrySnapshot:
    packs: tuple[str, ...]
    crosswalk_count: int


class StandardPackRegistry:
    """Versioned metadata registry; normative text is never silently copied."""

    def __init__(self) -> None:
        self._packs: dict[str, StandardPack] = {}
        self._crosswalks: list[Crosswalk] = []

    def add_pack(self, pack: StandardPack) -> None:
        if pack.version in self._packs:
            raise ValueError(f"duplicate standard pack: {pack.version}")
        if not pack.source_provenance.strip():
            raise ValueError("standard pack provenance is required")
        if pack.status == StandardStatus.UNKNOWN:
            raise ValueError("standard pack status must be explicit")
        self._packs[pack.version] = pack

    def add_crosswalk(self, crosswalk: Crosswalk) -> None:
        crosswalk.validate()
        if crosswalk.source_pack not in self._packs:
            raise KeyError(f"unknown source pack: {crosswalk.source_pack}")
        if crosswalk.target_pack not in self._packs:
            raise KeyError(f"unknown target pack: {crosswalk.target_pack}")
        source = self._packs[crosswalk.source_pack]
        target = self._packs[crosswalk.target_pack]
        if source.status != StandardStatus.PUBLISHED or target.status != StandardStatus.PUBLISHED:
            raise ValueError("crosswalk requires published source and target packs")
        if crosswalk.relation == CrosswalkRelation.EQUIVALENT:
            if crosswalk.source_requirement not in source.requirements:
                raise KeyError(f"unknown source requirement: {crosswalk.source_requirement}")
            if crosswalk.target_requirement not in target.requirements:
                raise KeyError(f"unknown target requirement: {crosswalk.target_requirement}")
        if any(item.semantic_key() == crosswalk.semantic_key() for item in self._crosswalks):
            raise ValueError("duplicate crosswalk")
        for item in self._crosswalks:
            if item.normalized_scope() != crosswalk.normalized_scope():
                continue
            if not _same_endpoints(item, crosswalk):
                continue
            if _relations_conflict(item.relation, crosswalk.relation):
                raise ValueError("contradictory crosswalk relation in the same scope")
        self._crosswalks.append(crosswalk)

    def get(self, version: str) -> StandardPack:
        return self._packs[version]

    def snapshot(self) -> RegistrySnapshot:
        return RegistrySnapshot(tuple(sorted(self._packs)), len(self._crosswalks))

    def packs(self) -> tuple[StandardPack, ...]:
        return tuple(self._packs[key] for key in sorted(self._packs))

    def crosswalks(self) -> tuple[Crosswalk, ...]:
        return tuple(self._crosswalks)


def _same_endpoints(left: Crosswalk, right: Crosswalk) -> bool:
    direct = (
        left.source_pack == right.source_pack
        and left.source_requirement == right.source_requirement
        and left.target_pack == right.target_pack
        and left.target_requirement == right.target_requirement
    )
    reverse = (
        left.source_pack == right.target_pack
        and left.source_requirement == right.target_requirement
        and left.target_pack == right.source_pack
        and left.target_requirement == right.source_requirement
    )
    return direct or reverse


def _relations_conflict(left: CrosswalkRelation, right: CrosswalkRelation) -> bool:
    if left == right:
        return False
    high_risk = {
        CrosswalkRelation.EQUIVALENT,
        CrosswalkRelation.CONFLICTS_WITH,
        CrosswalkRelation.NOT_COMPARABLE,
    }
    if left in high_risk and right in high_risk:
        return True
    if CrosswalkRelation.CONFLICTS_WITH in {left, right}:
        return True
    return False


def baseline_registry() -> StandardPackRegistry:
    """Metadata-only baseline registry with official source provenance.

    Requirement text and mappings must be supplied under a compatible licence
    by the user. The registry deliberately does not pretend that two controls
    are equivalent merely because their wording looks similar.
    """
    registry = StandardPackRegistry()
    packs: Iterable[StandardPack] = (
        StandardPack(
            "ISO/IEC 27001", "2022", "2022-10", "international",
            "https://www.iso.org/standard/27001", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "ISO/IEC 27002", "2022", "2022-02", "international",
            "https://www.iso.org/standard/75652.html", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "ISO/IEC 27000", "2026", "2026-07", "international",
            "https://www.iso.org/standard/27000", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "ISO 19011", "2026", "2026-05", "international",
            "https://www.iso.org/standard/19011", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "ISO/TS 22317", "2021", "2021-10", "international",
            "https://www.iso.org/obp/ui/en/#iso:std:iso:ts:22317:ed-2:v1:en", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "ISO/IEC 27031", "2025", "2025-05", "international",
            "https://www.iso.org/standard/27031", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "ISO/IEC 27090", "2026", "2026-10", "international",
            "https://www.iso.org/standard/27090", StandardStatus.PUBLISHED,
            applicability_conditions=("AI systems and their lifecycle security threats",),
        ),
        StandardPack(
            "ISO 22301", "2019", "2019-10", "international",
            "https://www.iso.org/standard/75106.html", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "ISO 22313", "2020", "2020-02", "international",
            "https://www.iso.org/standard/75107.html", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "NIST CSF", "2.0", "2024-02", "United States",
            "https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "NIST SP 800-137", "2011", "2011-09", "United States",
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-137.pdf", StandardStatus.PUBLISHED,
        ),
        StandardPack(
            "NIST SP 800-34", "Rev.1", "2010-05", "United States",
            "https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final", StandardStatus.PUBLISHED,
        ),
    )
    for pack in packs:
        registry.add_pack(pack)
    return registry

