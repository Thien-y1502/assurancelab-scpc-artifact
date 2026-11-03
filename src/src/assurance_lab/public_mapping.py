"""Explicit, fail-closed mapping from public records to audit evidence.

Public vulnerability/technique records are not controls or business outcomes.
This module requires an organization-owned mapping contract that states exactly
what assertion and value are being witnessed; no semantic inference is made.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from .models import Evidence, EvidenceKind
from .provenance import evidence_hash


class PublicEvidenceMappingError(ValueError):
    """Raised when an explicit public-record mapping is incomplete."""


@dataclass(frozen=True)
class ExplicitEvidenceMapping:
    subject: str
    assertion: str
    value: Any
    mapping_provenance: str
    mapping_version: str
    justification: str
    observed_at: datetime
    expires_at: datetime | None = None
    kind: EvidenceKind = EvidenceKind.DOCUMENT

    def __post_init__(self) -> None:
        if not self.subject.strip():
            raise PublicEvidenceMappingError("mapping subject is required")
        if not self.assertion.strip():
            raise PublicEvidenceMappingError("mapping assertion is required")
        if not self.mapping_version.strip():
            raise PublicEvidenceMappingError("mapping version is required")
        if not self.justification.strip():
            raise PublicEvidenceMappingError("mapping justification is required")
        parsed = urlsplit(self.mapping_provenance)
        if parsed.scheme not in {"https", "mapping"} or (parsed.scheme == "https" and not parsed.hostname):
            raise PublicEvidenceMappingError("mapping provenance must be an HTTPS or mapping:// URI")
        if not isinstance(self.kind, EvidenceKind):
            raise PublicEvidenceMappingError("mapping kind must be typed")


def map_public_record(record: object, mapping: ExplicitEvidenceMapping) -> Evidence:
    """Create evidence only from an explicit mapping, preserving source provenance."""

    record_id = _record_id(record)
    source_provenance = getattr(record, "provenance", None)
    if not isinstance(source_provenance, str) or not source_provenance.strip():
        raise PublicEvidenceMappingError("source record provenance is required")
    evidence = Evidence(
        evidence_id=f"{mapping.mapping_version}:{record_id}",
        subject=mapping.subject,
        assertion=mapping.assertion,
        value=mapping.value,
        observed_at=mapping.observed_at,
        expires_at=mapping.expires_at,
        kind=mapping.kind,
        provenance=source_provenance,
        integrity_hash="",
        independent=True,
        metadata={
            "_public_record_id": record_id,
            "_public_record_type": type(record).__name__,
            "_mapping_provenance": mapping.mapping_provenance,
            "_mapping_version": mapping.mapping_version,
            "_mapping_justification": mapping.justification,
        },
    )
    return replace(evidence, integrity_hash=evidence_hash(evidence))


def _record_id(record: object) -> str:
    for field in ("cve_id", "stix_id", "record_id", "id"):
        value = getattr(record, field, None)
        if isinstance(value, str) and value.strip():
            return value
    raise PublicEvidenceMappingError("public record identity is required")
