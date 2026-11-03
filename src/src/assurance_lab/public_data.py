"""Strict adapters for public cyber-data snapshots.

These adapters preserve source provenance and schema semantics. They do not
turn vulnerability or technique records into business outcomes or audit PASS
decisions; callers must provide an explicit, scoped mapping if they use a
record as evidence for a contract.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


class PublicDataSchemaError(ValueError):
    """Raised when a public snapshot cannot be admitted safely."""


@dataclass(frozen=True)
class NvdVulnerability:
    cve_id: str
    published: str
    last_modified: str
    description: str
    source_url: str
    source_sha256: str

    @property
    def provenance(self) -> str:
        return f"{self.source_url}#sha256={self.source_sha256}"


@dataclass(frozen=True)
class NvdSnapshot:
    source_url: str
    source_sha256: str
    schema: str
    vulnerabilities: tuple[NvdVulnerability, ...]


@dataclass(frozen=True)
class AttackTechnique:
    stix_id: str
    name: str
    description: str
    revoked: bool
    deprecated: bool
    source_url: str
    source_sha256: str

    @property
    def provenance(self) -> str:
        return f"{self.source_url}#sha256={self.source_sha256}"


@dataclass(frozen=True)
class AttackStixSnapshot:
    source_url: str
    source_sha256: str
    spec_version: str
    techniques: tuple[AttackTechnique, ...]


def parse_nvd_snapshot(
    payload: bytes | bytearray | str | Mapping[str, Any],
    *,
    source_url: str,
    source_sha256: str | None = None,
    max_records: int = 10_000,
) -> NvdSnapshot:
    """Parse an NVD JSON 2.0 snapshot without inferring business semantics."""

    raw, document, digest = _prepare(payload, source_url=source_url, source_sha256=source_sha256)
    _ = raw
    if document.get("format") not in ("NVD_CVE", "NVD JSON 2.0"):
        raise PublicDataSchemaError("unsupported NVD snapshot format")
    rows = document.get("vulnerabilities")
    if not isinstance(rows, list) or len(rows) > max_records:
        raise PublicDataSchemaError("NVD vulnerabilities must be a bounded list")
    parsed: list[NvdVulnerability] = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("cve"), Mapping):
            raise PublicDataSchemaError("NVD row must contain a cve object")
        cve = row["cve"]
        cve_id = cve.get("id")
        published = cve.get("published")
        last_modified = cve.get("lastModified")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            raise PublicDataSchemaError("NVD CVE id is invalid")
        if not isinstance(published, str) or not isinstance(last_modified, str):
            raise PublicDataSchemaError("NVD timestamps are required")
        descriptions = cve.get("descriptions", [])
        if not isinstance(descriptions, list):
            raise PublicDataSchemaError("NVD descriptions must be a list")
        english = next((item.get("value") for item in descriptions if isinstance(item, Mapping) and item.get("lang") == "en" and isinstance(item.get("value"), str)), "")
        parsed.append(NvdVulnerability(cve_id, published, last_modified, english, source_url, digest))
    return NvdSnapshot(source_url, digest, str(document.get("version", "2.0")), tuple(parsed))


def parse_attack_stix_snapshot(
    payload: bytes | bytearray | str | Mapping[str, Any],
    *,
    source_url: str,
    source_sha256: str | None = None,
    max_records: int = 50_000,
) -> AttackStixSnapshot:
    """Parse an ATT&CK STIX bundle, retaining only attack-pattern objects."""

    raw, document, digest = _prepare(payload, source_url=source_url, source_sha256=source_sha256)
    _ = raw
    if document.get("type") != "bundle":
        raise PublicDataSchemaError("unsupported STIX bundle")
    objects = document.get("objects")
    if not isinstance(objects, list) or len(objects) > max_records:
        raise PublicDataSchemaError("STIX objects must be a bounded list")
    object_versions = {item.get("spec_version") for item in objects if isinstance(item, Mapping) and item.get("spec_version") in ("2.0", "2.1")}
    spec_version = document.get("spec_version") or (next(iter(object_versions)) if len(object_versions) == 1 else None)
    if spec_version not in ("2.0", "2.1"):
        raise PublicDataSchemaError("STIX spec_version is missing or inconsistent")
    techniques: list[AttackTechnique] = []
    for item in objects:
        if not isinstance(item, Mapping) or item.get("type") != "attack-pattern":
            continue
        stix_id = item.get("id")
        name = item.get("name")
        if not isinstance(stix_id, str) or not stix_id.startswith("attack-pattern--") or not isinstance(name, str) or not name.strip():
            raise PublicDataSchemaError("ATT&CK attack-pattern identity is invalid")
        description = item.get("description", "")
        if not isinstance(description, str):
            raise PublicDataSchemaError("ATT&CK description must be a string")
        techniques.append(AttackTechnique(stix_id, name, description, bool(item.get("revoked", False)), bool(item.get("x_mitre_deprecated", False)), source_url, digest))
    return AttackStixSnapshot(source_url, digest, str(spec_version), tuple(techniques))


def _prepare(
    payload: bytes | bytearray | str | Mapping[str, Any],
    *,
    source_url: str,
    source_sha256: str | None,
) -> tuple[bytes, Mapping[str, Any], str]:
    parsed_url = urlsplit(source_url)
    if parsed_url.scheme.lower() != "https" or not parsed_url.hostname:
        raise PublicDataSchemaError("source_url must be an absolute HTTPS URL")
    if isinstance(payload, Mapping):
        if source_sha256 is None:
            raise PublicDataSchemaError("source_sha256 is required for mapping payloads")
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        document = payload
    elif isinstance(payload, str):
        raw = payload.encode("utf-8")
        document = _decode(raw)
    elif isinstance(payload, (bytes, bytearray)):
        raw = bytes(payload)
        document = _decode(raw)
    else:
        raise PublicDataSchemaError("payload must be JSON bytes, text or mapping")
    digest = hashlib.sha256(raw).hexdigest().upper()
    if source_sha256 is not None and digest != source_sha256.upper():
        raise PublicDataSchemaError("source_sha256 does not match payload")
    return raw, document, digest


def _decode(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicDataSchemaError("payload is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise PublicDataSchemaError("JSON root must be an object")
    return value
