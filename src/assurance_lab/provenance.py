from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from typing import Any


def canonical_json(value: Any) -> str:
    def default(obj: Any) -> str:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if is_dataclass(obj):
            return asdict(obj)
        raise TypeError(f"not serialisable: {type(obj)!r}")

    return json.dumps(value, default=default, sort_keys=True, separators=(",", ":"))


def sha256_record(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def evidence_payload(evidence: Any) -> dict[str, Any]:
    """Canonical, metadata-independent payload used for evidence hashing."""
    kind = getattr(evidence.kind, "value", evidence.kind)
    auth = {
        key: value
        for key, value in dict(getattr(evidence, "metadata", {})).items()
        if key.startswith("_auth_")
    }
    payload = {
        "evidence_id": evidence.evidence_id,
        "subject": evidence.subject,
        "assertion": evidence.assertion,
        "value": evidence.value,
        "observed_at": evidence.observed_at.isoformat(),
        "expires_at": None if evidence.expires_at is None else evidence.expires_at.isoformat(),
        "kind": kind,
        "provenance": evidence.provenance,
        "independent": evidence.independent,
    }
    if auth:
        payload["auth"] = auth
    return payload


def evidence_hash(evidence: Any) -> str:
    return sha256_record(evidence_payload(evidence))

