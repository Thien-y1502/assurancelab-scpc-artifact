from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from .models import Evidence, EvidenceKind
from .provenance import evidence_hash
from .auth import SignatureVerifier
from .replay import ReplayGuard


class EvidenceAdapter:
    """Boundary for external telemetry; adapters never decide PASS/FAIL."""

    def read(self, records: Iterable[Mapping[str, Any]]) -> tuple[Evidence, ...]:
        raise NotImplementedError


class MappingEvidenceAdapter(EvidenceAdapter):
    """Convert normalized, user-owned records into immutable Evidence."""

    def __init__(self, *, keyring: SignatureVerifier | None = None, require_signature: bool = False, replay_guard: ReplayGuard | None = None, require_replay: bool = False) -> None:
        self.keyring = keyring
        self.require_signature = require_signature
        self.replay_guard = replay_guard
        self.require_replay = require_replay

    def read(self, records: Iterable[Mapping[str, Any]]) -> tuple[Evidence, ...]:
        output: list[Evidence] = []
        for record in records:
            required = ("evidence_id", "subject", "assertion", "value", "observed_at", "kind", "provenance")
            missing = [key for key in required if key not in record]
            if missing:
                raise ValueError(f"missing evidence fields: {', '.join(missing)}")
            observed_at = _datetime(record["observed_at"])
            expires_at = None if record.get("expires_at") is None else _datetime(record["expires_at"])
            value = record["value"]
            metadata = dict(record.get("metadata", {}))
            for auth_key in ("key_id", "producer_id", "sequence", "nonce"):
                if auth_key in record:
                    metadata[f"_auth_{auth_key}"] = record[auth_key]
            provisional = Evidence(
                evidence_id=str(record["evidence_id"]),
                subject=str(record["subject"]),
                assertion=str(record["assertion"]),
                value=value,
                observed_at=observed_at,
                expires_at=expires_at,
                kind=EvidenceKind(str(record["kind"])),
                provenance=str(record["provenance"]),
                integrity_hash="",
                independent=bool(record.get("independent", True)),
                metadata=metadata,
            )
            expected_hash = evidence_hash(provisional)
            supplied_hash = record.get("integrity_hash")
            integrity_hash = expected_hash if supplied_hash is None else str(supplied_hash)
            metadata["_integrity_expected_hash"] = expected_hash
            metadata["_integrity_verified"] = integrity_hash == expected_hash
            key_id = record.get("key_id")
            signature = record.get("signature")
            signature_verified = False
            signature_error: str | None = None
            if key_id is not None and signature is not None and self.keyring is not None:
                try:
                    signature_verified = self.keyring.verify(provisional, str(key_id), str(signature))
                except Exception as exc:
                    # An unavailable or malformed custody provider must never
                    # become an optimistic PASS at the audit boundary.
                    signature_error = type(exc).__name__
            metadata["_signature_verified"] = signature_verified if self.require_signature else True
            if signature_error is not None:
                metadata["_signature_error"] = signature_error
            diagnostics = getattr(self.keyring, "last_diagnostics", None)
            if diagnostics is not None:
                metadata["_signature_provider_diagnostics"] = list(diagnostics)
            if key_id is not None:
                metadata["_signature_key_id"] = str(key_id)
            replay_verified = False
            if self.replay_guard is not None:
                replay_verified = self.replay_guard.observe(
                    str(record.get("producer_id", "")),
                    str(record.get("nonce", "")),
                    int(record.get("sequence", -1)),
                )
            metadata["_replay_verified"] = replay_verified if self.require_replay else True
            replay_error = getattr(self.replay_guard, "last_error", None)
            if replay_error is not None:
                metadata["_replay_error"] = replay_error
            replay_reason = getattr(self.replay_guard, "last_reason", None)
            if replay_reason is not None:
                metadata["_replay_reason"] = replay_reason
            output.append(
                Evidence(
                    evidence_id=provisional.evidence_id,
                    subject=provisional.subject,
                    assertion=provisional.assertion,
                    value=provisional.value,
                    observed_at=provisional.observed_at,
                    expires_at=provisional.expires_at,
                    kind=provisional.kind,
                    provenance=provisional.provenance,
                    integrity_hash=integrity_hash,
                    independent=provisional.independent,
                    metadata=metadata,
                )
            )
        return tuple(output)


def _datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("evidence timestamps must include a timezone")
        return parsed
    raise TypeError("evidence timestamp must be datetime or ISO-8601 string")

