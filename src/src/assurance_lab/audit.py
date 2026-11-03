"""Tamper-evident local audit chains for evidence provenance."""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from .provenance import canonical_json


GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditChainVerification:
    valid: bool
    records: int
    head_hash: str
    reason: str


class AuditChain:
    """Append-only hash chain with explicit verification and head anchoring.

    The chain provides tamper evidence, not authenticity. A deployment must
    protect the expected head hash (or an external signed checkpoint) if it
    needs to detect deletion of the final records.
    """

    def __init__(self, path: str | os.PathLike[str], *, genesis_hash: str = GENESIS_HASH) -> None:
        self.path = Path(path)
        if len(genesis_hash) != 64 or any(character not in "0123456789abcdef" for character in genesis_hash):
            raise ValueError("genesis_hash must be a lowercase SHA-256 hex digest")
        self.genesis_hash = genesis_hash

    def append(self, event: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            raise TypeError("audit event must be a mapping")
        with self._exclusive_lock():
            current = self.verify()
            if not current.valid:
                raise ValueError(f"cannot append to invalid audit chain: {current.reason}")
            payload: dict[str, Any] = {
                "sequence": current.records + 1,
                "prev_hash": current.head_hash,
                "event": dict(event),
            }
            record = dict(payload)
            record["record_hash"] = _record_hash(payload)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(canonical_json(record) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            return record

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        lock_path = self.path.with_name(self.path.name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def verify(self, *, expected_head_hash: str | None = None) -> AuditChainVerification:
        if not self.path.exists():
            head = self.genesis_hash
            if expected_head_hash is not None and expected_head_hash != head:
                return AuditChainVerification(False, 0, head, "head_mismatch")
            return AuditChainVerification(True, 0, head, "empty")
        previous = self.genesis_hash
        records = 0
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        return AuditChainVerification(False, records, previous, f"blank_line:{line_number}")
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        return AuditChainVerification(False, records, previous, f"invalid_json:{line_number}")
                    if not isinstance(record, dict):
                        return AuditChainVerification(False, records, previous, f"record_not_object:{line_number}")
                    if set(record) != {"sequence", "prev_hash", "event", "record_hash"}:
                        return AuditChainVerification(False, records, previous, f"schema:{line_number}")
                    expected_sequence = records + 1
                    if record["sequence"] != expected_sequence:
                        return AuditChainVerification(False, records, previous, f"sequence:{line_number}")
                    if record["prev_hash"] != previous:
                        return AuditChainVerification(False, records, previous, f"prev_hash:{line_number}")
                    payload = {"sequence": record["sequence"], "prev_hash": record["prev_hash"], "event": record["event"]}
                    expected_record_hash = _record_hash(payload)
                    if record["record_hash"] != expected_record_hash:
                        return AuditChainVerification(False, records, previous, f"record_hash:{line_number}")
                    previous = expected_record_hash
                    records += 1
        except (OSError, UnicodeError) as exc:
            return AuditChainVerification(False, records, previous, f"io:{type(exc).__name__}")
        if expected_head_hash is not None and previous != expected_head_hash:
            return AuditChainVerification(False, records, previous, "head_mismatch")
        return AuditChainVerification(True, records, previous, "ok")

    def create_checkpoint(self, signer: object, key_id: str) -> dict[str, Any]:
        state = self.verify()
        if not state.valid:
            raise ValueError(f"cannot checkpoint invalid audit chain: {state.reason}")
        payload = {
            "genesis_hash": self.genesis_hash,
            "head_hash": state.head_hash,
            "records": state.records,
        }
        sign_payload = getattr(signer, "sign_payload", None)
        if not callable(sign_payload):
            raise TypeError("signer must provide sign_payload(payload, key_id)")
        return {
            "algorithm": "HMAC-SHA256",
            "key_id": str(key_id),
            "payload": payload,
            "signature": str(sign_payload(payload, key_id)),
        }

    def verify_checkpoint(self, checkpoint: Mapping[str, Any], verifier: object) -> AuditChainVerification:
        if not isinstance(checkpoint, Mapping) or set(checkpoint) != {"algorithm", "key_id", "payload", "signature"}:
            return AuditChainVerification(False, 0, self.genesis_hash, "checkpoint_schema")
        if checkpoint.get("algorithm") != "HMAC-SHA256":
            return AuditChainVerification(False, 0, self.genesis_hash, "checkpoint_algorithm")
        payload = checkpoint.get("payload")
        if not isinstance(payload, Mapping) or set(payload) != {"genesis_hash", "head_hash", "records"}:
            return AuditChainVerification(False, 0, self.genesis_hash, "checkpoint_payload")
        if payload.get("genesis_hash") != self.genesis_hash or not isinstance(payload.get("records"), int):
            return AuditChainVerification(False, 0, self.genesis_hash, "checkpoint_genesis")
        state = self.verify(expected_head_hash=str(payload.get("head_hash")))
        if not state.valid:
            return state
        if state.records != payload.get("records"):
            return AuditChainVerification(False, state.records, state.head_hash, "checkpoint_records")
        verify_payload = getattr(verifier, "verify_payload", None)
        if not callable(verify_payload):
            return AuditChainVerification(False, state.records, state.head_hash, "checkpoint_verifier_unavailable")
        try:
            verified = bool(verify_payload(payload, str(checkpoint.get("key_id")), str(checkpoint.get("signature"))))
        except Exception:
            return AuditChainVerification(False, state.records, state.head_hash, "checkpoint_verifier_error")
        if not verified:
            return AuditChainVerification(False, state.records, state.head_hash, "checkpoint_signature")
        return AuditChainVerification(True, state.records, state.head_hash, "checkpoint_ok")


def _record_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
