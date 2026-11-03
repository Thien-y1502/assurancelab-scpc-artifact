from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Evidence


@dataclass(frozen=True)
class LedgerEntry:
    sequence: int
    evidence_id: str
    appended_at: datetime
    evidence: Evidence


class EvidenceLedger:
    """Small append-only ledger used by the local replay harness."""

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._ids: set[str] = set()

    def append(self, evidence: Evidence, *, appended_at: datetime | None = None) -> LedgerEntry:
        if evidence.evidence_id in self._ids:
            raise ValueError(f"duplicate evidence id: {evidence.evidence_id}")
        if not evidence.integrity_hash.strip():
            raise ValueError("evidence integrity hash is required")
        entry = LedgerEntry(
            sequence=len(self._entries) + 1,
            evidence_id=evidence.evidence_id,
            appended_at=appended_at or datetime.now(timezone.utc),
            evidence=evidence,
        )
        self._entries.append(entry)
        self._ids.add(evidence.evidence_id)
        return entry

    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def export_jsonl(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            for entry in self._entries:
                payload = asdict(entry)
                handle.write(json.dumps(payload, default=_json_default, sort_keys=True) + "\n")


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"unsupported ledger value: {type(value)!r}")

