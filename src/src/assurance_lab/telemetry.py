"""Strict, provenance-preserving telemetry ingestion for audit evidence.

The connector normalizes transport data but never makes an audit decision.
Malformed, duplicated or oversized batches fail closed before reaching the
engine; integrity and signature policy remain the responsibility of the
configured ``MappingEvidenceAdapter``.
"""
from __future__ import annotations

import hashlib
import json
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from .adapters import EvidenceAdapter
from .models import Evidence


TELEMETRY_SCHEMA_V1 = "assurance-telemetry/v1"


class _HttpsOnlyRedirectHandler(HTTPRedirectHandler):
    """Prevent a telemetry request from following an HTTPS-to-HTTP downgrade."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if urlsplit(newurl).scheme.lower() != "https":
            raise TelemetrySchemaError("telemetry redirect must remain HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class TelemetrySchemaError(ValueError):
    """Raised when a telemetry envelope cannot be admitted safely."""


@dataclass(frozen=True)
class TelemetryBatch:
    evidence: tuple[Evidence, ...]
    source: str
    source_sha256: str
    schema_version: str
    record_count: int


def ingest_json_envelope(
    payload: str | bytes | bytearray | Mapping[str, Any],
    adapter: EvidenceAdapter,
    *,
    source: str = "inline",
    max_records: int = 10_000,
    schema_version: str = TELEMETRY_SCHEMA_V1,
) -> TelemetryBatch:
    """Admit a versioned JSON telemetry envelope into immutable evidence.

    The raw JSON bytes are hashed for transport provenance. The adapter then
    performs evidence normalization and optional integrity/signature/replay
    checks. The function is intentionally strict: callers receive no partial
    batch when the envelope is malformed.
    """
    raw = _raw_bytes(payload)
    document = _decode(payload)
    if document.get("schema_version") != schema_version:
        raise TelemetrySchemaError("unsupported telemetry schema version")
    records = document.get("records")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise TelemetrySchemaError("records must be a sequence")
    if len(records) > max_records:
        raise TelemetrySchemaError(f"record limit exceeded: {len(records)} > {max_records}")
    if not all(isinstance(record, Mapping) for record in records):
        raise TelemetrySchemaError("records must contain mappings")
    ids = [str(record.get("evidence_id", "")) for record in records]
    if any(not evidence_id for evidence_id in ids):
        raise TelemetrySchemaError("every record requires evidence_id")
    if len(set(ids)) != len(ids):
        raise TelemetrySchemaError("duplicate evidence_id in telemetry batch")
    try:
        evidence = adapter.read(records)
    except (TypeError, ValueError, KeyError) as exc:
        raise TelemetrySchemaError(f"record normalization failed: {type(exc).__name__}") from exc
    return TelemetryBatch(tuple(evidence), str(source), hashlib.sha256(raw).hexdigest().upper(), schema_version, len(records))


def ingest_jsonl(
    payload: str | bytes | bytearray,
    adapter: EvidenceAdapter,
    *,
    source: str = "inline-jsonl",
    max_records: int = 10_000,
    schema_version: str = TELEMETRY_SCHEMA_V1,
) -> TelemetryBatch:
    """Convert newline-delimited records into the same strict envelope path."""
    raw = _raw_bytes(payload)
    try:
        lines = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetrySchemaError("invalid JSONL payload") from exc
    return ingest_json_envelope(
        {"schema_version": schema_version, "records": lines},
        adapter,
        source=source,
        max_records=max_records,
        schema_version=schema_version,
    )


def ingest_otlp_json(
    payload: str | bytes | bytearray | Mapping[str, Any],
    adapter: EvidenceAdapter,
    *,
    source: str = "otlp-json",
    max_records: int = 10_000,
    schema_version: str = TELEMETRY_SCHEMA_V1,
) -> TelemetryBatch:
    """Normalize the bounded OTLP/HTTP JSON log shape into audit evidence.

    The connector consumes resource logs and maps assurance fields from log
    attributes. It intentionally supports a small, explicit interoperability
    profile rather than guessing arbitrary application log text.
    """
    raw = _raw_bytes(payload)
    document = _decode(payload)
    resource_logs = document.get("resourceLogs")
    if not isinstance(resource_logs, Sequence) or isinstance(resource_logs, (str, bytes, bytearray)):
        raise TelemetrySchemaError("OTLP resourceLogs must be a sequence")
    records: list[dict[str, Any]] = []
    for resource_log in resource_logs:
        if not isinstance(resource_log, Mapping):
            raise TelemetrySchemaError("OTLP resource log must be an object")
        resource = resource_log.get("resource", {})
        resource_attributes = _otlp_attributes(resource.get("attributes", [])) if isinstance(resource, Mapping) else {}
        default_subject = resource_attributes.get("service.name") or resource_attributes.get("assurance.subject")
        scopes = resource_log.get("scopeLogs", [])
        if not isinstance(scopes, Sequence) or isinstance(scopes, (str, bytes, bytearray)):
            raise TelemetrySchemaError("OTLP scopeLogs must be a sequence")
        for scope in scopes:
            if not isinstance(scope, Mapping):
                raise TelemetrySchemaError("OTLP scope log must be an object")
            log_records = scope.get("logRecords", [])
            if not isinstance(log_records, Sequence) or isinstance(log_records, (str, bytes, bytearray)):
                raise TelemetrySchemaError("OTLP logRecords must be a sequence")
            for log_record in log_records:
                if not isinstance(log_record, Mapping):
                    raise TelemetrySchemaError("OTLP log record must be an object")
                attributes = _otlp_attributes(log_record.get("attributes", []))
                evidence_id = attributes.get("assurance.evidence_id")
                assertion = attributes.get("assurance.assertion")
                observed_at = _otlp_time(log_record.get("timeUnixNano"))
                value = attributes.get("assurance.value", _otlp_any_value(log_record.get("body")))
                provenance = attributes.get("assurance.provenance")
                subject = attributes.get("assurance.subject", default_subject)
                if not evidence_id or not assertion or observed_at is None or provenance is None or subject is None:
                    raise TelemetrySchemaError("OTLP record lacks required assurance attributes")
                record: dict[str, Any] = {
                    "evidence_id": str(evidence_id),
                    "subject": str(subject),
                    "assertion": str(assertion),
                    "value": value,
                    "observed_at": observed_at,
                    "expires_at": attributes.get("assurance.expires_at"),
                    "kind": str(attributes.get("assurance.kind", "runtime")),
                    "provenance": str(provenance),
                }
                for key in ("integrity_hash", "key_id", "signature", "producer_id", "sequence", "nonce"):
                    assurance_key = f"assurance.{key}"
                    if assurance_key in attributes:
                        record[key] = attributes[assurance_key]
                    elif key in attributes:
                        record[key] = attributes[key]
                records.append(record)
    batch = ingest_json_envelope({"schema_version": schema_version, "records": records}, adapter, source=source, max_records=max_records, schema_version=schema_version)
    return replace(batch, source_sha256=hashlib.sha256(raw).hexdigest().upper())


def fetch_otlp_json(
    url: str,
    adapter: EvidenceAdapter,
    *,
    ssl_context: Any,
    payload: str | bytes | bytearray | None = None,
    source: str | None = None,
    timeout_seconds: float = 5.0,
    max_bytes: int = 10_000_000,
    max_records: int = 10_000,
) -> TelemetryBatch:
    """Fetch OTLP/HTTP JSON over a caller-provided (possibly mTLS) context."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise TelemetrySchemaError("telemetry endpoint must use an HTTPS URL")
    if ssl_context is None:
        raise TelemetrySchemaError("an explicit SSL context is required")
    body = None if payload is None else _raw_bytes(payload)
    request = Request(url, data=body, method="POST" if body is not None else "GET", headers={"Accept": "application/json", "Content-Type": "application/json"})
    try:
        opener = build_opener(HTTPSHandler(context=ssl_context), _HttpsOnlyRedirectHandler())
        with opener.open(request, timeout=timeout_seconds) as response:
            if getattr(response, "status", 200) != 200:
                raise TelemetrySchemaError(f"telemetry endpoint returned HTTP {response.status}")
            if urlsplit(response.geturl()).scheme.lower() != "https":
                raise TelemetrySchemaError("telemetry response URL must remain HTTPS")
            received = response.read(max_bytes + 1)
            if len(received) > max_bytes:
                raise TelemetrySchemaError("telemetry response exceeds byte limit")
    except TelemetrySchemaError:
        raise
    except (OSError, URLError, TimeoutError) as exc:
        raise TelemetrySchemaError(f"telemetry HTTPS fetch failed: {type(exc).__name__}") from exc
    return ingest_otlp_json(received, adapter, source=source or url, max_records=max_records)


def _decode(payload: str | bytes | bytearray | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(payload, Mapping):
        return payload
    try:
        value = json.loads(_raw_bytes(payload).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TelemetrySchemaError("invalid JSON telemetry envelope") from exc
    if not isinstance(value, Mapping):
        raise TelemetrySchemaError("telemetry envelope must be an object")
    return value


def _raw_bytes(payload: str | bytes | bytearray | Mapping[str, Any]) -> bytes:
    if isinstance(payload, str):
        return payload.encode("utf-8")
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, Mapping):
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    raise TypeError("payload must be JSON text, bytes, or a mapping")


def _otlp_any_value(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return value
    for key in ("stringValue", "boolValue", "intValue", "doubleValue", "bytesValue"):
        if key in value:
            item = value[key]
            if key == "intValue":
                return int(item)
            return item
    if "arrayValue" in value and isinstance(value["arrayValue"], Mapping):
        return [_otlp_any_value(item) for item in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value and isinstance(value["kvlistValue"], Mapping):
        return _otlp_attributes(value["kvlistValue"].get("values", []))
    return None


def _otlp_attributes(attributes: Any) -> dict[str, Any]:
    if not isinstance(attributes, Sequence) or isinstance(attributes, (str, bytes, bytearray)):
        raise TelemetrySchemaError("OTLP attributes must be a sequence")
    output: dict[str, Any] = {}
    for item in attributes:
        if not isinstance(item, Mapping) or not isinstance(item.get("key"), str) or "value" not in item:
            raise TelemetrySchemaError("invalid OTLP attribute")
        output[item["key"]] = _otlp_any_value(item["value"])
    return output


def _otlp_time(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1_000_000_000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise TelemetrySchemaError("invalid OTLP timeUnixNano") from exc
