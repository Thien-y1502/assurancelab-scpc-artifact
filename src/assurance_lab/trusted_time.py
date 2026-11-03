"""Versioned trusted-time contracts with explicit provenance and fail-closed quorum."""
from __future__ import annotations

import hashlib
import json
import math
import statistics
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Protocol
from urllib.parse import urlparse

from .provenance import canonical_json


TRUSTED_TIME_CONTRACT_VERSION = "trusted-time/v1"


class TrustedTimeUnavailable(RuntimeError):
    """Raised when a trusted-time provider cannot produce an acceptable sample."""


@dataclass(frozen=True)
class TimeSample:
    """A timestamp with enough provenance to audit its authority boundary."""

    timestamp: float
    source_id: str
    provider_version: str
    captured_at: float
    uncertainty_seconds: float = 0.0
    provenance: str = ""
    contract_version: str = TRUSTED_TIME_CONTRACT_VERSION

    def __post_init__(self) -> None:
        numeric = (self.timestamp, self.captured_at, self.uncertainty_seconds)
        if any(not math.isfinite(float(value)) for value in numeric):
            raise ValueError("trusted-time numeric fields must be finite")
        if self.uncertainty_seconds < 0:
            raise ValueError("trusted-time uncertainty must be non-negative")
        for name, value in (
            ("source_id", self.source_id),
            ("provider_version", self.provider_version),
            ("provenance", self.provenance),
            ("contract_version", self.contract_version),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"trusted-time {name} must be non-empty")
        if self.contract_version != TRUSTED_TIME_CONTRACT_VERSION:
            raise ValueError("unsupported trusted-time contract version")

    def as_dict(self) -> dict[str, object]:
        return {
            "timestamp": float(self.timestamp),
            "source_id": self.source_id,
            "provider_version": self.provider_version,
            "captured_at": float(self.captured_at),
            "uncertainty_seconds": float(self.uncertainty_seconds),
            "provenance": self.provenance,
            "contract_version": self.contract_version,
        }


class TrustedTimeProvider(Protocol):
    """Provider contract consumed by runtime lease decisions."""

    def read(self) -> TimeSample:
        """Return one authenticated/provenance-bearing time sample."""


class PayloadSignatureVerifier(Protocol):
    """Verifier boundary for signatures over canonical receipt payloads."""

    def verify_payload(self, payload: object, key_id: str, signature: str) -> bool:
        ...


class CertificateStatusUnavailable(RuntimeError):
    """Raised when external certificate-status evidence cannot reach quorum."""


class ProviderIdentityAttestationPolicy:
    """Verify signed provider identity, region and certificate-lifetime claims."""

    def __init__(
        self,
        verifier: PayloadSignatureVerifier,
        *,
        trusted_regions: Iterable[str],
        max_age_seconds: float = 300.0,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.verifier = verifier
        self.trusted_regions = frozenset(str(item) for item in trusted_regions if str(item).strip())
        if not self.trusted_regions:
            raise ValueError("at least one trusted provider region is required")
        if not math.isfinite(float(max_age_seconds)) or max_age_seconds < 0:
            raise ValueError("attestation max_age_seconds must be finite and non-negative")
        self.max_age_seconds = float(max_age_seconds)
        self.wall_clock = wall_clock
        self.last_reason: str | None = None

    def validate(self, envelope: object, *, expected_provider_id: str | None = None) -> bool:
        self.last_reason = None
        try:
            if not isinstance(envelope, Mapping):
                return self._reject("attestation_missing")
            payload = envelope.get("payload")
            key_id = envelope.get("key_id")
            signature = envelope.get("signature")
            if not isinstance(payload, Mapping) or not isinstance(key_id, str) or not isinstance(signature, str) or not key_id.strip() or not signature:
                return self._reject("attestation_envelope_malformed")
            verify_payload = getattr(self.verifier, "verify_payload", None)
            if not callable(verify_payload) or not bool(verify_payload(dict(payload), key_id, signature)):
                return self._reject("attestation_signature_invalid")
            provider_id = payload.get("provider_id")
            region = payload.get("region")
            fingerprint = payload.get("cert_fingerprint")
            if not isinstance(provider_id, str) or not provider_id.strip() or (expected_provider_id is not None and provider_id != expected_provider_id):
                return self._reject("attestation_provider_mismatch")
            if not isinstance(region, str) or region not in self.trusted_regions:
                return self._reject("attestation_region_untrusted")
            if not isinstance(fingerprint, str) or not fingerprint.strip():
                return self._reject("attestation_fingerprint_missing")
            issued_at = float(payload["issued_at"])
            expires_at = float(payload["expires_at"])
            now = float(self.wall_clock())
            if not all(math.isfinite(value) for value in (issued_at, expires_at, now)):
                return self._reject("attestation_time_nonfinite")
            if issued_at > now:
                return self._reject("attestation_from_future")
            if now - issued_at > self.max_age_seconds:
                return self._reject("attestation_stale")
            if expires_at <= now:
                return self._reject("attestation_expired")
            return True
        except (TypeError, ValueError, KeyError):
            return self._reject("attestation_time_malformed")

    def _reject(self, reason: str) -> bool:
        self.last_reason = reason
        return False


class AttestedTrustedTimeProvider:
    """Bind a time provider sample to a signed provider identity attestation."""

    def __init__(
        self,
        provider: TrustedTimeProvider,
        attestation_loader: Callable[[], Mapping[str, object]],
        policy: ProviderIdentityAttestationPolicy,
    ) -> None:
        if not callable(attestation_loader):
            raise ValueError("attestation_loader must be callable")
        self.provider = provider
        self.attestation_loader = attestation_loader
        self.policy = policy
        self.last_error: str | None = None
        self.last_reason: str | None = None

    def read(self) -> TimeSample:
        self.last_error = None
        self.last_reason = None
        try:
            sample = self.provider.read()
            if not isinstance(sample, TimeSample):
                raise TypeError("attested provider returned a non-TimeSample value")
            envelope = self.attestation_loader()
            if not self.policy.validate(envelope, expected_provider_id=sample.source_id):
                self.last_reason = self.policy.last_reason or "attestation_invalid"
                raise TrustedTimeUnavailable(self.last_reason)
            return sample
        except TrustedTimeUnavailable:
            self.last_error = "TrustedTimeUnavailable"
            raise
        except Exception as exc:
            self.last_error = type(exc).__name__
            self.last_reason = str(exc)
            raise TrustedTimeUnavailable(self.last_reason) from exc


class CertificateStatusProvider(Protocol):
    """External OCSP/CRL status adapter contract."""

    def fetch(self, issuer: str, serial: str) -> Mapping[str, object]:
        ...


class HTTPSCertificateStatusProvider:
    """HTTPS-by-default OCSP/CRL status transport for one responder."""

    def __init__(
        self,
        endpoint: str,
        *,
        identity: str,
        timeout_seconds: float = 2.0,
        allow_insecure_local: bool = False,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("certificate status endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and (not allow_insecure_local or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}):
            raise ValueError("HTTPS is required except for an explicit loopback fixture")
        if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        self.endpoint = endpoint
        self.identity = str(identity)
        self.timeout_seconds = float(timeout_seconds)
        self.ssl_context = ssl_context
        self.last_error: str | None = None
        self.last_reason: str | None = None

    def fetch(self, issuer: str, serial: str) -> Mapping[str, object]:
        self.last_error = None
        self.last_reason = None
        body = json.dumps({"operation": "certificate_status", "issuer": str(issuer), "serial": str(serial)}, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(self.endpoint, data=body, headers={"Accept": "application/json", "Content-Type": "application/json", "X-Provider-Identity": self.identity}, method="POST")
        try:
            open_kwargs: dict[str, object] = {"timeout": self.timeout_seconds}
            if self.ssl_context is not None:
                open_kwargs["context"] = self.ssl_context
            with urllib.request.urlopen(request, **open_kwargs) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            self.last_error = type(exc).__name__
            self.last_reason = f"status request failed: {self.last_error}"
            raise CertificateStatusUnavailable(self.last_reason) from exc
        if not isinstance(decoded, Mapping):
            self.last_reason = "status response is not an object"
            raise CertificateStatusUnavailable(self.last_reason)
        return dict(decoded)


class QuorumCertificateStatusProvider:
    """Require matching OCSP/CRL responses and retain the accepted evidence."""

    def __init__(
        self,
        providers: Mapping[str, CertificateStatusProvider] | Iterable[CertificateStatusProvider],
        *,
        quorum: int,
        retention_path: str | None = None,
    ) -> None:
        if isinstance(providers, Mapping):
            self.providers = tuple(providers.items())
        else:
            self.providers = tuple((str(index), provider) for index, provider in enumerate(providers))
        if not self.providers or quorum < 1 or quorum > len(self.providers):
            raise ValueError("certificate status quorum must be within provider count")
        self.quorum = int(quorum)
        self.retention_path = retention_path
        self.last_error: str | None = None
        self.last_reason: str | None = None
        self.last_diagnostics: list[dict[str, object]] = []

    def fetch(self, issuer: str, serial: str) -> Mapping[str, object]:
        self.last_error = None
        self.last_reason = None
        self.last_diagnostics = []
        responses: list[tuple[str, Mapping[str, object]]] = []
        for name, provider in self.providers:
            try:
                response = provider.fetch(issuer, serial)
                if not isinstance(response, Mapping):
                    raise TypeError("certificate status response must be an object")
                if response.get("issuer") != issuer or response.get("serial") != serial:
                    raise ValueError("certificate status identity mismatch")
                responses.append((name, dict(response)))
                self.last_diagnostics.append({"provider": name, "status": "received"})
            except Exception as exc:
                self.last_error = type(exc).__name__
                self.last_diagnostics.append({"provider": name, "status": "error", "error": type(exc).__name__})
        if not responses:
            self.last_reason = "no_status_responses"
            raise CertificateStatusUnavailable(self.last_reason)
        clusters: dict[str, list[tuple[str, Mapping[str, object]]]] = {}
        for name, response in responses:
            fingerprint_payload = {key: response.get(key) for key in ("issuer", "serial", "ocsp_status", "crl_status", "checked_at", "next_update")}
            fingerprint = canonical_json(fingerprint_payload)
            clusters.setdefault(fingerprint, []).append((name, response))
        winner = max(clusters.values(), key=len)
        if len(winner) < self.quorum:
            self.last_reason = "status_disagreement" if len(responses) >= self.quorum else "insufficient_status_quorum"
            raise CertificateStatusUnavailable(self.last_reason)
        accepted = dict(winner[0][1])
        accepted["responders"] = [name for name, _ in winner]
        if self.retention_path is not None:
            try:
                from .audit import AuditChain

                AuditChain(self.retention_path).append({"event": "certificate_status", "issuer": issuer, "serial": serial, "status": accepted})
            except Exception as exc:
                self.last_error = type(exc).__name__
                self.last_reason = "status_retention_failed"
                raise CertificateStatusUnavailable(self.last_reason) from exc
        return accepted


class CertificateValidationPolicy:
    """Deterministic chain/OCSP/CRL status policy for signed receipts."""

    def __init__(
        self,
        trusted_issuers: Iterable[str],
        *,
        revoked_serials: Iterable[str] = (),
        max_status_age_seconds: float = 300.0,
        require_ocsp: bool = True,
        require_crl: bool = True,
        status_provider: CertificateStatusProvider | None = None,
    ) -> None:
        self.trusted_issuers = frozenset(str(item) for item in trusted_issuers if str(item).strip())
        self.revoked_serials = frozenset(str(item) for item in revoked_serials)
        if not self.trusted_issuers:
            raise ValueError("at least one trusted certificate issuer is required")
        if not math.isfinite(float(max_status_age_seconds)) or max_status_age_seconds < 0:
            raise ValueError("max_status_age_seconds must be finite and non-negative")
        self.max_status_age_seconds = float(max_status_age_seconds)
        self.require_ocsp = bool(require_ocsp)
        self.require_crl = bool(require_crl)
        self.status_provider = status_provider
        self.last_reason: str | None = None

    def validate(self, metadata: object, *, now: float) -> bool:
        self.last_reason = None
        if not isinstance(metadata, Mapping):
            return self._reject("certificate_missing")
        if metadata.get("chain_valid") is not True:
            return self._reject("chain_invalid")
        issuer = metadata.get("issuer")
        serial = metadata.get("serial")
        if not isinstance(issuer, str) or issuer not in self.trusted_issuers:
            return self._reject("issuer_untrusted")
        if not isinstance(serial, str) or not serial.strip():
            return self._reject("serial_missing")
        if serial in self.revoked_serials:
            return self._reject("serial_revoked")
        if self.status_provider is not None:
            try:
                external_status = self.status_provider.fetch(issuer, serial)
            except Exception as exc:
                provider_reason = getattr(self.status_provider, "last_reason", None)
                return self._reject(f"status_provider_error:{provider_reason or type(exc).__name__}")
            if not isinstance(external_status, Mapping):
                return self._reject("status_provider_malformed")
            if external_status.get("issuer") != issuer or external_status.get("serial") != serial:
                return self._reject("status_provider_identity_mismatch")
            metadata = {**metadata, **dict(external_status)}
        if self.require_ocsp and metadata.get("ocsp_status") != "good":
            return self._reject("ocsp_not_good")
        if self.require_crl and metadata.get("crl_status") != "good":
            return self._reject("crl_not_good")
        checked_at = metadata.get("checked_at")
        next_update = metadata.get("next_update")
        try:
            checked = float(checked_at)
            next_refresh = float(next_update)
            current = float(now)
        except (TypeError, ValueError):
            return self._reject("status_time_malformed")
        if not all(math.isfinite(value) for value in (checked, next_refresh, current)):
            return self._reject("status_time_nonfinite")
        if checked > current:
            return self._reject("status_from_future")
        if current - checked > self.max_status_age_seconds:
            return self._reject("status_stale")
        if next_refresh < current:
            return self._reject("status_expired")
        return True

    def _reject(self, reason: str) -> bool:
        self.last_reason = reason
        return False


class StaticTrustedTimeProvider:
    """Small deterministic provider useful for fixtures and controlled tests."""

    def __init__(self, sample: TimeSample) -> None:
        self.sample = sample

    def read(self) -> TimeSample:
        return self.sample


class SignedTimeReceiptProvider:
    """Verify and freshness-check an externally supplied signed time receipt."""

    def __init__(
        self,
        receipt_loader: Callable[[], Mapping[str, object]],
        verifier: PayloadSignatureVerifier,
        *,
        max_age_seconds: float = 5.0,
        wall_clock: Callable[[], float] = time.time,
        certificate_policy: CertificateValidationPolicy | None = None,
    ) -> None:
        if not callable(receipt_loader):
            raise ValueError("receipt_loader must be callable")
        if not math.isfinite(float(max_age_seconds)) or max_age_seconds < 0:
            raise ValueError("max_age_seconds must be finite and non-negative")
        self.receipt_loader = receipt_loader
        self.verifier = verifier
        self.max_age_seconds = float(max_age_seconds)
        self.wall_clock = wall_clock
        self.certificate_policy = certificate_policy
        self.last_error: str | None = None
        self.last_reason: str | None = None
        self.last_sample: TimeSample | None = None

    def read(self) -> TimeSample:
        self.last_error = None
        self.last_reason = None
        self.last_sample = None
        try:
            receipt = self.receipt_loader()
            if not isinstance(receipt, Mapping):
                raise TypeError("signed time receipt must be an object")
            payload = receipt.get("payload")
            key_id = receipt.get("key_id")
            signature = receipt.get("signature")
            if not isinstance(payload, Mapping) or not isinstance(key_id, str) or not key_id.strip() or not isinstance(signature, str) or not signature:
                raise ValueError("signed time receipt envelope is malformed")
            verify_payload = getattr(self.verifier, "verify_payload", None)
            if not callable(verify_payload):
                raise TypeError("verifier must provide verify_payload(payload, key_id, signature)")
            if not bool(verify_payload(dict(payload), key_id, signature)):
                self.last_reason = "signature_invalid"
                raise TrustedTimeUnavailable(self.last_reason)
            sample = TimeSample(
                timestamp=float(payload["timestamp"]),
                source_id=str(payload["source_id"]),
                provider_version=str(payload["provider_version"]),
                captured_at=float(payload["captured_at"]),
                uncertainty_seconds=float(payload.get("uncertainty_seconds", 0.0)),
                provenance=str(payload["provenance"]),
                contract_version=str(payload.get("contract_version", TRUSTED_TIME_CONTRACT_VERSION)),
            )
            now = float(self.wall_clock())
            if not math.isfinite(now):
                raise ValueError("trusted-time wall clock is not finite")
            if self.certificate_policy is not None and not self.certificate_policy.validate(payload.get("certificate"), now=now):
                self.last_reason = f"certificate_policy:{self.certificate_policy.last_reason}"
                raise TrustedTimeUnavailable(self.last_reason)
            age = now - sample.captured_at
            if age > self.max_age_seconds:
                self.last_reason = "stale_receipt"
                raise TrustedTimeUnavailable(self.last_reason)
            if age < -self.max_age_seconds:
                self.last_reason = "future_receipt"
                raise TrustedTimeUnavailable(self.last_reason)
            self.last_sample = sample
            return sample
        except TrustedTimeUnavailable:
            self.last_error = "TrustedTimeUnavailable"
            raise
        except Exception as exc:
            self.last_error = type(exc).__name__
            self.last_reason = str(exc)
            raise TrustedTimeUnavailable(self.last_reason) from exc


class HTTPSignedTimeReceiptProvider(SignedTimeReceiptProvider):
    """Network transport for signed receipts with HTTPS/mTLS-by-context policy."""

    def __init__(
        self,
        endpoint: str,
        verifier: PayloadSignatureVerifier,
        *,
        identity: str,
        timeout_seconds: float = 2.0,
        allow_insecure_local: bool = False,
        ssl_context: ssl.SSLContext | None = None,
        max_age_seconds: float = 5.0,
        wall_clock: Callable[[], float] = time.time,
        certificate_policy: CertificateValidationPolicy | None = None,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("time receipt endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and (not allow_insecure_local or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}):
            raise ValueError("HTTPS is required except for an explicit loopback fixture")
        if not math.isfinite(float(timeout_seconds)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be finite and positive")
        self.endpoint = endpoint
        self.identity = str(identity)
        self.timeout_seconds = float(timeout_seconds)
        self.ssl_context = ssl_context
        super().__init__(self._load_receipt, verifier, max_age_seconds=max_age_seconds, wall_clock=wall_clock, certificate_policy=certificate_policy)

    def _load_receipt(self) -> Mapping[str, object]:
        body = json.dumps(
            {"operation": "time", "contract_version": TRUSTED_TIME_CONTRACT_VERSION},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Provider-Identity": self.identity,
            },
            method="POST",
        )
        try:
            open_kwargs: dict[str, object] = {"timeout": self.timeout_seconds}
            if self.ssl_context is not None:
                open_kwargs["context"] = self.ssl_context
            with urllib.request.urlopen(request, **open_kwargs) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"time receipt request failed: {type(exc).__name__}") from exc
        if not isinstance(decoded, Mapping):
            raise ValueError("time receipt endpoint must return a JSON object")
        return decoded


class SequenceTrustedTimeProvider:
    """Deterministic provider that consumes a finite sequence of samples."""

    def __init__(self, samples: Iterable[TimeSample]) -> None:
        self._samples = list(samples)

    def read(self) -> TimeSample:
        if not self._samples:
            raise TrustedTimeUnavailable("trusted-time sample sequence exhausted")
        return self._samples.pop(0)


class QuorumTrustedTimeProvider:
    """Reject stale/disagreeing sources and return a provenance-bound quorum sample."""

    def __init__(
        self,
        providers: Mapping[str, TrustedTimeProvider] | Iterable[TrustedTimeProvider],
        *,
        quorum: int,
        max_skew_seconds: float = 0.5,
        max_age_seconds: float = 5.0,
        wall_clock: Callable[[], float] = time.time,
        retention_path: str | None = None,
    ) -> None:
        if isinstance(providers, Mapping):
            self.providers = tuple(providers.items())
        else:
            self.providers = tuple((str(index), provider) for index, provider in enumerate(providers))
        if not self.providers:
            raise ValueError("at least one trusted-time provider is required")
        if quorum < 1 or quorum > len(self.providers):
            raise ValueError("trusted-time quorum must be within provider count")
        if not math.isfinite(float(max_skew_seconds)) or max_skew_seconds < 0:
            raise ValueError("max_skew_seconds must be finite and non-negative")
        if not math.isfinite(float(max_age_seconds)) or max_age_seconds < 0:
            raise ValueError("max_age_seconds must be finite and non-negative")
        self.quorum = int(quorum)
        self.max_skew_seconds = float(max_skew_seconds)
        self.max_age_seconds = float(max_age_seconds)
        self.wall_clock = wall_clock
        self.retention_path = retention_path
        self.last_error: str | None = None
        self.last_reason: str | None = None
        self.last_sample: TimeSample | None = None
        self.last_diagnostics: list[dict[str, object]] = []

    def read(self) -> TimeSample:
        self.last_error = None
        self.last_reason = None
        self.last_sample = None
        self.last_diagnostics = []
        now = float(self.wall_clock())
        if not math.isfinite(now):
            self.last_reason = "invalid_wall_clock"
            raise TrustedTimeUnavailable(self.last_reason)
        samples: list[TimeSample] = []
        errors: list[str] = []
        for source_key, provider in self.providers:
            try:
                if not callable(getattr(provider, "read", None)):
                    raise TypeError("provider must implement read()")
                sample = provider.read()
                if not isinstance(sample, TimeSample):
                    raise TypeError("provider returned a non-TimeSample value")
                age = now - sample.captured_at
                if age > self.max_age_seconds:
                    raise TrustedTimeUnavailable(f"stale:{source_key}")
                if age < -self.max_age_seconds:
                    raise TrustedTimeUnavailable(f"future:{source_key}")
                samples.append(sample)
                self.last_diagnostics.append({"provider": source_key, "status": "accepted"})
            except Exception as exc:
                self.last_error = type(exc).__name__
                errors.append(str(exc))
                self.last_diagnostics.append({"provider": source_key, "status": "error", "error": type(exc).__name__})
                continue
        if len(samples) < self.quorum:
            self.last_reason = errors[0] if not samples and len(self.providers) == self.quorum == 1 and errors else "insufficient_samples"
            raise TrustedTimeUnavailable(self.last_reason)

        clusters: list[list[TimeSample]] = []
        for candidate in samples:
            cluster = [
                sample
                for sample in samples
                if abs(sample.timestamp - candidate.timestamp)
                <= self.max_skew_seconds + sample.uncertainty_seconds + candidate.uncertainty_seconds
            ]
            clusters.append(cluster)
        largest = max(clusters, key=len)
        if len(largest) < self.quorum:
            self.last_reason = "source_disagreement"
            raise TrustedTimeUnavailable(self.last_reason)
        winner_signature = tuple(sorted(sample.source_id for sample in largest))
        competing = {
            tuple(sorted(cluster_item.source_id for cluster_item in cluster))
            for cluster in clusters
            if len(cluster) >= self.quorum
        }
        if len(competing) > 1 and len(largest) == self.quorum:
            self.last_reason = "ambiguous_quorum"
            raise TrustedTimeUnavailable(self.last_reason)
        ordered = sorted(largest, key=lambda sample: sample.timestamp)
        timestamp = float(statistics.median([sample.timestamp for sample in ordered]))
        provenance_payload = {
            "contract_version": TRUSTED_TIME_CONTRACT_VERSION,
            "sources": [sample.as_dict() for sample in sorted(largest, key=lambda item: item.source_id)],
            "quorum": self.quorum,
            "winner": winner_signature,
        }
        provenance_json = json.dumps(provenance_payload, sort_keys=True, separators=(",", ":"))
        result = TimeSample(
            timestamp=timestamp,
            source_id="quorum",
            provider_version=TRUSTED_TIME_CONTRACT_VERSION,
            captured_at=now,
            uncertainty_seconds=max(sample.uncertainty_seconds for sample in largest) + self.max_skew_seconds,
            provenance="sha256:" + hashlib.sha256(provenance_json.encode("utf-8")).hexdigest(),
        )
        self.last_sample = result
        if self.retention_path is not None:
            try:
                from .audit import AuditChain

                AuditChain(self.retention_path).append({"event": "trusted_time_quorum", "timestamp": result.timestamp, "sources": list(winner_signature), "captured_at": result.captured_at})
            except Exception as exc:
                self.last_error = type(exc).__name__
                self.last_reason = "quorum_retention_failed"
                raise TrustedTimeUnavailable(self.last_reason) from exc
        return result
