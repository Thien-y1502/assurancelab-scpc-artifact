from __future__ import annotations

import hashlib
import hmac
import json
import os
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlparse

from .provenance import canonical_json, evidence_payload


@dataclass(frozen=True)
class HMACKey:
    key_id: str
    secret: bytes
    active: bool = True


class SignatureVerifier(Protocol):
    """Minimal verifier contract used at the telemetry boundary.

    Implementations may keep key material locally or delegate verification to
    a process/service that owns the material. The evaluator only receives a
    boolean verification result.
    """

    def verify(self, evidence: object, key_id: str, signature: str) -> bool:
        ...


class HMACKeyring:
    """Small deterministic HMAC verifier for local and test deployments."""

    def __init__(self, keys: Mapping[str, HMACKey]) -> None:
        self._keys = dict(keys)

    def sign(self, evidence: object, key_id: str) -> str:
        key = self._keys[key_id]
        if not key.active:
            raise ValueError(f"inactive key: {key_id}")
        return self.sign_payload(evidence_payload(evidence), key_id)

    def sign_payload(self, payload: object, key_id: str) -> str:
        key = self._keys[key_id]
        if not key.active:
            raise ValueError(f"inactive key: {key_id}")
        message = canonical_json(payload).encode("utf-8")
        return hmac.new(key.secret, message, hashlib.sha256).hexdigest()

    def verify(self, evidence: object, key_id: str, signature: str) -> bool:
        key = self._keys.get(key_id)
        if key is None or not key.active:
            return False
        expected = self.sign(evidence, key_id)
        return hmac.compare_digest(expected, str(signature))

    def verify_payload(self, payload: object, key_id: str, signature: str) -> bool:
        key = self._keys.get(key_id)
        if key is None or not key.active:
            return False
        expected = self.sign_payload(payload, key_id)
        return hmac.compare_digest(expected, str(signature))


class ProcessSignatureVerifier:
    """One-shot JSON-lines verifier for a separately owned key process.

    The verifier intentionally accepts no secret. The command receives one
    canonical request on stdin and must return ``{"valid": bool}`` on stdout.
    This small protocol is suitable for a local custody fixture and makes the
    process boundary explicit; it is not itself a KMS/HSM implementation.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float = 2.0,
    ) -> None:
        if not command:
            raise ValueError("verifier command cannot be empty")
        self.command = tuple(str(item) for item in command)
        self.env = None if env is None else dict(env)
        self.timeout_seconds = float(timeout_seconds)

    def verify(self, evidence: object, key_id: str, signature: str) -> bool:
        request = canonical_json(
            {
                "payload": evidence_payload(evidence),
                "key_id": str(key_id),
                "signature": str(signature),
            }
        )
        process_env = None
        if self.env is not None:
            process_env = dict(os.environ)
            process_env.update(self.env)
        completed = subprocess.run(
            self.command,
            input=request + "\n",
            text=True,
            capture_output=True,
            check=False,
            timeout=self.timeout_seconds,
            env=process_env,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"signature verifier exited {completed.returncode}")
        try:
            response = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("signature verifier returned invalid JSON") from exc
        if not isinstance(response, dict) or not isinstance(response.get("valid"), bool):
            raise RuntimeError("signature verifier response must contain boolean valid")
        return bool(response["valid"])


class HTTPSignatureVerifier:
    """KMS-compatible HTTP verification contract without local key material.

    The evaluator sends a canonical payload and receives only a boolean
    decision. HTTPS is required by default; HTTP is permitted only for an
    explicitly opted-in loopback fixture. The implementation deliberately
    leaves key custody and provider audit storage to the remote service.
    """

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
            raise ValueError("signature provider endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme != "https":
            if not allow_insecure_local or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("HTTPS is required except for an explicit loopback fixture")
        self.endpoint = endpoint
        self.identity = str(identity)
        self.timeout_seconds = float(timeout_seconds)
        self.ssl_context = ssl_context

    def verify(self, evidence: object, key_id: str, signature: str) -> bool:
        decoded = self._post({"payload": evidence_payload(evidence), "key_id": str(key_id), "signature": str(signature)})
        if not isinstance(decoded.get("valid"), bool):
            raise RuntimeError("signature provider response must contain boolean valid")
        return bool(decoded["valid"])

    def verify_payload(self, payload: object, key_id: str, signature: str) -> bool:
        decoded = self._post({"payload": payload, "key_id": str(key_id), "signature": str(signature)})
        if not isinstance(decoded.get("valid"), bool):
            raise RuntimeError("signature provider response must contain boolean valid")
        return bool(decoded["valid"])

    def _post(self, payload: Mapping[str, object]) -> dict[str, Any]:
        body = canonical_json(payload).encode("utf-8")
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
            open_kwargs = {"timeout": self.timeout_seconds}
            if self.ssl_context is not None:
                open_kwargs["context"] = self.ssl_context
            with urllib.request.urlopen(request, **open_kwargs) as response:
                response_body = response.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            raise RuntimeError(f"signature provider request failed: {type(exc).__name__}") from exc
        try:
            decoded = json.loads(response_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("signature provider returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("signature provider response must be a JSON object")
        return decoded


class HTTPSignatureSigner(HTTPSignatureVerifier):
    """Remote canonical-payload signer for checkpoints or envelopes."""

    def sign_payload(self, payload: object, key_id: str) -> str:
        decoded = self._post({"operation": "sign", "payload": payload, "key_id": str(key_id)})
        signature = decoded.get("signature")
        if not isinstance(signature, str) or not signature:
            raise RuntimeError("signature provider response must contain signature")
        return signature


class QuorumSignatureSigner:
    """Require matching signatures from a remote key-custody quorum."""

    def __init__(self, signers: Sequence[object], *, quorum: int) -> None:
        if not signers or quorum < 1 or quorum > len(signers):
            raise ValueError("signature quorum must be within signer count")
        self.signers = tuple(signers)
        self.quorum = int(quorum)
        self._local = threading.local()

    @property
    def last_diagnostics(self) -> list[dict[str, Any]]:
        return list(getattr(self._local, "diagnostics", []))

    def sign_payload(self, payload: object, key_id: str) -> str:
        signatures: list[str] = []
        diagnostics: list[dict[str, Any]] = []
        for index, signer in enumerate(self.signers):
            try:
                sign_payload = getattr(signer, "sign_payload", None)
                if not callable(sign_payload):
                    raise TypeError("signer lacks sign_payload")
                signature = str(sign_payload(payload, key_id))
                if not signature:
                    raise ValueError("signer returned an empty signature")
                signatures.append(signature)
                diagnostics.append({"provider": index, "status": "signed"})
            except Exception as exc:
                diagnostics.append({"provider": index, "status": "error", "error": type(exc).__name__})
        self._local.diagnostics = diagnostics
        counts: dict[str, int] = {}
        for signature in signatures:
            counts[signature] = counts.get(signature, 0) + 1
        if not counts:
            raise RuntimeError("no signer produced a signature")
        signature, count = max(counts.items(), key=lambda item: item[1])
        if count < self.quorum:
            raise RuntimeError("signature quorum unavailable")
        return signature


class QuorumSignatureVerifier:
    """Verify a payload through a conservative remote key-custody quorum."""

    def __init__(self, verifiers: Sequence[SignatureVerifier], *, quorum: int) -> None:
        if not verifiers or quorum < 1 or quorum > len(verifiers):
            raise ValueError("signature quorum must be within verifier count")
        self.verifiers = tuple(verifiers)
        self.quorum = int(quorum)
        self._local = threading.local()

    @property
    def last_diagnostics(self) -> list[dict[str, Any]]:
        return list(getattr(self._local, "diagnostics", []))

    def verify_payload(self, payload: object, key_id: str, signature: str) -> bool:
        diagnostics: list[dict[str, Any]] = []
        values: list[bool] = []
        for index, verifier in enumerate(self.verifiers):
            try:
                verify_payload = getattr(verifier, "verify_payload", None)
                if not callable(verify_payload):
                    raise TypeError("verifier lacks verify_payload")
                result = bool(verify_payload(payload, key_id, signature))
                values.append(result)
                diagnostics.append({"provider": index, "status": "valid" if result else "invalid"})
            except Exception as exc:
                diagnostics.append({"provider": index, "status": "error", "error": type(exc).__name__})
        self._local.diagnostics = diagnostics
        if any(result is False for result in values):
            return False
        return len(values) >= self.quorum and all(values)

    def verify(self, evidence: object, key_id: str, signature: str) -> bool:
        diagnostics: list[dict[str, Any]] = []
        values: list[bool] = []
        for index, verifier in enumerate(self.verifiers):
            try:
                result = bool(verifier.verify(evidence, key_id, signature))
                values.append(result)
                diagnostics.append({"provider": index, "status": "valid" if result else "invalid"})
            except Exception as exc:
                diagnostics.append({"provider": index, "status": "error", "error": type(exc).__name__})
        self._local.diagnostics = diagnostics
        if any(result is False for result in values):
            return False
        return len(values) >= self.quorum and all(values)


class FailoverSignatureVerifier:
    """Combine trusted verifiers without allowing stale revocation bypasses.

    A provider returning ``False`` is authoritative negative evidence and
    always wins over another provider returning ``True``. In strict mode all
    providers must return ``True``; degraded mode tolerates provider errors but
    still rejects any explicit ``False``. Diagnostics are exposed for adapter
    telemetry and never alter the conservative decision rule.
    """

    def __init__(self, providers: Sequence[SignatureVerifier], *, require_all: bool = True) -> None:
        if not providers:
            raise ValueError("at least one signature provider is required")
        self.providers = tuple(providers)
        self.require_all = bool(require_all)
        self._local = threading.local()

    @property
    def last_diagnostics(self) -> list[dict[str, Any]]:
        return list(getattr(self._local, "diagnostics", []))

    def verify(self, evidence: object, key_id: str, signature: str) -> bool:
        diagnostics: list[dict[str, Any]] = []
        values: list[bool] = []
        for index, provider in enumerate(self.providers):
            try:
                result = bool(provider.verify(evidence, key_id, signature))
                values.append(result)
                diagnostics.append({"provider": index, "status": "valid" if result else "invalid"})
            except Exception as exc:
                diagnostics.append({"provider": index, "status": "error", "error": type(exc).__name__})
        self._local.diagnostics = diagnostics
        # Explicit negative evidence has precedence over stale positive data.
        if any(result is False for result in values):
            return False
        if not values:
            return False
        if self.require_all and len(values) != len(self.providers):
            return False
        return all(values) if self.require_all else any(values)
