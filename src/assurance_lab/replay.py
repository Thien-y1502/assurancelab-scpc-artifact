from __future__ import annotations

import json
import math
import os
import ssl
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from urllib.parse import urlparse

from .trusted_time import TimeSample, TrustedTimeProvider, TrustedTimeUnavailable


class ReplayGuard:
    """Monotonic sequence/nonce guard with fail-closed durable state."""

    def __init__(self, state_path: str | Path | None = None) -> None:
        self.state_path = None if state_path is None else Path(state_path)
        self._last_sequence: dict[str, int] = {}
        self._seen: set[tuple[str, str]] = set()
        self._load()

    def observe(self, producer_id: str, nonce: str, sequence: int) -> bool:
        if not producer_id or not nonce or sequence < 0:
            return False
        with self._exclusive_lock():
            # Reload while holding the lock so separate processes cannot make
            # acceptance decisions from stale in-memory state.
            self._load()
            token = (producer_id, nonce)
            previous = self._last_sequence.get(producer_id, -1)
            if token in self._seen or sequence <= previous:
                return False
            self._seen.add(token)
            self._last_sequence[producer_id] = sequence
            self._save()
            return True

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        if self.state_path is None:
            yield
            return
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
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

    def _load(self) -> None:
        if self.state_path is None or not self.state_path.exists():
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("replay state must be an object")
            sequences = payload.get("last_sequence", {})
            seen = payload.get("seen", [])
            if not isinstance(sequences, dict) or not isinstance(seen, list):
                raise ValueError("replay state fields have invalid types")
            parsed_sequences = {str(key): int(value) for key, value in sequences.items()}
            parsed_seen = set()
            for item in seen:
                if not isinstance(item, list) or len(item) != 2:
                    raise ValueError("replay state token is malformed")
                parsed_seen.add((str(item[0]), str(item[1])))
            if any(value < -1 for value in parsed_sequences.values()):
                raise ValueError("replay state sequence is negative")
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError(f"replay state is invalid; refusing to continue: {exc}") from exc
        self._last_sequence = parsed_sequences
        self._seen = parsed_seen

    def _save(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "last_sequence": self._last_sequence,
            "seen": sorted([list(item) for item in self._seen]),
        }
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
        finally:
            temporary.unlink(missing_ok=True)


class HTTPReplayGuard:
    """Client for a shared replay coordinator at an HTTP(S) boundary.

    Coordinator failures return ``False`` and retain an error marker so the
    adapter can resolve evidence to UNKNOWN instead of accepting locally.
    HTTP is permitted only for explicit loopback fixtures; deployments should
    use HTTPS/mTLS.
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
            raise ValueError("replay coordinator endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme != "https" and (not allow_insecure_local or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}):
            raise ValueError("HTTPS is required except for an explicit loopback fixture")
        self.endpoint = endpoint
        self.identity = str(identity)
        self.timeout_seconds = float(timeout_seconds)
        self.ssl_context = ssl_context
        self.last_error: str | None = None
        self.last_reason: str | None = None
        self.fencing_token: dict[str, object] | None = None

    def set_fencing_token(self, owner_id: str, epoch: int) -> None:
        self.fencing_token = {"owner_id": str(owner_id), "epoch": int(epoch)}

    def observe(self, producer_id: str, nonce: str, sequence: int) -> bool:
        self.last_error = None
        self.last_reason = None
        payload = {"producer_id": str(producer_id), "nonce": str(nonce), "sequence": int(sequence)}
        if self.fencing_token is not None:
            payload["fencing_token"] = dict(self.fencing_token)
        body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint,
            data=body,
            headers={"Accept": "application/json", "Content-Type": "application/json", "X-Provider-Identity": self.identity},
            method="POST",
        )
        try:
            open_kwargs = {"timeout": self.timeout_seconds}
            if self.ssl_context is not None:
                open_kwargs["context"] = self.ssl_context
            with urllib.request.urlopen(request, **open_kwargs) as response:
                decoded = json.loads(response.read().decode("utf-8"))
            if not isinstance(decoded, dict) or not isinstance(decoded.get("accepted"), bool):
                raise ValueError("replay coordinator response must contain boolean accepted")
            if decoded.get("reason") is not None:
                self.last_reason = str(decoded["reason"])
            return bool(decoded["accepted"])
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self.last_error = type(exc).__name__
            return False


@dataclass(frozen=True)
class FencingToken:
    owner_id: str
    epoch: int
    expires_at: float


class LeaseStore:
    """Durable epoch lease used to fence stale replay coordinators."""

    def __init__(self, state_path: str | Path, *, ttl_seconds: float = 30.0, time_provider: TrustedTimeProvider | None = None) -> None:
        self.state_path = Path(state_path)
        self.ttl_seconds = float(ttl_seconds)
        self.time_provider = time_provider
        self.last_error: str | None = None
        self.last_reason: str | None = None
        self.last_time_sample: TimeSample | None = None

    def acquire(self, owner_id: str, *, now: float | None = None) -> FencingToken | None:
        if not owner_id.strip() or self.ttl_seconds <= 0:
            return None
        current_time = self._resolve_time(now)
        if current_time is None:
            return None
        with self._exclusive_lock():
            state = self._load()
            if state is not None and current_time < state["last_now"]:
                return None
            if state is not None and state["expires_at"] > current_time and state["owner_id"] != owner_id:
                return None
            epoch = 0 if state is None else state["epoch"] + 1
            token = FencingToken(str(owner_id), epoch, current_time + self.ttl_seconds)
            self._save(token, current_time)
            return token

    def renew(self, token: FencingToken, *, now: float | None = None) -> FencingToken | None:
        current_time = self._resolve_time(now)
        if current_time is None:
            return None
        with self._exclusive_lock():
            state = self._load()
            if state is None or current_time < state["last_now"] or state["owner_id"] != token.owner_id or state["epoch"] != token.epoch or state["expires_at"] <= current_time:
                return None
            renewed = FencingToken(token.owner_id, token.epoch, current_time + self.ttl_seconds)
            self._save(renewed, current_time)
            return renewed

    def validate(self, token: FencingToken, *, now: float | None = None) -> bool:
        current_time = self._resolve_time(now)
        if current_time is None:
            return False
        with self._exclusive_lock():
            state = self._load()
            if state is None or current_time < state["last_now"]:
                return False
            valid = bool(state["owner_id"] == token.owner_id and state["epoch"] == token.epoch and state["expires_at"] > current_time)
            self._save(FencingToken(str(state["owner_id"]), int(state["epoch"]), float(state["expires_at"])), current_time)
            return valid

    def _resolve_time(self, now: float | None) -> float | None:
        self.last_error = None
        self.last_reason = None
        self.last_time_sample = None
        try:
            if now is not None:
                current_time = float(now)
                if not math.isfinite(current_time):
                    raise ValueError("explicit lease time must be finite")
                return current_time
            if self.time_provider is None:
                return float(time.time())
            sample = self.time_provider.read()
            if not isinstance(sample, TimeSample):
                raise TypeError("time provider returned a non-TimeSample value")
            self.last_time_sample = sample
            return float(sample.timestamp)
        except Exception as exc:
            self.last_error = type(exc).__name__
            self.last_reason = str(exc)
            return None

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
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

    def _load(self) -> dict[str, object] | None:
        if not self.state_path.exists():
            return None
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not isinstance(payload.get("owner_id"), str) or not isinstance(payload.get("epoch"), int) or not isinstance(payload.get("expires_at"), (int, float)):
                raise ValueError("lease state schema is invalid")
            last_now = payload.get("last_now", float(payload["expires_at"]) - self.ttl_seconds)
            if not isinstance(last_now, (int, float)):
                raise ValueError("lease last_now is invalid")
            return {"owner_id": payload["owner_id"], "epoch": payload["epoch"], "expires_at": float(payload["expires_at"]), "last_now": float(last_now)}
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError(f"lease state is invalid; refusing to continue: {exc}") from exc

    def _save(self, token: FencingToken, last_now: float) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump({"owner_id": token.owner_id, "epoch": token.epoch, "expires_at": token.expires_at, "last_now": float(last_now)}, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
        finally:
            temporary.unlink(missing_ok=True)
