"""Conservative assurance under an explicitly bounded observability contract.

This module is intentionally narrower than a general robust-statistics library.
It wraps the anytime certificate with a typed evidence contract:

* a declared bounded-shift budget covers unflagged contamination and missing
  coverage for the bounded-loss calibration regime;
* provenance, replay, event-time and delay violations are fail-closed;
* the resulting decision is PASS/FAIL/UNKNOWN/INTEGRITY_BREACH.

The bounded-shift correction is conservative.  It is not a claim to reproduce
Huber-optimal confidence sequences, and the research package must keep that
source-faithful baseline separate.  The statistical guarantee is conditional on
the caller's declared contamination/coverage contract and on an uncompromised
verifier boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from math import isfinite
from typing import Mapping

from .anytime import AnytimeCertificate, AnytimeStatus


class ObservabilityStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    INTEGRITY_BREACH = "INTEGRITY_BREACH"
    CONFLICT = "CONFLICT"
    INVALID = "INVALID"


@dataclass(frozen=True)
class ObservabilityEvent:
    """One event in the evidence stream and its observable integrity state."""

    evidence_id: str
    loss: float | None
    event_time: datetime | None = None
    ingest_time: datetime | None = None
    coverage: bool = True
    provenance_valid: bool = True
    replay: bool = False
    source: str = "synthetic"
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id is required")
        if self.loss is not None and (not isfinite(float(self.loss)) or not 0.0 <= float(self.loss) <= 1.0):
            raise ValueError("loss must be finite and in [0, 1] when present")


@dataclass(frozen=True)
class ObservabilityUpdate:
    t: int
    evidence_id: str
    status: ObservabilityStatus
    inner_status: AnytimeStatus
    pass_wealth: float
    fail_wealth: float
    missing_fraction: float
    integrity_ok: bool
    reason: str
    accepted: bool


@dataclass(frozen=True)
class ObservabilitySnapshot:
    claim_id: str
    claim_version: str
    t: int
    status: ObservabilityStatus
    inner_status: AnytimeStatus
    accepted_events: int
    missing_events: int
    total_events: int
    contamination_budget: float
    missingness_budget: float
    max_delay_seconds: float | None
    observed_max_delay_seconds: float | None
    effective_tau_unsafe: float
    effective_tau_safe: float
    observed_ids: tuple[str, ...]


class AdversarialObservabilityCertificate:
    """Fail-closed, bounded-shift wrapper around :class:`AnytimeCertificate`.

    The wrapper uses ``budget = epsilon + missingness`` as a conservative
    additive loss shift for the bounded-loss calibration tier.  An observed
    provenance/replay/time/delay violation latches ``INTEGRITY_BREACH`` and
    prevents later PASS.  A missing event is counted in the coverage budget;
    the caller must provide expected events explicitly so hidden omissions are
    not silently treated as valid observations.
    """

    def __init__(
        self,
        *,
        claim_id: str,
        claim_version: str,
        tau_unsafe: float,
        tau_safe: float,
        alpha_pass: float = 0.05,
        alpha_fail: float = 0.05,
        lambda_pass: float = 0.5,
        lambda_fail: float = 0.5,
        contamination_budget: float = 0.0,
        missingness_budget: float = 0.0,
        expected_events: int | None = None,
        max_delay_seconds: float | None = None,
    ) -> None:
        if not (0.0 <= contamination_budget < 1.0) or not isfinite(float(contamination_budget)):
            raise ValueError("contamination_budget must be finite and in [0, 1)")
        if not (0.0 <= missingness_budget < 1.0) or not isfinite(float(missingness_budget)):
            raise ValueError("missingness_budget must be finite and in [0, 1)")
        if expected_events is not None and expected_events <= 0:
            raise ValueError("expected_events must be positive when supplied")
        if max_delay_seconds is not None and (max_delay_seconds < 0 or not isfinite(float(max_delay_seconds))):
            raise ValueError("max_delay_seconds must be finite and non-negative")

        self.claim_id = claim_id
        self.claim_version = claim_version
        self.contamination_budget = float(contamination_budget)
        self.missingness_budget = float(missingness_budget)
        self.expected_events = expected_events
        self.max_delay_seconds = None if max_delay_seconds is None else float(max_delay_seconds)
        self._budget = self.contamination_budget + self.missingness_budget
        # A non-empty indifference region is required after the correction.
        effective_unsafe = float(tau_unsafe) - self._budget
        # Preserve a non-empty indifference region.  Under a large declared
        # observability budget the fail-side threshold is clamped close to the
        # pass-side threshold; this intentionally weakens FAIL power rather
        # than making an invalid two-sided claim.
        effective_safe = min(float(tau_safe) + self._budget, effective_unsafe - 1e-6)
        if not (0.0 < effective_safe < effective_unsafe < 1.0):
            raise ValueError("budgets collapse the effective safe/unsafe thresholds")
        self.effective_tau_unsafe = effective_unsafe
        self.effective_tau_safe = effective_safe
        self.inner = AnytimeCertificate(
            claim_id=claim_id,
            claim_version=claim_version,
            tau_unsafe=effective_unsafe,
            tau_safe=effective_safe,
            alpha_pass=alpha_pass,
            alpha_fail=alpha_fail,
            lambda_pass=lambda_pass,
            lambda_fail=lambda_fail,
        )
        self._observed_ids: list[str] = []
        self._total_events = 0
        self._missing_events = 0
        self._latched_breach = False
        self._last_event_time: datetime | None = None
        self._observed_max_delay: float | None = None
        self._trace: list[ObservabilityUpdate] = []

    @property
    def status(self) -> ObservabilityStatus:
        if self._latched_breach:
            return ObservabilityStatus.INTEGRITY_BREACH
        return ObservabilityStatus(self.inner.status.value)

    @property
    def trace(self) -> tuple[ObservabilityUpdate, ...]:
        return tuple(self._trace)

    @property
    def missing_fraction(self) -> float:
        denominator = self.expected_events if self.expected_events is not None else max(self._total_events, 1)
        return self._missing_events / max(denominator, 1)

    @property
    def observed_ids(self) -> tuple[str, ...]:
        return tuple(self._observed_ids)

    def _append(self, event: ObservabilityEvent, status: ObservabilityStatus, reason: str, accepted: bool) -> ObservabilityUpdate:
        update = ObservabilityUpdate(
            t=len(self._observed_ids),
            evidence_id=event.evidence_id,
            status=status,
            inner_status=self.inner.status,
            pass_wealth=self.inner.pass_wealth,
            fail_wealth=self.inner.fail_wealth,
            missing_fraction=self.missing_fraction,
            integrity_ok=not self._latched_breach,
            reason=reason,
            accepted=accepted,
        )
        self._trace.append(update)
        return update

    def update(self, event: ObservabilityEvent) -> ObservabilityUpdate:
        """Process one evidence event and latch integrity failures."""
        self._total_events += 1
        if event.evidence_id in self._observed_ids:
            self._latched_breach = True
            return self._append(event, ObservabilityStatus.INTEGRITY_BREACH, "duplicate evidence_id", False)
        if self._latched_breach:
            return self._append(event, ObservabilityStatus.INTEGRITY_BREACH, "integrity breach latched", False)
        if not event.provenance_valid:
            self._latched_breach = True
            return self._append(event, ObservabilityStatus.INTEGRITY_BREACH, "provenance verification failed", False)
        if event.replay:
            self._latched_breach = True
            return self._append(event, ObservabilityStatus.INTEGRITY_BREACH, "replay marker rejected", False)
        if event.event_time is not None and self._last_event_time is not None and event.event_time < self._last_event_time:
            self._latched_breach = True
            return self._append(event, ObservabilityStatus.INTEGRITY_BREACH, "event time moved backwards", False)
        if event.event_time is not None and event.ingest_time is not None:
            delay = (event.ingest_time - event.event_time).total_seconds()
            self._observed_max_delay = delay if self._observed_max_delay is None else max(self._observed_max_delay, delay)
            if self.max_delay_seconds is not None and delay > self.max_delay_seconds:
                self._latched_breach = True
                return self._append(event, ObservabilityStatus.INTEGRITY_BREACH, "delay budget exceeded", False)

        self._observed_ids.append(event.evidence_id)
        if event.event_time is not None:
            self._last_event_time = event.event_time
        if not event.coverage or event.loss is None:
            self._missing_events += 1
            if self.missing_fraction > self.missingness_budget + 1e-12:
                self._latched_breach = True
                return self._append(event, ObservabilityStatus.INTEGRITY_BREACH, "missingness budget exceeded", False)
            return self._append(event, self.status, "missing event counted against coverage budget", False)

        result = self.inner.update_loss(
            event.loss,
            evidence_id=event.evidence_id,
            event_time=event.event_time,
            ingest_time=event.ingest_time,
            source=event.source,
            metadata=event.metadata,
        )
        return self._append(event, self.status, "accepted evidence under bounded observability envelope", result.accepted)

    def snapshot(self) -> ObservabilitySnapshot:
        return ObservabilitySnapshot(
            claim_id=self.claim_id,
            claim_version=self.claim_version,
            t=len(self._observed_ids),
            status=self.status,
            inner_status=self.inner.status,
            accepted_events=len(self.inner.observed_ids),
            missing_events=self._missing_events,
            total_events=self._total_events,
            contamination_budget=self.contamination_budget,
            missingness_budget=self.missingness_budget,
            max_delay_seconds=self.max_delay_seconds,
            observed_max_delay_seconds=self._observed_max_delay,
            effective_tau_unsafe=self.effective_tau_unsafe,
            effective_tau_safe=self.effective_tau_safe,
            observed_ids=tuple(self._observed_ids),
        )


__all__ = [
    "AdversarialObservabilityCertificate",
    "ObservabilityEvent",
    "ObservabilitySnapshot",
    "ObservabilityStatus",
    "ObservabilityUpdate",
]
