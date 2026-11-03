"""Anytime-valid assurance certificates for sequential cyber-audit evidence.

The module deliberately implements a small, auditable kernel rather than a
general sequential-testing framework.  A leaf certificate consumes bounded
loss observations ``X_t in [0, 1]`` and maintains two non-negative e-processes:

* ``pass_wealth`` tests the unsafe null ``E[X_t | F_{t-1}] >= tau_unsafe``;
* ``fail_wealth`` tests the safe null ``E[X_t | F_{t-1}] <= tau_safe``.

The update factors are predictable-bet factors.  A crossing of
``1 / alpha`` is a decision boundary; otherwise the state remains UNKNOWN.
Evidence ids are immutable and duplicate ids are rejected, because counting
the same observation twice would invalidate the filtration used by the proof.

This is a bounded research implementation.  It does not claim enterprise
conformity, adversarial robustness, or validity when the declared assumptions
are violated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from math import isfinite
from typing import Iterable, Mapping, Sequence

from .models import DecisionState


class AnytimeStatus(str, Enum):
    """Observable state of a leaf certificate."""

    PASS = DecisionState.PASS.value
    FAIL = DecisionState.FAIL.value
    UNKNOWN = DecisionState.UNKNOWN.value
    CONFLICT = DecisionState.CONFLICT.value
    INVALID = "INVALID"


@dataclass(frozen=True)
class AnytimeObservation:
    """One bounded loss event in the audit filtration."""

    evidence_id: str
    loss: float
    event_time: datetime | None = None
    ingest_time: datetime | None = None
    source: str = "synthetic"
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id is required")
        if not isfinite(float(self.loss)) or not 0.0 <= float(self.loss) <= 1.0:
            raise ValueError("loss must be a finite number in [0, 1]")


@dataclass(frozen=True)
class AnytimeUpdate:
    """Trace returned after one observation is processed."""

    t: int
    evidence_id: str
    status: AnytimeStatus
    pass_wealth: float
    fail_wealth: float
    pass_boundary: float
    fail_boundary: float
    reason: str
    accepted: bool


@dataclass(frozen=True)
class AnytimeSnapshot:
    """Immutable audit snapshot suitable for a provenance record."""

    claim_id: str
    claim_version: str
    t: int
    status: AnytimeStatus
    pass_wealth: float
    fail_wealth: float
    observed_ids: tuple[str, ...]
    tau_unsafe: float
    tau_safe: float
    alpha_pass: float
    alpha_fail: float


class AnytimeCertificate:
    """Two-sided, abstaining anytime-valid certificate for one leaf claim.

    Under the unsafe null ``E[X_t | F_{t-1}] >= tau_unsafe``, the pass wealth is
    a non-negative supermartingale.  Under the safe null
    ``E[X_t | F_{t-1}] <= tau_safe``, the fail wealth has the corresponding
    property.  Ville's inequality therefore bounds each boundary crossing by
    its allocated alpha.  The implementation intentionally uses a fixed
    predictable lambda; callers may provide a deterministic schedule but may
    not depend on the current observation.
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
        enforce_monotone_time: bool = True,
    ) -> None:
        if not claim_id.strip() or not claim_version.strip():
            raise ValueError("claim_id and claim_version are required")
        if not (0.0 < tau_safe < tau_unsafe < 1.0):
            raise ValueError("require 0 < tau_safe < tau_unsafe < 1")
        for name, value in (("alpha_pass", alpha_pass), ("alpha_fail", alpha_fail)):
            if not (0.0 < float(value) < 1.0) or not isfinite(float(value)):
                raise ValueError(f"{name} must be finite and in (0, 1)")
        for name, value in (("lambda_pass", lambda_pass), ("lambda_fail", lambda_fail)):
            if not (0.0 <= float(value) <= 1.0) or not isfinite(float(value)):
                raise ValueError(f"{name} must be finite and in [0, 1]")
        self.claim_id = claim_id
        self.claim_version = claim_version
        self.tau_unsafe = float(tau_unsafe)
        self.tau_safe = float(tau_safe)
        self.alpha_pass = float(alpha_pass)
        self.alpha_fail = float(alpha_fail)
        self.lambda_pass = float(lambda_pass)
        self.lambda_fail = float(lambda_fail)
        self.enforce_monotone_time = bool(enforce_monotone_time)
        self.pass_wealth = 1.0
        self.fail_wealth = 1.0
        self._observed_ids: list[str] = []
        self._last_event_time: datetime | None = None
        self._status = AnytimeStatus.UNKNOWN
        self._trace: list[AnytimeUpdate] = []

    @property
    def pass_boundary(self) -> float:
        return 1.0 / self.alpha_pass

    @property
    def fail_boundary(self) -> float:
        return 1.0 / self.alpha_fail

    @property
    def status(self) -> AnytimeStatus:
        return self._status

    @property
    def trace(self) -> tuple[AnytimeUpdate, ...]:
        return tuple(self._trace)

    @property
    def observed_ids(self) -> tuple[str, ...]:
        return tuple(self._observed_ids)

    def _set_status(self) -> AnytimeStatus:
        pass_hit = self.pass_wealth >= self.pass_boundary
        fail_hit = self.fail_wealth >= self.fail_boundary
        if pass_hit and fail_hit:
            self._status = AnytimeStatus.CONFLICT
        elif pass_hit:
            self._status = AnytimeStatus.PASS
        elif fail_hit:
            self._status = AnytimeStatus.FAIL
        else:
            self._status = AnytimeStatus.UNKNOWN
        return self._status

    def update(self, observation: AnytimeObservation) -> AnytimeUpdate:
        """Consume exactly one observation, rejecting invalid reuse/order."""
        if observation.evidence_id in self._observed_ids:
            result = AnytimeUpdate(
                t=len(self._observed_ids),
                evidence_id=observation.evidence_id,
                status=AnytimeStatus.INVALID,
                pass_wealth=self.pass_wealth,
                fail_wealth=self.fail_wealth,
                pass_boundary=self.pass_boundary,
                fail_boundary=self.fail_boundary,
                reason="duplicate evidence_id; observation not counted",
                accepted=False,
            )
            self._trace.append(result)
            return result
        if (
            self.enforce_monotone_time
            and observation.event_time is not None
            and self._last_event_time is not None
            and observation.event_time < self._last_event_time
        ):
            result = AnytimeUpdate(
                t=len(self._observed_ids),
                evidence_id=observation.evidence_id,
                status=AnytimeStatus.INVALID,
                pass_wealth=self.pass_wealth,
                fail_wealth=self.fail_wealth,
                pass_boundary=self.pass_boundary,
                fail_boundary=self.fail_boundary,
                reason="event_time moved backwards; observation not counted",
                accepted=False,
            )
            self._trace.append(result)
            return result

        x = float(observation.loss)
        # Both factors are non-negative for lambda in [0, 1] and x/tau in [0, 1].
        self.pass_wealth *= 1.0 + self.lambda_pass * (self.tau_unsafe - x)
        self.fail_wealth *= 1.0 + self.lambda_fail * (x - self.tau_safe)
        self._observed_ids.append(observation.evidence_id)
        if observation.event_time is not None:
            self._last_event_time = observation.event_time
        status = self._set_status()
        result = AnytimeUpdate(
            t=len(self._observed_ids),
            evidence_id=observation.evidence_id,
            status=status,
            pass_wealth=self.pass_wealth,
            fail_wealth=self.fail_wealth,
            pass_boundary=self.pass_boundary,
            fail_boundary=self.fail_boundary,
            reason="accepted observation",
            accepted=True,
        )
        self._trace.append(result)
        return result

    def update_loss(
        self,
        loss: float,
        *,
        evidence_id: str,
        event_time: datetime | None = None,
        ingest_time: datetime | None = None,
        source: str = "synthetic",
        metadata: Mapping[str, object] | None = None,
    ) -> AnytimeUpdate:
        return self.update(
            AnytimeObservation(
                evidence_id=evidence_id,
                loss=loss,
                event_time=event_time,
                ingest_time=ingest_time,
                source=source,
                metadata={} if metadata is None else metadata,
            )
        )

    def snapshot(self) -> AnytimeSnapshot:
        return AnytimeSnapshot(
            claim_id=self.claim_id,
            claim_version=self.claim_version,
            t=len(self._observed_ids),
            status=self._status,
            pass_wealth=self.pass_wealth,
            fail_wealth=self.fail_wealth,
            observed_ids=tuple(self._observed_ids),
            tau_unsafe=self.tau_unsafe,
            tau_safe=self.tau_safe,
            alpha_pass=self.alpha_pass,
            alpha_fail=self.alpha_fail,
        )


@dataclass(frozen=True)
class BusinessLeaf:
    """Named leaf used in an immutable monotone business formula."""

    name: str
    certificate: AnytimeCertificate


@dataclass(frozen=True)
class BusinessFormulaResult:
    status: AnytimeStatus
    reason: str
    leaf_statuses: Mapping[str, AnytimeStatus]
    allocated_alpha: float
    global_alpha: float


class BusinessFormula:
    """Conservative ALL/ANY composition over leaf certificates.

    ``ALL`` requires every leaf to PASS; ``ANY`` requires at least one leaf to
    PASS.  The global false-PASS statement is a union-bound statement over the
    finite preregistered leaves, so independence is neither assumed nor used.
    ``ANY`` is intentionally marked conservative: its scientific meaning must
    be justified by the business contract before being used in a paper.
    """

    def __init__(self, *, mode: str, leaves: Sequence[BusinessLeaf], global_alpha: float):
        mode = mode.upper()
        if mode not in {"ALL", "ANY"}:
            raise ValueError("mode must be ALL or ANY")
        if not leaves:
            raise ValueError("at least one business leaf is required")
        if len({leaf.name for leaf in leaves}) != len(leaves):
            raise ValueError("business leaf names must be unique")
        if not (0.0 < global_alpha < 1.0):
            raise ValueError("global_alpha must be in (0, 1)")
        allocated = sum(leaf.certificate.alpha_pass for leaf in leaves)
        if allocated > global_alpha + 1e-15:
            raise ValueError("leaf alpha allocations exceed global_alpha")
        self.mode = mode
        self.leaves = tuple(leaves)
        self.global_alpha = float(global_alpha)

    @property
    def allocated_alpha(self) -> float:
        return sum(leaf.certificate.alpha_pass for leaf in self.leaves)

    def evaluate(self) -> BusinessFormulaResult:
        statuses = {leaf.name: leaf.certificate.status for leaf in self.leaves}
        if any(status is AnytimeStatus.CONFLICT or status is AnytimeStatus.INVALID for status in statuses.values()):
            return BusinessFormulaResult(AnytimeStatus.CONFLICT, "invalid or conflicting leaf", statuses, self.allocated_alpha, self.global_alpha)
        passes = [status is AnytimeStatus.PASS for status in statuses.values()]
        fails = [status is AnytimeStatus.FAIL for status in statuses.values()]
        decision = (all(passes) if self.mode == "ALL" else any(passes))
        if decision:
            return BusinessFormulaResult(AnytimeStatus.PASS, f"{self.mode} formula satisfied", statuses, self.allocated_alpha, self.global_alpha)
        if self.mode == "ALL" and any(fails):
            return BusinessFormulaResult(AnytimeStatus.FAIL, "required leaf failed", statuses, self.allocated_alpha, self.global_alpha)
        if self.mode == "ANY" and all(fails):
            return BusinessFormulaResult(AnytimeStatus.FAIL, "all alternative leaves failed", statuses, self.allocated_alpha, self.global_alpha)
        return BusinessFormulaResult(AnytimeStatus.UNKNOWN, f"{self.mode} formula unresolved", statuses, self.allocated_alpha, self.global_alpha)


def replay_losses(
    certificate: AnytimeCertificate,
    losses: Iterable[float],
    *,
    prefix: str = "e",
    start_time: datetime | None = None,
) -> AnytimeSnapshot:
    """Deterministically replay a loss stream for benchmark and audit tests."""
    time = start_time
    for index, loss in enumerate(losses, start=1):
        if time is None:
            event_time = None
        else:
            event_time = time
            time = time.replace(microsecond=time.microsecond) + timedelta(seconds=1)
        certificate.update_loss(loss, evidence_id=f"{prefix}-{index}", event_time=event_time)
    return certificate.snapshot()


__all__ = [
    "AnytimeCertificate",
    "AnytimeObservation",
    "AnytimeSnapshot",
    "AnytimeStatus",
    "AnytimeUpdate",
    "BusinessFormula",
    "BusinessFormulaResult",
    "BusinessLeaf",
    "replay_losses",
]
