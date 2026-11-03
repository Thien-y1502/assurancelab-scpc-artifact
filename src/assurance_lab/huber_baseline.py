"""Source-faithful bounded-data baseline from Wang & Ramdas (AISTATS 2023).

The implementation follows Theorem 6, Equation (42) of *Huber-Robust
Confidence Sequences*: for ``Q`` in a total-variation epsilon ball around ``P``
and bounded observations, the factor

    1 + lambda * (X - m) - epsilon * abs(lambda)

is a nonnegative supermartingale factor when ``abs(lambda) <= 1/(1+epsilon)``.

This is a baseline, not the proposed AOCCA method.  The theorem assumes an iid
contamination model and does not cover missingness, strategic coverage, or a
compromised verifier; those cells are marked diagnostic-only by the benchmark.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Iterable

from .anytime import AnytimeStatus


@dataclass(frozen=True)
class HuberUpdate:
    t: int
    evidence_id: str
    status: AnytimeStatus
    pass_wealth: float
    fail_wealth: float
    pass_factor: float
    fail_factor: float
    accepted: bool
    reason: str


class HuberRobustBettingCertificate:
    """Two-sided bounded-data implementation of Huber Theorem 6.

    ``lambda_pass`` should be negative to test the unsafe null
    ``mu(P) >= tau_unsafe``; ``lambda_fail`` should be positive to test the
    safe null ``mu(P) <= tau_safe``.  The class keeps the factor exact rather
    than replacing it with AOCCA's additive threshold shift.
    """

    SOURCE = "Wang-Ramdas-2023-Theorem-6-Equation-42"

    def __init__(
        self,
        *,
        claim_id: str,
        claim_version: str,
        tau_unsafe: float,
        tau_safe: float,
        epsilon: float,
        alpha_pass: float = 0.05,
        alpha_fail: float = 0.05,
        lambda_pass: float = -0.5,
        lambda_fail: float = 0.5,
    ) -> None:
        if not (0.0 <= float(epsilon) < 1.0) or not isfinite(float(epsilon)):
            raise ValueError("epsilon must be finite and in [0, 1)")
        if not (0.0 < float(tau_safe) < float(tau_unsafe) < 1.0):
            raise ValueError("require 0 < tau_safe < tau_unsafe < 1")
        for name, value in (("alpha_pass", alpha_pass), ("alpha_fail", alpha_fail)):
            if not (0.0 < float(value) < 1.0) or not isfinite(float(value)):
                raise ValueError(f"{name} must be finite and in (0, 1)")
        limit = 1.0 / (1.0 + float(epsilon))
        if abs(float(lambda_pass)) > limit or abs(float(lambda_fail)) > limit:
            raise ValueError("lambda violates Huber Theorem 6 bound")
        if lambda_pass >= 0 or lambda_fail <= 0:
            raise ValueError("lambda_pass must be negative and lambda_fail positive")
        self.claim_id = claim_id
        self.claim_version = claim_version
        self.tau_unsafe = float(tau_unsafe)
        self.tau_safe = float(tau_safe)
        self.epsilon = float(epsilon)
        self.alpha_pass = float(alpha_pass)
        self.alpha_fail = float(alpha_fail)
        self.lambda_pass = float(lambda_pass)
        self.lambda_fail = float(lambda_fail)
        self.pass_wealth = 1.0
        self.fail_wealth = 1.0
        self._observed_ids: list[str] = []
        self._status = AnytimeStatus.UNKNOWN
        self._trace: list[HuberUpdate] = []

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
    def trace(self) -> tuple[HuberUpdate, ...]:
        return tuple(self._trace)

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

    def update(self, *, evidence_id: str, loss: float) -> HuberUpdate:
        if evidence_id in self._observed_ids:
            result = HuberUpdate(
                t=len(self._observed_ids),
                evidence_id=evidence_id,
                status=AnytimeStatus.INVALID,
                pass_wealth=self.pass_wealth,
                fail_wealth=self.fail_wealth,
                pass_factor=1.0,
                fail_factor=1.0,
                accepted=False,
                reason="duplicate evidence_id; observation not counted",
            )
            self._trace.append(result)
            return result
        x = float(loss)
        if not isfinite(x) or not 0.0 <= x <= 1.0:
            raise ValueError("loss must be finite and in [0, 1]")
        pass_factor = 1.0 + self.lambda_pass * (x - self.tau_unsafe) - self.epsilon * abs(self.lambda_pass)
        fail_factor = 1.0 + self.lambda_fail * (x - self.tau_safe) - self.epsilon * abs(self.lambda_fail)
        if pass_factor < -1e-12 or fail_factor < -1e-12:
            raise ArithmeticError("Huber factor became negative; theorem contract violated")
        self.pass_wealth *= max(pass_factor, 0.0)
        self.fail_wealth *= max(fail_factor, 0.0)
        self._observed_ids.append(evidence_id)
        status = self._set_status()
        result = HuberUpdate(
            t=len(self._observed_ids),
            evidence_id=evidence_id,
            status=status,
            pass_wealth=self.pass_wealth,
            fail_wealth=self.fail_wealth,
            pass_factor=pass_factor,
            fail_factor=fail_factor,
            accepted=True,
            reason="accepted Huber Theorem 6 factor",
        )
        self._trace.append(result)
        return result


def replay_huber(
    certificate: HuberRobustBettingCertificate,
    losses: Iterable[float],
    *,
    prefix: str = "h",
) -> AnytimeStatus:
    for i, loss in enumerate(losses, start=1):
        certificate.update(evidence_id=f"{prefix}-{i}", loss=loss)
    return certificate.status


__all__ = ["HuberRobustBettingCertificate", "HuberUpdate", "replay_huber"]
