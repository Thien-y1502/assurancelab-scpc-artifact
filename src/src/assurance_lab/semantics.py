"""Finite decision-state semantics used by the AssuranceLab evaluator.

``NOT_TESTED`` is an envelope state selected when no evidence was supplied;
it is deliberately excluded from the non-empty control/dependency/objective
aggregation domain.  The remaining states form a total severity order.  The
explicit function makes the mathematical rule auditable and testable rather
than leaving precedence implicit in a chain of conditionals.
"""
from __future__ import annotations

from collections.abc import Iterable

from .models import DecisionState


AGGREGATION_ORDER: tuple[DecisionState, ...] = (
    DecisionState.PASS,
    DecisionState.UNKNOWN,
    DecisionState.FAIL,
    DecisionState.EXPIRED,
    DecisionState.CONFLICT,
)
_RANK = {state: rank for rank, state in enumerate(AGGREGATION_ORDER)}


def state_rank(state: DecisionState) -> int:
    """Return the severity rank used by non-empty decision aggregation."""
    if state is DecisionState.NOT_TESTED:
        raise ValueError("NOT_TESTED is an envelope state, not an aggregate member")
    return _RANK[state]


def aggregate_states(states: Iterable[DecisionState]) -> DecisionState:
    """Join non-empty control/dependency/objective states by severity.

    The empty join is ``PASS`` for compatibility with the engine's historical
    behavior; the public evaluator overrides this with ``NOT_TESTED`` when no
    evidence at all was supplied.  Callers cannot silently mix envelope and
    aggregate semantics: ``NOT_TESTED`` raises a ``ValueError``.
    """
    values = tuple(states)
    if any(state is DecisionState.NOT_TESTED for state in values):
        raise ValueError("NOT_TESTED is an envelope state, not an aggregate member")
    return max(values, key=state_rank, default=DecisionState.PASS)


def state_order() -> tuple[DecisionState, ...]:
    """Return the immutable public order for reproducible reports."""
    return AGGREGATION_ORDER
