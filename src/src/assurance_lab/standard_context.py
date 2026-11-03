from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Iterable, Mapping

from .engine import AssuranceEngine
from .models import AuditDecision, Evidence, ServiceContract, DecisionState
from .standard_registry import StandardPackRegistry
from .standards import StandardStatus


@dataclass(frozen=True)
class StandardContextAdmission:
    accepted: bool
    versions: tuple[str, ...]
    reasons: tuple[str, ...]


def admit_standard_context(
    registry: StandardPackRegistry,
    versions: Iterable[str],
    *,
    applicability_context: Mapping[str, bool] | None = None,
) -> StandardContextAdmission:
    """Admit registered packs and fail closed on unproven applicability.

    ``StandardPack.applicability_conditions`` is intentionally descriptive;
    the caller must provide an explicit boolean admission for every selected
    pack that declares such conditions.  This prevents a published standard
    from being treated as applicable merely because it is in the registry.
    """
    normalized = tuple(dict.fromkeys(str(version) for version in versions))
    reasons: list[str] = []
    context = dict(applicability_context or {})
    if not normalized:
        reasons.append("standard_context:missing")
    for version in normalized:
        try:
            pack = registry.get(version)
        except KeyError:
            reasons.append(f"standard_context:unknown={version}")
            continue
        if pack.status != StandardStatus.PUBLISHED:
            reasons.append(f"standard_context:not_published={version}:{pack.status.value}")
        if pack.applicability_conditions:
            if version not in context:
                reasons.append(f"standard_context:applicability_unproven={version}")
            elif type(context[version]) is not bool:
                reasons.append(f"standard_context:applicability_invalid={version}")
            elif not context[version]:
                reasons.append(f"standard_context:not_applicable={version}")
    return StandardContextAdmission(not reasons, normalized, tuple(reasons))


def evaluate_with_standard_context(
    engine: AssuranceEngine,
    registry: StandardPackRegistry,
    contract: ServiceContract,
    evidence: Iterable[Evidence],
    *,
    now: datetime,
    standard_pack_versions: Iterable[str],
    applicability_context: Mapping[str, bool] | None = None,
) -> AuditDecision:
    """Evaluate a contract while fail-closing on an inadmissible standard context."""
    versions = tuple(dict.fromkeys(str(version) for version in standard_pack_versions))
    admission = admit_standard_context(registry, versions, applicability_context=applicability_context)
    decision = engine.evaluate(contract, evidence, now=now, standard_pack_versions=versions)
    if admission.accepted:
        return decision
    reasons = decision.reasons + admission.reasons
    return replace(decision, state=DecisionState.UNKNOWN, reasons=reasons)
