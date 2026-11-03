from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .models import BusinessLinkRelation, BusinessObjective, ControlObjectiveLink, ControlRequirement, DependencyRequirement, ServiceContract


def compile_service_contract(spec: Mapping[str, Any]) -> ServiceContract:
    """Compile a user-owned contract document into typed semantics.

    The compiler accepts only explicit control assertions and business metrics;
    it does not map standards by keyword or invent missing targets.
    """
    required = ("service_id", "name", "controls", "objectives")
    missing = [key for key in required if key not in spec]
    if missing:
        raise ValueError(f"missing contract fields: {', '.join(missing)}")
    controls: list[ControlRequirement] = []
    for item in _sequence(spec["controls"], "controls"):
        controls.append(
            ControlRequirement(
                control_id=_string(item, "control_id"),
                title=_string(item, "title"),
                assertion=_string(item, "assertion"),
                expected_value=item.get("expected_value", True),
                critical=bool(item.get("critical", True)),
            )
        )
    objectives: list[BusinessObjective] = []
    for item in _sequence(spec["objectives"], "objectives"):
        objectives.append(
            BusinessObjective(
                objective_id=_string(item, "objective_id"),
                metric=_string(item, "metric"),
                target=float(item["target"]),
                comparator=_string(item, "comparator"),
                critical=bool(item.get("critical", True)),
            )
        )
    dependencies = tuple(str(value) for value in spec.get("dependencies", ()))
    dependency_requirements: list[DependencyRequirement] = []
    for item in _sequence(spec.get("dependency_requirements", ()), "dependency_requirements"):
        dependency_id = _string(item, "dependency_id")
        if dependency_id not in dependencies:
            raise ValueError(f"dependency requirement is not declared: {dependency_id}")
        dependency_requirements.append(
            DependencyRequirement(
                dependency_id=dependency_id,
                assertion=_string(item, "assertion"),
                expected_value=item.get("expected_value", True),
                critical=bool(item.get("critical", True)),
            )
        )
    links: list[ControlObjectiveLink] = []
    for item in _sequence(spec.get("control_objective_links", ()), "control_objective_links"):
        try:
            relation = BusinessLinkRelation(item.get("relation", BusinessLinkRelation.SUPPORTS.value))
        except ValueError as exc:
            raise ValueError("unsupported control-objective link relation") from exc
        links.append(
            ControlObjectiveLink(
                control_id=_string(item, "control_id"),
                objective_id=_string(item, "objective_id"),
                relation=relation,
                provenance=_string(item, "provenance"),
                scope_conditions=tuple(str(value) for value in item.get("scope_conditions", ())),
            )
        )
    return ServiceContract(
        service_id=_string(spec, "service_id"),
        name=_string(spec, "name"),
        controls=tuple(controls),
        objectives=tuple(objectives),
        dependencies=dependencies,
        dependency_requirements=tuple(dependency_requirements),
        metadata=dict(spec.get("metadata", {})),
        control_objective_links=tuple(links),
    )


def _sequence(value: Any, name: str) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of mappings")
    if not all(isinstance(item, Mapping) for item in value):
        raise TypeError(f"{name} must contain mappings")
    return value


def _string(mapping: Mapping[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value

