from __future__ import annotations

import itertools
import json
import random
import sys
from pathlib import Path

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
ROOT = BUNDLE_ROOT if (BUNDLE_ROOT / "src").exists() else Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(BUNDLE_ROOT))

from assurance_lab import StandardPackRegistry, baseline_registry  # noqa: E402
from common import environment_record, mean_ci, write_json, write_jsonl  # noqa: E402


ATTRS = ("auth", "fresh", "scope")
RELATIONS = ("equivalent", "refines", "overlap", "informative", "conflicts")
SEEDS = (11, 23, 37, 41, 53)
CASES_PER_SEED = 1000


def relation_for(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    if conflict:
        return "conflicts"
    if source == target and scope_match:
        return "equivalent"
    if source < target and scope_match:
        return "refines"
    if source & target and scope_match:
        return "overlap"
    return "informative"


def scpc(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> tuple[str, dict[str, object] | None]:
    if conflict:
        attribute = sorted(source & target or source or target or set(ATTRS))[0]
        return "conflicts", {"kind": "negated_attribute", "attribute": attribute}
    if not scope_match:
        return "informative", {"kind": "scope_mismatch", "source_scope": "checkout", "target_scope": "recovery"}
    if source == target:
        return "equivalent", None
    if source < target:
        return "refines", {"kind": "additional_target_constraints", "attributes": sorted(target - source)}
    if source & target:
        return "overlap", {"kind": "missing_source_constraints", "attributes": sorted(source - target)}
    return "informative", {"kind": "no_composable_relation"}


def untyped_crosswalk(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    if conflict:
        return "equivalent" if source & target else "conflicts"
    return "equivalent" if source & target else "informative"


def keyword_match(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    if conflict:
        return "equivalent" if len(source & target) >= 1 else "conflicts"
    jaccard = len(source & target) / max(1, len(source | target))
    return "equivalent" if jaccard >= 0.75 else ("overlap" if jaccard > 0 else "informative")


def ontology_rule(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    if conflict:
        return "conflicts"
    if source == target:
        return "equivalent"
    if source <= target:
        return "refines"
    if source & target:
        return "equivalent"  # untyped ontology baseline collapses overlap
    return "informative"


def strict_exact(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    return "equivalent" if source == target and scope_match and not conflict else "informative"


def generate_case(rng: random.Random, index: int) -> dict[str, object]:
    source = {a for a in ATTRS if rng.random() < 0.55}
    if not source:
        source = {ATTRS[index % len(ATTRS)]}
    relation = rng.choice(RELATIONS)
    if relation == "equivalent":
        target = set(source)
        scope_match = True
        conflict = False
    elif relation == "refines":
        target = set(source)
        target.add(rng.choice([a for a in ATTRS if a not in target] or [ATTRS[0]]))
        scope_match = True
        conflict = False
    elif relation == "overlap":
        target = {rng.choice(tuple(source))}
        if target == source:
            target = set()
        scope_match = True
        conflict = False
    elif relation == "conflicts":
        target = set(source)
        scope_match = True
        conflict = True
    else:
        target = set(source)
        scope_match = False if rng.random() < 0.75 else True
        conflict = False
        if scope_match:
            target = {a for a in ATTRS if rng.random() < 0.2}
    return {
        "case_id": index,
        "source": sorted(source),
        "target": sorted(target),
        "scope_match": scope_match,
        "conflict": conflict,
        "gold": relation_for(source, target, scope_match, conflict),
    }


def finite_proof_audit() -> dict[str, object]:
    rows = []
    for source_bits in itertools.product((0, 1), repeat=len(ATTRS)):
        source = {a for a, bit in zip(ATTRS, source_bits) if bit}
        for target_bits in itertools.product((0, 1), repeat=len(ATTRS)):
            target = {a for a, bit in zip(ATTRS, target_bits) if bit}
            for scope_match in (False, True):
                for conflict in (False, True):
                    predicted, witness = scpc(source, target, scope_match, conflict)
                    gold = relation_for(source, target, scope_match, conflict)
                    rows.append({"source": sorted(source), "target": sorted(target), "scope_match": scope_match, "conflict": conflict, "gold": gold, "predicted": predicted, "witness": witness})
    false_equiv = sum(row["predicted"] == "equivalent" and row["gold"] != "equivalent" for row in rows)
    non_equiv = sum(row["gold"] != "equivalent" for row in rows)
    witness_complete = sum(row["gold"] != "equivalent" and row["witness"] is not None for row in rows)
    return {
        "schema": ATTRS,
        "rows": len(rows),
        "false_equivalence": false_equiv,
        "witness_complete": witness_complete / non_equiv,
        "soundness_pass": false_equiv == 0,
        "witness_pass": witness_complete == non_equiv,
    }


def main() -> int:
    out = Path(__file__).resolve().parent
    registry: StandardPackRegistry = baseline_registry()
    registry_snapshot = registry.snapshot().__dict__
    all_rows: list[dict[str, object]] = []
    methods = {"scpc": scpc, "untyped_crosswalk": untyped_crosswalk, "keyword_match": keyword_match, "ontology_rule": ontology_rule, "strict_exact": strict_exact}
    for seed in SEEDS:
        rng = random.Random(seed)
        for idx in range(CASES_PER_SEED):
            case = generate_case(rng, idx)
            source = set(case["source"])
            target = set(case["target"])
            for name, fn in methods.items():
                result = fn(source, target, bool(case["scope_match"]), bool(case["conflict"]))
                if name == "scpc":
                    predicted, witness = result
                else:
                    predicted, witness = result, None
                all_rows.append({"seed": seed, **case, "method": name, "predicted": predicted, "witness": witness})
    write_jsonl(out / "raw_cases.jsonl", all_rows)
    summary: dict[str, dict[str, object]] = {}
    for method in methods:
        rows = [row for row in all_rows if row["method"] == method]
        false_eq = sum(row["predicted"] == "equivalent" and row["gold"] != "equivalent" for row in rows)
        exact = sum(row["predicted"] == row["gold"] for row in rows)
        coverage = sum(row["predicted"] != "informative" for row in rows)
        non_equiv = sum(row["gold"] != "equivalent" for row in rows)
        witness = sum(row["gold"] != "equivalent" and row["witness"] is not None for row in rows)
        scoped = [row for row in rows if row["gold"] == "informative" and not row["scope_match"]]
        scope_safe = sum(row["predicted"] != "equivalent" for row in scoped)
        per_seed = []
        for seed in SEEDS:
            seed_rows = [row for row in rows if row["seed"] == seed]
            per_seed.append({"seed": seed, "accuracy": sum(r["predicted"] == r["gold"] for r in seed_rows) / len(seed_rows), "false_equivalence_rate": sum(r["predicted"] == "equivalent" and r["gold"] != "equivalent" for r in seed_rows) / len(seed_rows), "coverage": sum(r["predicted"] != "informative" for r in seed_rows) / len(seed_rows)})
        summary[method] = {
            "n": len(rows),
            "accuracy": exact / len(rows),
            "false_equivalence_rate": false_eq / len(rows),
            "coverage": coverage / len(rows),
            "witness_completeness": witness / non_equiv if non_equiv else 1.0,
            "scope_negative_control_rate": scope_safe / len(scoped) if scoped else 1.0,
            "per_seed": per_seed,
            "accuracy_ci_across_seeds": mean_ci([item["accuracy"] for item in per_seed]),
        }
    proof = finite_proof_audit()
    scpc_metrics = summary["scpc"]
    status = "PASS" if scpc_metrics["false_equivalence_rate"] == 0.0 and scpc_metrics["witness_completeness"] == 1.0 and scpc_metrics["coverage"] >= 0.70 and scpc_metrics["scope_negative_control_rate"] == 1.0 and proof["soundness_pass"] and proof["witness_pass"] else "FAIL"
    payload = {"candidate": "SCPC", "status": status, "claim_state": "BOUNDED_LOCAL_SEMANTIC_PASS" if status == "PASS" else "BOUNDED_LOCAL_SEMANTIC_FAIL", "environment": environment_record(), "registry_snapshot": registry_snapshot, "seeds": SEEDS, "cases_per_seed": CASES_PER_SEED, "methods": summary, "finite_proof_audit": proof, "docker": "NOT_TESTED", "enterprise_validity": "NOT_TESTED", "novelty": "NOT_PROVEN", "next_gate": "independent Docker reproduction and formal relation-proof audit"}
    write_json(out / "results.json", payload)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
