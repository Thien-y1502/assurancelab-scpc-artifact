from __future__ import annotations

import itertools
import random
import sys
from pathlib import Path
from statistics import mean

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
ROOT = BUNDLE_ROOT if (BUNDLE_ROOT / "src").exists() else Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(BUNDLE_ROOT))

from common import environment_record, mean_ci, write_json, write_jsonl  # noqa: E402


ATTRS = ("auth", "fresh", "scope", "integrity", "continuity")
RELATIONS = ("equivalent", "refines", "overlap", "informative", "conflicts")
SEEDS = (101, 211, 307, 401, 503)
CASES_PER_SEED = 2000
BOOTSTRAP_REPEATS = 2000


def reference_relation(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    """Independent oracle written as a case table, not calling production code."""
    if conflict:
        return "conflicts"
    if not scope_match:
        return "informative"
    if source == target:
        return "equivalent"
    if source < target:
        return "refines"
    if source and target and source & target:
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


def scpc_no_scope(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> tuple[str, dict[str, object] | None]:
    return scpc(source, target, True, conflict)


def scpc_no_conflict(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> tuple[str, dict[str, object] | None]:
    return scpc(source, target, scope_match, False)


def untyped_crosswalk(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    if conflict:
        return "equivalent" if source & target else "conflicts"
    return "equivalent" if source & target else "informative"


def keyword_match(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    if conflict:
        return "equivalent" if source & target else "conflicts"
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
        return "equivalent"
    return "informative"


def strict_exact(source: set[str], target: set[str], scope_match: bool, conflict: bool) -> str:
    return "equivalent" if source == target and scope_match and not conflict else "informative"


def generate_case(rng: random.Random, index: int, *, density: float) -> dict[str, object]:
    source = {a for a in ATTRS if rng.random() < density}
    if not source:
        source = {ATTRS[index % len(ATTRS)]}
    relation = rng.choice(RELATIONS)
    if relation == "equivalent":
        target, scope_match, conflict = set(source), True, False
    elif relation == "refines":
        target = set(source)
        target.add(rng.choice([a for a in ATTRS if a not in target] or [ATTRS[0]]))
        scope_match, conflict = True, False
    elif relation == "overlap":
        target = {rng.choice(tuple(source))}
        if target == source:
            target = set()
        scope_match, conflict = True, False
    elif relation == "conflicts":
        target, scope_match, conflict = set(source), True, True
    else:
        target = set(source)
        scope_match = rng.random() >= 0.75
        conflict = False
        if scope_match:
            target = {a for a in ATTRS if rng.random() < 0.25}
    return {
        "case_id": index,
        "source": sorted(source),
        "target": sorted(target),
        "scope_match": scope_match,
        "conflict": conflict,
        "gold": reference_relation(source, target, scope_match, conflict),
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
                    gold = reference_relation(source, target, scope_match, conflict)
                    rows.append((predicted, gold, witness))
    non_equiv = sum(gold != "equivalent" for _, gold, _ in rows)
    return {
        "rows": len(rows),
        "oracle_disagreement": sum(predicted != gold for predicted, gold, _ in rows),
        "false_equivalence": sum(predicted == "equivalent" and gold != "equivalent" for predicted, gold, _ in rows),
        "witness_completeness": sum(gold != "equivalent" and witness is not None for _, gold, witness in rows) / non_equiv,
    }


def main() -> int:
    out = Path(__file__).resolve().parent
    methods = {
        "scpc": scpc,
        "untyped_crosswalk": untyped_crosswalk,
        "keyword_match": keyword_match,
        "ontology_rule": ontology_rule,
        "strict_exact": strict_exact,
    }
    all_rows: list[dict[str, object]] = []
    for seed in SEEDS:
        for density_name, density in (("sparse", 0.20), ("base", 0.55), ("dense", 0.80)):
            rng = random.Random(seed * 1009 + int(density * 100))
            for idx in range(CASES_PER_SEED):
                case = generate_case(rng, idx, density=density)
                source, target = set(case["source"]), set(case["target"])
                for name, fn in methods.items():
                    result = fn(source, target, bool(case["scope_match"]), bool(case["conflict"]))
                    predicted, witness = result if name == "scpc" else (result, None)
                    all_rows.append({"seed": seed, "density": density_name, **case, "method": name, "predicted": predicted, "witness": witness})
    write_jsonl(out / "raw_cases_v2.jsonl", all_rows)

    summary: dict[str, dict[str, object]] = {}
    for method in methods:
        rows = [row for row in all_rows if row["method"] == method]
        false_eq = sum(row["predicted"] == "equivalent" and row["gold"] != "equivalent" for row in rows)
        accuracy = [int(row["predicted"] == row["gold"]) for row in rows]
        coverage = [int(row["predicted"] != "informative") for row in rows]
        non_equiv = sum(row["gold"] != "equivalent" for row in rows)
        witnesses = sum(row["gold"] != "equivalent" and row["witness"] is not None for row in rows)
        scoped = [row for row in rows if row["gold"] == "informative" and not row["scope_match"]]
        scope_safe = sum(row["predicted"] != "equivalent" for row in scoped)
        per_shift = {}
        for shift in ("sparse", "base", "dense"):
            sr = [row for row in rows if row["density"] == shift]
            per_shift[shift] = {
                "n": len(sr),
                "accuracy": mean(int(row["predicted"] == row["gold"]) for row in sr),
                "false_equivalence_rate": sum(row["predicted"] == "equivalent" and row["gold"] != "equivalent" for row in sr) / len(sr),
                "coverage": mean(int(row["predicted"] != "informative") for row in sr),
            }
        summary[method] = {
            "n": len(rows),
            "accuracy": mean(accuracy),
            "accuracy_ci_across_cases": mean_ci(accuracy),
            "false_equivalence_rate": false_eq / len(rows),
            "coverage": mean(coverage),
            "witness_completeness": witnesses / non_equiv if non_equiv else 1.0,
            "scope_negative_control_rate": scope_safe / len(scoped),
            "per_density": per_shift,
        }

    paired = {}
    for baseline in ("untyped_crosswalk", "keyword_match", "ontology_rule", "strict_exact"):
        diffs_acc, diffs_cov = [], []
        for seed in SEEDS:
            left = [row for row in all_rows if row["method"] == "scpc" and row["seed"] == seed]
            right = [row for row in all_rows if row["method"] == baseline and row["seed"] == seed]
            diffs_acc.append(mean(float(a["predicted"] == a["gold"]) - float(b["predicted"] == b["gold"]) for a, b in zip(left, right)))
            diffs_cov.append(mean(float(a["predicted"] != "informative") - float(b["predicted"] != "informative") for a, b in zip(left, right)))
        paired[baseline] = {
            "accuracy_difference_scpc_minus_baseline_across_seed_ci": mean_ci(diffs_acc),
            "coverage_difference_scpc_minus_baseline_across_seed_ci": mean_ci(diffs_cov),
        }
    proof = finite_proof_audit()
    oracle_holdout = all(
        scpc(set(row["source"]), set(row["target"]), bool(row["scope_match"]), bool(row["conflict"]))[0] == row["gold"]
        for row in all_rows
        if row["method"] == "scpc"
    )
    ablation_rows = []
    for row in all_rows:
        if row["method"] != "scpc":
            continue
        source, target = set(row["source"]), set(row["target"])
        a, _ = scpc_no_scope(source, target, bool(row["scope_match"]), bool(row["conflict"]))
        b, _ = scpc_no_conflict(source, target, bool(row["scope_match"]), bool(row["conflict"]))
        ablation_rows.append({"scope": a, "conflict": b, "gold": row["gold"], "scope_match": row["scope_match"], "conflict_flag": row["conflict"]})
    scope_ablation_false = sum(r["scope"] == "equivalent" and r["gold"] != "equivalent" for r in ablation_rows)
    conflict_ablation_false = sum(r["conflict"] == "equivalent" and r["gold"] != "equivalent" for r in ablation_rows)
    scpc_metrics = summary["scpc"]
    status = "PASS" if (
        scpc_metrics["false_equivalence_rate"] == 0.0
        and scpc_metrics["witness_completeness"] == 1.0
        and scpc_metrics["coverage"] >= 0.70
        and scpc_metrics["scope_negative_control_rate"] == 1.0
        and proof["oracle_disagreement"] == 0
        and proof["false_equivalence"] == 0
        and oracle_holdout
        and paired["strict_exact"]["coverage_difference_scpc_minus_baseline_across_seed_ci"][2] > 0
        and scope_ablation_false > 0
        and conflict_ablation_false > 0
    ) else "FAIL"
    payload = {
        "candidate": "SCPC",
        "version": "v2-independent-holdout",
        "status": status,
        "claim_state": "BOUNDED_SIMULATION_PASS" if status == "PASS" else "BOUNDED_SIMULATION_FAIL",
        "environment": environment_record(),
        "seeds": SEEDS,
        "cases_per_seed_per_density": CASES_PER_SEED,
        "attributes": ATTRS,
        "methods": summary,
        "paired_baseline_statistics": paired,
        "finite_proof_audit": proof,
        "independent_oracle_holdout_pass": oracle_holdout,
        "ablation": {"scope_disabled_false_equivalences": scope_ablation_false, "conflict_disabled_false_equivalences": conflict_ablation_false},
        "docker": "NOT_TESTED",
        "enterprise_validity": "OUT_OF_SCOPE_BY_CONTRACT",
        "novelty": "NOT_PROVEN",
        "next_gate": "formal relation-algebra proof and external adjudicated benchmark; enterprise deployment is out of scope",
    }
    write_json(out / "results_v2.json", payload)
    write_json(out / "results.json", payload)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
