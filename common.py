"""Shared deterministic utilities for the three approved candidate runs."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import random
import subprocess
import sys
from pathlib import Path
from statistics import mean, stdev
from typing import Iterable, Sequence


def wilson(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if total <= 0:
        return (float("nan"), float("nan"))
    p = successes / total
    denom = 1.0 + z * z / total
    centre = (p + z * z / (2.0 * total)) / denom
    half = z * math.sqrt((p * (1.0 - p) + z * z / (4.0 * total)) / total) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def mean_ci(values: Sequence[float], z: float = 1.959963984540054) -> tuple[float, float, float]:
    if not values:
        return (float("nan"), float("nan"), float("nan"))
    m = mean(values)
    if len(values) < 2:
        return (m, m, m)
    half = z * stdev(values) / math.sqrt(len(values))
    return (m, m - half, m + half)


def bootstrap_mean_difference(
    left: Sequence[float],
    right: Sequence[float],
    *,
    seed: int,
    repeats: int = 2000,
) -> tuple[float, float, float]:
    n = min(len(left), len(right))
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    observed = mean(left[:n]) - mean(right[:n])
    rng = random.Random(seed)
    draws: list[float] = []
    for _ in range(repeats):
        indices = [rng.randrange(n) for _ in range(n)]
        draws.append(mean(left[i] - right[i] for i in indices))
    draws.sort()
    lo = draws[int(0.025 * (len(draws) - 1))]
    hi = draws[int(0.975 * (len(draws) - 1))]
    return (observed, lo, hi)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[object]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def environment_record() -> dict[str, object]:
    record: dict[str, object] = {
        "python": sys.version,
        "platform": platform.platform(),
        "implementation": platform.python_implementation(),
    }
    try:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if completed.returncode == 0 and completed.stdout.strip():
            record["docker"] = {"status": "AVAILABLE", "server": completed.stdout.strip()}
        else:
            record["docker"] = {"status": "NOT_AVAILABLE", "stderr": completed.stderr.strip()[-500:]}
    except Exception as exc:  # pragma: no cover - environment dependent
        record["docker"] = {"status": "NOT_AVAILABLE", "error": type(exc).__name__}
    return record
