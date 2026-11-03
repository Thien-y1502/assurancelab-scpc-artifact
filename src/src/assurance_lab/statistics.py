from __future__ import annotations

import math


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if trials <= 0 or successes < 0 or successes > trials:
        raise ValueError("invalid binomial counts")
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def binary_summary(values: list[bool]) -> dict[str, float | list[float]]:
    if not values:
        raise ValueError("values cannot be empty")
    successes = sum(values)
    low, high = wilson_interval(successes, len(values))
    return {"n": float(len(values)), "rate": successes / len(values), "wilson_95": [low, high]}

