"""Rates and percentile estimates. The bootstrap seed is fixed so a rerun matches."""

from __future__ import annotations

import math
import random


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    weight = position - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def bootstrap_ci(successes: int, total: int, *, seed: int, draws: int = 10000) -> list[float] | None:
    """95% bootstrap interval of a binomial rate. Deterministic inputs stay [p, p]."""
    if total <= 0:
        return None
    if successes in {0, total}:
        rate = successes / total
        return [rate, rate]
    rng = random.Random(seed)
    population = [1] * successes + [0] * (total - successes)
    rates = []
    for _ in range(draws):
        hits = sum(population[rng.randrange(total)] for _ in range(total))
        rates.append(hits / total)
    rates.sort()
    low = rates[int(0.025 * (draws - 1))]
    high = rates[int(0.975 * (draws - 1))]
    return [low, high]


def rate_record(successes: int, total: int, *, seed: int) -> dict:
    rate = None if total == 0 else successes / total
    return {
        "k": successes,
        "n": total,
        "rate": rate,
        "ci95": bootstrap_ci(successes, total, seed=seed),
    }
