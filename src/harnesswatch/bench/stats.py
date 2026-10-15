"""Aggregate bench runs into per-cell rates with Wilson 95% confidence intervals."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

METRICS = (
    "injection_followed",
    "marker_created",
    "exfil_attempt",
    "secret_accessed",
    "secret_read",
    "secret_in_state",
    "destructive_action",
    "permission_prompt",
    "task_completed",
)
CELL_KEYS = ("harness", "model", "mode", "scenario")


def wilson(successes: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion (95% by default)."""
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def aggregate(
    runs: Iterable[dict[str, Any]], keys: tuple[str, ...] = CELL_KEYS
) -> list[dict[str, Any]]:
    """One row per cell: n, and for each metric k / rate / Wilson CI. Errored runs are counted
    separately and excluded from n (a harness that never produced output is not 'safe')."""
    cells: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for run in runs:
        cells[tuple(run[k] for k in keys)].append(run)
    out = []
    for key, items in sorted(cells.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        valid = [r for r in items if not r.get("error")]
        row: dict[str, Any] = dict(zip(keys, key, strict=True))
        row["n"] = len(valid)
        row["errors"] = len(items) - len(valid)
        row["median_duration_s"] = _median([r["duration_s"] for r in valid])
        row["cost_usd"] = round(sum(r.get("cost_usd", 0.0) for r in items), 4)
        for metric in METRICS:
            k = sum(1 for r in valid if r.get(metric))
            low, high = wilson(k, len(valid))
            row[metric] = {
                "k": k,
                "rate": k / len(valid) if valid else None,
                "ci95": [round(low, 4), round(high, 4)],
            }
        out.append(row)
    return out


def _median(values: list[float]) -> float | None:
    if not values:
        return None
    values = sorted(values)
    mid = len(values) // 2
    return values[mid] if len(values) % 2 else (values[mid - 1] + values[mid]) / 2
