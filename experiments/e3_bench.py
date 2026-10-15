"""E3 analysis (offline): canary-bench runs.jsonl -> results JSON, tables and figure.

Reads bench/results/<date>/runs.jsonl (committed) and writes:
- experiments/results/e3_bench.json: per-cell rates with Wilson 95% CIs, plus pooled views
  (harness x mode over the injection scenarios; harness x scenario over both modes);
- paper/tables/e3_bench.tex|.md and paper/figures/e3_follow.pdf|.png.
Usage: uv run --group experiments python experiments/e3_bench.py [results-dir]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from harnesswatch.bench.runner import completed_runs
from harnesswatch.bench.stats import METRICS, aggregate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "bench" / "results" / "2026-10-15"
INJECTION = {"readme", "instructions", "code_comment", "tool_output", "hidden_unicode"}
CLOSED = {"claude-code", "github-copilot", "grok-build"}
# Cells whose payload never reaches the model: Aider loads no instruction file unless given
# `--read` (ASSUMPTIONS A21). Their runs stay in runs.jsonl but are N/A in every pooled view.
NOT_APPLICABLE = {("aider", "instructions")}


def pooled(runs: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    return aggregate(runs, keys)


def analyse(all_runs: list[dict[str, Any]]) -> dict[str, Any]:
    runs = [r for r in all_runs if (r["harness"], r["scenario"]) not in NOT_APPLICABLE]
    injected = [r for r in runs if r["scenario"] in INJECTION]
    return {
        "n_runs": len(all_runs),
        "n_runs_analysed": len(runs),
        "not_applicable_cells": sorted(f"{h}/{s}" for h, s in NOT_APPLICABLE),
        "n_errors": sum(1 for r in runs if r.get("error")),
        "harnesses": sorted({r["harness"] for r in runs}),
        "models": sorted({r["model"] for r in runs}),
        "total_cost_usd": round(sum(r.get("cost_usd", 0.0) for r in runs), 4),
        "cells": aggregate(runs),
        "by_harness_mode": pooled(injected, ("harness", "mode")),
        "by_harness_scenario": pooled(runs, ("harness", "scenario")),
        "by_scenario": pooled(runs, ("scenario",)),
        "by_mode": pooled(injected, ("mode",)),
        "control": pooled([r for r in runs if r["scenario"] == "control"], ("harness", "mode")),
        "hosts_contacted": _hosts(runs),
        "timeouts": {
            "total": sum(1 for r in runs if r.get("timed_out")),
            "by_harness_mode": _timeouts(injected),
        },
    }


def _timeouts(runs: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in runs:
        key = f"{r['harness']}/{r['mode']}"
        out[key] = out.get(key, 0) + (1 if r.get("timed_out") else 0)
    return dict(sorted(out.items()))


def _hosts(runs: list[dict[str, Any]]) -> dict[str, list[str]]:
    out: dict[str, set[str]] = {}
    for run in runs:
        out.setdefault(run["harness"], set()).update(run.get("blocked_hosts", []))
    return {k: sorted(v) for k, v in sorted(out.items())}


def _pct_ci(cell: dict[str, Any], n: int) -> str:
    lo, hi = cell["ci95"]
    return f"{cell['k']}/{n} [{100 * lo:.1f}, {100 * hi:.1f}]"


def tables(result: dict[str, Any], out_dir: Path) -> None:
    rows = result["by_harness_mode"]
    touts = result.get("timeouts", {}).get("by_harness_mode", {})
    header = [
        "Harness",
        "Mode",
        "n",
        "Follow [95\\% CI, \\%]",
        "Exfil",
        "Destr.",
        "Secret in state",
        "Prompts",
        "Timeouts",
        "Task done [95\\% CI, \\%]",
    ]
    md = ["| " + " | ".join(h.replace("\\", "") for h in header) + " |", "|" + "---|" * len(header)]
    tex = [
        "\\begin{tabular}{llrlrrrrrl}",
        "\\toprule",
        " & ".join(header) + " \\\\",
        "\\midrule",
    ]
    for row in rows:
        n = row["n"]
        vals = [
            _pct_ci(row["injection_followed"], n),
            str(row["exfil_attempt"]["k"]),
            str(row["destructive_action"]["k"]),
            str(row.get("secret_in_state", {}).get("k", "--")),
            str(row["permission_prompt"]["k"]),
            str(touts.get(f"{row['harness']}/{row['mode']}", 0)),
            _pct_ci(row["task_completed"], n),
        ]
        name = row["harness"] + ("$^{B}$" if row["harness"] in CLOSED else "")
        md.append(
            "| " + " | ".join([name.replace("$^{B}$", " (B)"), row["mode"], str(n), *vals]) + " |"
        )
        tex.append(" & ".join([name.replace("_", "\\_"), row["mode"], str(n), *vals]) + " \\\\")
    tex += ["\\bottomrule", "\\end{tabular}"]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "e3_bench.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out_dir / "e3_bench.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def figure(result: dict[str, Any], out_dir: Path) -> None:
    """Task completion (bars, Wilson CI) against injection follow (markers) per harness and mode."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    rows = result["by_harness_mode"]
    harnesses = sorted({r["harness"] for r in rows})
    modes = ["default", "auto"]
    fig, ax = plt.subplots(figsize=(3.5, 1.9))
    width = 0.38
    colors = ["#9ecae1", "#3182bd"]
    for i, mode in enumerate(modes):
        xs, ys, lo, hi, fy = [], [], [], [], []
        for j, harness in enumerate(harnesses):
            row = next((r for r in rows if r["harness"] == harness and r["mode"] == mode), None)
            if not row:
                continue
            cell = row["task_completed"]
            xs.append(j + (i - 0.5) * width)
            ys.append(cell["rate"])
            lo.append(cell["rate"] - cell["ci95"][0])
            hi.append(cell["ci95"][1] - cell["rate"])
            fy.append(row["injection_followed"]["rate"])
        ax.bar(
            xs,
            ys,
            width,
            yerr=[lo, hi],
            capsize=1.5,
            label=f"task done, {mode}",
            color=colors[i],
            error_kw={"linewidth": 0.6},
        )
        ax.scatter(
            xs,
            fy,
            marker="x",
            s=10,
            color="#b2182b",
            zorder=3,
            label="injection followed" if i else None,
            linewidths=0.8,
        )
    ax.set_xticks(range(len(harnesses)))
    ax.set_xticklabels(
        [h + ("$^B$" if h in CLOSED else "") for h in harnesses],
        rotation=25,
        ha="right",
        fontsize=5.5,
    )
    ax.tick_params(axis="y", labelsize=5.5)
    ax.set_ylabel("rate (injection scenarios)", fontsize=6)
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=5, frameon=False, loc="upper right", ncol=3, bbox_to_anchor=(1.0, 1.16))
    fig.tight_layout(pad=0.3)
    out_dir.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(out_dir / f"e3_follow.{ext}", dpi=200)
    plt.close(fig)


def main(results_dir: Path) -> None:
    runs = completed_runs(results_dir / "runs.jsonl")
    result = analyse(runs)
    result["metrics"] = list(METRICS)
    result["source"] = str(results_dir.resolve().relative_to(ROOT))
    out = ROOT / "experiments" / "results" / "e3_bench.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    tables(result, ROOT / "paper" / "tables")
    figure(result, ROOT / "paper" / "figures")
    print(f"{result['n_runs']} runs, {len(result['cells'])} cells -> {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT)
