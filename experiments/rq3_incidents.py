"""RQ3 analysis (offline): incident timeline, root-cause classes and patch latency, 2025-2026.

Counting rule (ASSUMPTIONS A11): an incident is counted only if the research agent marked it
verified=yes AND the independent NVD/GHSA re-check (evidence/verification/incidents_check.json)
confirmed every listed ID; ID-less incidents count on their primary source alone.
Classes come from taxonomy/incident-classification.csv (Phase 2 ordered procedure) where present,
else from the incident row itself (Phase-1b additions).

Writes experiments/results/rq3_incidents.json, paper/tables/rq3_*.tex|.md, paper/figures/rq3_*.pdf|.png
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
import figstyle

ROOT = Path(__file__).resolve().parents[1]
COUNTED_STATUS = {"confirmed", "no-id (primary-source only)"}
TIERS: dict[str, str] = {}


def _tier(harness: str) -> str:
    if not TIERS:
        import yaml

        for path in (ROOT / "rules" / "harness_profiles").glob("*.yaml"):
            if path.name.startswith("_"):
                continue
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            TIERS[data["id"]] = str(data.get("tier") or "?")
    first = harness.split("|")[0].strip()
    return TIERS.get(first, "ecosystem")


def load() -> list[dict[str, Any]]:
    incidents = list(csv.DictReader((ROOT / "evidence" / "incidents.csv").open(encoding="utf-8")))
    classes = {
        r["id"]: r
        for r in csv.DictReader(
            (ROOT / "taxonomy" / "incident-classification.csv").open(encoding="utf-8")
        )
    }
    checks = {
        r["id"]: r
        for r in json.loads(
            (ROOT / "evidence" / "verification" / "incidents_check.json").read_text()
        )
    }
    rows = []
    for inc in incidents:
        cls = classes.get(inc["id"], {})
        check = checks.get(inc["id"], {})
        rows.append(
            {
                **inc,
                "taxonomy_class": cls.get("taxonomy_class") or inc["taxonomy_class"],
                "root_cause_class": cls.get("root_cause_class") or inc["root_cause_class"],
                "kind": cls.get("kind") or inc["kind"],
                "check_status": check.get("status", "unchecked"),
                "counted": inc["verified"] == "yes"
                and check.get("status") in COUNTED_STATUS
                and inc["date_disclosed"][:4] in {"2025", "2026"},
            }
        )
    return rows


def latency(row: dict[str, Any]) -> int | None:
    try:
        disclosed = date.fromisoformat(row["date_disclosed"][:10])
        fixed = date.fromisoformat(row["fix_date"][:10])
    except ValueError:
        return None
    return (fixed - disclosed).days


def _quarter_end(iso: str) -> str:
    """Last day of the calendar quarter that contains the ISO date."""
    year, month = int(iso[:4]), int(iso[5:7])
    end_month = ((month - 1) // 3 + 1) * 3
    return f"{year}-{end_month:02d}-{31 if end_month in (3, 12) else 30}"


def analyse(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counted = [r for r in rows if r["counted"]]
    latest = max(r["date_disclosed"][:10] for r in counted)
    quarters = Counter(
        f"{r['date_disclosed'][:4]}-Q{(int(r['date_disclosed'][5:7]) - 1) // 3 + 1}"
        for r in counted
    )
    by_harness = Counter(r["harness"].split("|")[0].strip() for r in counted)
    latencies = [x for r in counted if (x := latency(r)) is not None]
    rc_by_class: dict[str, Counter[str]] = defaultdict(Counter)
    for r in counted:
        rc_by_class[r["taxonomy_class"]][r["root_cause_class"]] += 1
    tiers = Counter(_tier(r["harness"]) for r in counted)
    return {
        "counting_rule": "verified=yes AND independent ID check confirmed (or ID-less with primary source); disclosed 2025-2026 (A11)",
        "total_rows": len(rows),
        "counted": len(counted),
        "excluded": {
            "not_verified": sum(1 for r in rows if r["verified"] != "yes"),
            "id_check_failed": sum(
                1
                for r in rows
                if r["verified"] == "yes" and r["check_status"] not in COUNTED_STATUS
            ),
            "outside_2025_2026": sum(
                1 for r in rows if r["date_disclosed"][:4] not in {"2025", "2026"}
            ),
        },
        "by_year": dict(sorted(Counter(r["date_disclosed"][:4] for r in counted).items())),
        "by_quarter": dict(sorted(quarters.items())),
        "latest_disclosure": latest,
        "partial_last_quarter": latest < _quarter_end(latest),
        "by_kind": dict(Counter(r["kind"] for r in counted).most_common()),
        "by_taxonomy_class": dict(Counter(r["taxonomy_class"] for r in counted).most_common()),
        "by_root_cause": dict(Counter(r["root_cause_class"] for r in counted).most_common()),
        "by_tier": dict(tiers.most_common()),
        "top_harnesses": dict(by_harness.most_common(15)),
        "with_cve": sum(1 for r in counted if r["cve"].strip()),
        "with_ghsa": sum(1 for r in counted if r["ghsa"].strip()),
        "root_cause_by_class": {k: dict(v) for k, v in sorted(rc_by_class.items())},
        "patch_latency_days": {
            "n": len(latencies),
            "median": statistics.median(latencies) if latencies else None,
            "fixed_before_disclosure": sum(1 for x in latencies if x <= 0),
            "within_30_days": sum(1 for x in latencies if x <= 30),
            "p90": sorted(latencies)[int(0.9 * (len(latencies) - 1))] if latencies else None,
            "max": max(latencies) if latencies else None,
        },
    }


def tables(result: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    names = _names()
    lines_md = ["| Class | Name | Incidents |", "|---|---|---|"]
    lines_tex = ["\\begin{tabular}{llr}", "\\toprule", "Class & Name & Incidents \\\\", "\\midrule"]
    for cls, n in result["by_taxonomy_class"].items():
        lines_md.append(f"| {cls} | {names.get(cls, '')} | {n} |")
        lines_tex.append(f"{cls} & {_tex(names.get(cls, ''))} & {n} \\\\")
    lines_tex += ["\\bottomrule", "\\end{tabular}"]
    (out / "rq3_classes.md").write_text("\n".join(lines_md) + "\n", encoding="utf-8")
    (out / "rq3_classes.tex").write_text("\n".join(lines_tex) + "\n", encoding="utf-8")
    rc_names = _rc_names()
    rc = ["| Root cause | Name | Incidents |", "|---|---|---|"] + [
        f"| {k} | {rc_names.get(k, '')} | {v} |" for k, v in result["by_root_cause"].items()
    ]
    (out / "rq3_root_causes.md").write_text("\n".join(rc) + "\n", encoding="utf-8")
    rct = [
        "\\begin{tabular}{lp{6.2cm}r}",
        "\\toprule",
        "Root cause & Name & Incidents \\\\",
        "\\midrule",
    ]
    rct += [
        f"{k} & {_tex(rc_names.get(k, ''))} & {v} \\\\" for k, v in result["by_root_cause"].items()
    ]
    rct += ["\\bottomrule", "\\end{tabular}"]
    (out / "rq3_root_causes.tex").write_text("\n".join(rct) + "\n", encoding="utf-8")


def _names() -> dict[str, str]:
    import yaml

    data = yaml.safe_load((ROOT / "taxonomy" / "harness-threats.yaml").read_text(encoding="utf-8"))
    return {c["id"]: c.get("name") or c.get("title", "") for c in data.get("classes", [])}


def _rc_names() -> dict[str, str]:
    import yaml

    data = yaml.safe_load((ROOT / "taxonomy" / "root-causes.yaml").read_text(encoding="utf-8"))
    return {c["id"]: c.get("name", "") for c in data.get("classes", [])}


def _tex(text: str) -> str:
    return text.replace("&", "\\&").replace("_", "\\_").replace("%", "\\%")


def figure(result: dict[str, Any], out: Path) -> None:
    figstyle.apply()
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    quarters = list(result["by_quarter"])
    counts = [result["by_quarter"][q] for q in quarters]
    partial = bool(result.get("partial_last_quarter"))
    fig, ax = plt.subplots(figsize=(figstyle.COLUMN_IN, 1.6))
    xs = list(range(len(quarters)))
    bars = ax.bar(xs, counts, width=0.7, color=figstyle.BLUE, linewidth=0)
    open_bar = {
        "facecolor": "#eaf0f8",
        "edgecolor": figstyle.BLUE,
        "hatch": "////",
        "linewidth": 0.5,
    }
    if partial:  # the last quarter ends at the study cut-off, so it is drawn open
        bars[-1].set(**open_bar)
    for x, c in zip(xs, counts, strict=True):
        ax.text(x, c + max(counts) * 0.02, str(c), ha="center", va="bottom", fontsize=6)
    ax.set_xticks(xs)
    ax.set_xticklabels([q.split("-")[1] for q in quarters])
    for year in sorted({q[:4] for q in quarters}):  # year centred under its quarters
        idx = [x for x, q in zip(xs, quarters, strict=True) if q.startswith(year)]
        ax.annotate(
            year,
            xy=((idx[0] + idx[-1]) / 2, 0),
            xycoords=("data", "axes fraction"),
            xytext=(0, -13),
            textcoords="offset points",
            ha="center",
            va="top",
            fontsize=6.5,
        )
    ax.set_ylabel("Counted incidents")
    ax.set_ylim(0, max(counts) * 1.2)
    ax.yaxis.grid(True, color=figstyle.GRID, linewidth=0.5)
    ax.set_axisbelow(True)
    ax.tick_params(axis="x", length=0)
    if partial:
        ax.legend(
            handles=[Patch(**open_bar)],
            labels=["partial quarter (study cut-off)"],
            loc="upper left",
            handlelength=1.4,
        )
    fig.tight_layout(pad=0.25)
    figstyle.save(fig, out, "rq3_timeline")
    plt.close(fig)


def main() -> None:
    result = analyse(load())
    path = ROOT / "experiments" / "results" / "rq3_incidents.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    tables(result, ROOT / "paper" / "tables")
    figure(result, ROOT / "paper" / "figures")
    print(f"counted {result['counted']} of {result['total_rows']} -> {path}")


if __name__ == "__main__":
    main()
