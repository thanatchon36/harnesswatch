"""E1 - RQ2 control matrix: evidence JSON + rubric + rater scores -> matrix, tables, heat map.

Deterministic and offline. Inputs:
  * matrix/rubric.yaml (dimension ids, exposure weights)
  * matrix/evidence/<harness>.json (facts with source URL and evidence label)
  * rules/harness_profiles/<harness>.yaml (tier, display name, status)
  * matrix/scores_rater1.yaml (this rater's decisions; see the file header for the schema)
  * matrix/scores_rater2.yaml, optional (an independent rater, same schema) -> agreement only

Outputs:
  * matrix/controls.csv, matrix/scorecard.md
  * experiments/results/e1_matrix.json (+ e1_agreement.json when rater 2 exists)
  * paper/tables/scorecard.{tex,md}
  * paper/figures/e1_heatmap.{pdf,png}

Evidence rules enforced here (matrix/rubric.yaml, MISSION 6.4):
  * a cited fact labelled ``unverified`` is an error;
  * a non-N/A score must cite at least one fact labelled from-official-docs or verified-by-test
    (third-party reports may only lower a score, so they never stand alone);
  * tier-C (runtime/SDK) and docs-only harnesses never cite ``verified-by-test``: such facts were
    source or API reads and are cited as ``from-official-docs`` (ASSUMPTIONS A09);
  * N/A cells need a rationale starting with "N/A (".

Usage: ``uv run --group experiments python experiments/e1_matrix.py [--no-figure]``
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
RUBRIC = ROOT / "matrix" / "rubric.yaml"
EVIDENCE_DIR = ROOT / "matrix" / "evidence"
PROFILES_DIR = ROOT / "rules" / "harness_profiles"
RATER1 = ROOT / "matrix" / "scores_rater1.yaml"
RATER2 = ROOT / "matrix" / "scores_rater2.yaml"

CORE_DIMS = [f"D{i:02d}" for i in range(1, 16)]
SECURITY_CORE = ["D01", "D02", "D03", "D04", "D05", "D07", "D08", "D13", "D14"]
MIN_SCORED = 8  # rubric guardrail: mean only if >= 8 of 15 dimensions are scored
LABEL_ABBR = {
    "verified-by-test": "verified-by-test",
    "from-official-docs": "from-official-docs",
    "third-party-report": "third-party-report",
}
ELIGIBLE = {"verified-by-test", "from-official-docs"}
CSV_COLUMNS = [
    "harness",
    "tier",
    "version",
    "dimension",
    "score",
    "na_reason",
    "rationale",
    "evidence",
    "rater",
]


class ScoringError(ValueError):
    """A rater decision violates the evidence rules."""


# --- loading ---------------------------------------------------------------------------------


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_rubric(path: Path) -> dict[str, dict[str, Any]]:
    data = load_yaml(path)
    return {d["id"]: d for d in data["dimensions"]}


def load_evidence(directory: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for p in sorted(directory.glob("*.json")):
        out[p.stem] = json.loads(p.read_text(encoding="utf-8"))
    return out


def load_profiles(directory: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for p in sorted(directory.glob("*.yaml")):
        if p.name.startswith("_"):
            continue
        prof = load_yaml(p)
        out[str(prof.get("id", p.stem))] = prof
    return out


# --- evidence rules --------------------------------------------------------------------------


def tier_group(tier: str) -> str:
    """Rubric: compare tier C (runtimes/SDKs) only with tier C."""
    return "C" if str(tier).upper() == "C" else "A/B"


def cite_label(fact: dict[str, Any], tier: str, status: str) -> str | None:
    """Label under which a fact may be cited, or None when it may not be cited at all."""
    label = str(fact.get("label", "unverified"))
    if label == "unverified" or label not in LABEL_ABBR:
        return None
    if label == "verified-by-test" and (tier_group(tier) == "C" or status == "docs-only"):
        return "from-official-docs"
    return label


def resolve_fact(evidence: dict[str, Any], dim: str, ref: int | str) -> dict[str, Any]:
    """``ref`` is an index into ``dim``'s facts, or ``"Dxx.i"`` for another dimension."""
    if isinstance(ref, str):
        m = re.fullmatch(r"(D\d\d)\.(\d+)", ref)
        if not m:
            raise ScoringError(f"bad fact reference {ref!r}")
        dim, idx = m.group(1), int(m.group(2))
    else:
        idx = int(ref)
    facts = evidence.get("dimensions", {}).get(dim, {}).get("facts", [])
    if not 0 <= idx < len(facts):
        raise ScoringError(f"fact {dim}[{idx}] does not exist")
    fact: dict[str, Any] = facts[idx]
    return fact


def check_decision(
    harness: str,
    dim: str,
    decision: dict[str, Any],
    evidence: dict[str, Any],
    tier: str,
    status: str,
) -> list[tuple[str, str]]:
    """Validate one decision and return the cited (label, source) pairs."""
    where = f"{harness} {dim}"
    if not isinstance(decision, dict) or "s" not in decision or "r" not in decision:
        raise ScoringError(f"{where}: decision needs keys s and r")
    score, rationale = decision["s"], str(decision["r"]).strip()
    if score is None:
        if not rationale.startswith("N/A ("):
            raise ScoringError(f"{where}: N/A rationale must start with 'N/A ('")
    elif score not in (0, 1, 2, 3) or isinstance(score, bool):
        raise ScoringError(f"{where}: score {score!r} not in 0-3")
    refs = decision.get("f")
    if refs is None:  # default: every citable fact of the dimension
        n = len(evidence.get("dimensions", {}).get(dim, {}).get("facts", []))
        refs = [
            i
            for i in range(n)
            if cite_label(resolve_fact(evidence, dim, i), tier, status) is not None
        ]
    cited: list[tuple[str, str]] = []
    labels: set[str] = set()
    for ref in refs:
        fact = resolve_fact(evidence, dim, ref)
        label = cite_label(fact, tier, status)
        if label is None:
            raise ScoringError(f"{where}: cites unverified fact {ref!r}")
        labels.add(label)
        pair = (label, str(fact.get("source", "")).strip())
        if pair not in cited:
            cited.append(pair)
    if score is not None and not labels & ELIGIBLE:
        raise ScoringError(
            f"{where}: a score needs a from-official-docs or verified-by-test fact "
            "(third-party reports can only lower a score)"
        )
    return cited


# --- matrix ----------------------------------------------------------------------------------


def build_rows(
    evidence: dict[str, dict[str, Any]],
    profiles: dict[str, dict[str, Any]],
    scores: dict[str, Any],
    rater: str = "rater1",
) -> list[dict[str, Any]]:
    """One row per harness x D01-D15, plus D16 where the rater scored it."""
    decisions: dict[str, dict[str, Any]] = scores.get("scores", {}) or {}
    d16: dict[str, Any] = scores.get("d16", {}) or {}
    missing = sorted(set(profiles) - set(evidence)) + sorted(set(profiles) - set(decisions))
    if missing:
        raise ScoringError(f"harnesses without evidence or scores: {missing}")
    rows: list[dict[str, Any]] = []
    for harness in sorted(profiles):
        prof, ev = profiles[harness], evidence[harness]
        tier = str(prof.get("tier", ev.get("tier", "")))
        status = str(ev.get("status", prof.get("status", "")))
        per_dim = dict(decisions[harness])
        if harness in d16:
            per_dim["D16"] = d16[harness]
        dims = [*CORE_DIMS, "D16"] if "D16" in per_dim else CORE_DIMS
        for dim in dims:
            if dim not in per_dim:
                raise ScoringError(f"{harness} {dim}: no decision")
            dec = per_dim[dim]
            cited = check_decision(harness, dim, dec, ev, tier, status)
            rationale = " ".join(str(dec["r"]).split())
            score = dec["s"]
            rows.append(
                {
                    "harness": harness,
                    "tier": tier,
                    "version": " ".join(str(ev.get("version", "")).split()),
                    "dimension": dim,
                    "score": "N/A" if score is None else int(score),
                    "na_reason": rationale if score is None else "",
                    "rationale": rationale,
                    "evidence": "; ".join(f"[{lab}] {src}" for lab, src in cited),
                    "rater": rater,
                }
            )
    return rows


def _mean(values: Iterable[float], weights: Iterable[float] | None = None) -> float | None:
    vals = list(values)
    if not vals:
        return None
    w = list(weights) if weights is not None else [1.0] * len(vals)
    total = sum(w)
    return round(sum(v * x for v, x in zip(vals, w, strict=True)) / total, 3) if total else None


def short_name(name: str) -> str:
    """Product name without the parenthetical/aside of the profile's long name."""
    return re.split(r" \(| - |; |: ", str(name), maxsplit=1)[0].strip()


def harness_summary(
    rows: list[dict[str, Any]],
    profiles: dict[str, dict[str, Any]],
    rubric: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for harness in sorted(profiles):
        cells = {
            r["dimension"]: r["score"]
            for r in rows
            if r["harness"] == harness and r["dimension"] in CORE_DIMS
        }
        scored = {d: s for d, s in cells.items() if s != "N/A"}
        enough = len(scored) >= MIN_SCORED
        core = {d: s for d, s in scored.items() if d in SECURITY_CORE}
        out[harness] = {
            "name": short_name(profiles[harness].get("name", harness)),
            "tier": str(profiles[harness].get("tier", "")),
            "tier_group": tier_group(str(profiles[harness].get("tier", ""))),
            "n_scored": len(scored),
            "n_na": len(cells) - len(scored),
            "mean": _mean(scored.values()) if enough else None,
            "min": min(scored.values()) if scored else None,
            "mean_exposure_weighted": _mean(
                scored.values(), [float(rubric[d]["incident_exposure"]) for d in scored]
            )
            if enough
            else None,
            "mean_security_core": _mean(core.values()) if enough and core else None,
            "note": "" if enough else "insufficient evidence (<8 of 15 dimensions scored)",
            "scores": {d: cells[d] for d in CORE_DIMS},
        }
    return out


def dimension_distribution(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for dim in [*CORE_DIMS, "D16"]:
        cells = [r for r in rows if r["dimension"] == dim]
        if not cells:
            continue
        entry: dict[str, Any] = {}
        for group in ("all", "A/B", "C"):
            sel = [r for r in cells if group == "all" or tier_group(r["tier"]) == group]
            c = Counter(str(r["score"]) for r in sel)
            nums = [r["score"] for r in sel if r["score"] != "N/A"]
            entry[group] = {
                "counts": {k: c.get(k, 0) for k in ("0", "1", "2", "3", "N/A")},
                "n": len(sel),
                "mean": _mean(nums),
            }
        out[dim] = entry
    return out


def rankings(summary: dict[str, dict[str, Any]], k: int = 3) -> dict[str, Any]:
    """Top/bottom k per tier group under the three rubric weightings (+ stability flag)."""
    out: dict[str, Any] = {}
    for group in ("A/B", "C"):
        ranked = {
            h: v for h, v in summary.items() if v["tier_group"] == group and v["mean"] is not None
        }
        g: dict[str, Any] = {"n_ranked": len(ranked)}
        for key in ("mean", "mean_exposure_weighted", "mean_security_core"):
            order = sorted(ranked, key=lambda h, key=key: (-(ranked[h][key] or 0.0), h))
            g[key] = {"top": order[:k], "bottom": list(reversed(order[-k:]))}
        keys = ("mean", "mean_exposure_weighted", "mean_security_core")
        g["top_in_all_weightings"] = sorted(set.intersection(*(set(g[x]["top"]) for x in keys)))
        g["bottom_in_all_weightings"] = sorted(
            set.intersection(*(set(g[x]["bottom"]) for x in keys))
        )
        g["top_stable"] = all(
            set(g[key]["top"]) == set(g["mean"]["top"])
            for key in ("mean_exposure_weighted", "mean_security_core")
        )
        g["bottom_stable"] = all(
            set(g[key]["bottom"]) == set(g["mean"]["bottom"])
            for key in ("mean_exposure_weighted", "mean_security_core")
        )
        out[group] = g
    return out


# --- agreement -------------------------------------------------------------------------------


def quadratic_weighted_kappa(a: list[int], b: list[int], k: int = 4) -> float | None:
    """Cohen's kappa with quadratic weights on categories 0..k-1."""
    if len(a) != len(b):
        raise ValueError("rating lists differ in length")
    n = len(a)
    if n == 0:
        return None
    obs = [[0.0] * k for _ in range(k)]
    for x, y in zip(a, b, strict=True):
        obs[x][y] += 1
    row = [sum(obs[i]) for i in range(k)]
    col = [sum(obs[i][j] for i in range(k)) for j in range(k)]
    num = den = 0.0
    for i in range(k):
        for j in range(k):
            w = (i - j) ** 2 / (k - 1) ** 2
            num += w * obs[i][j]
            den += w * row[i] * col[j] / n
    return 1.0 if den == 0 else round(1 - num / den, 4)


def agreement(scores1: dict[str, Any], scores2: dict[str, Any]) -> dict[str, Any]:
    s1, s2 = scores1.get("scores", {}), scores2.get("scores", {})
    a: list[int] = []
    b: list[int] = []
    disagreements: list[dict[str, Any]] = []
    na_mismatch = both_na = 0
    for h in sorted(set(s1) & set(s2)):
        for d in CORE_DIMS:
            if d not in s1[h] or d not in s2[h]:
                continue
            x, y = s1[h][d].get("s"), s2[h][d].get("s")
            if x is None and y is None:
                both_na += 1
                continue
            if x is None or y is None:
                na_mismatch += 1
                disagreements.append({"harness": h, "dimension": d, "rater1": x, "rater2": y})
                continue
            a.append(int(x))
            b.append(int(y))
            if x != y:
                disagreements.append(
                    {"harness": h, "dimension": d, "rater1": x, "rater2": y, "diff": abs(x - y)}
                )
    exact = sum(x == y for x, y in zip(a, b, strict=True))
    return {
        "overlapping_scored_cells": len(a),
        "exact_agreement": round(exact / len(a), 4) if a else None,
        "within_one": round(sum(abs(x - y) <= 1 for x, y in zip(a, b, strict=True)) / len(a), 4)
        if a
        else None,
        "kappa_quadratic": quadratic_weighted_kappa(a, b),
        "both_na": both_na,
        "na_vs_score": na_mismatch,
        "disagreements": disagreements,
    }


# --- writers ---------------------------------------------------------------------------------


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(buf.getvalue(), encoding="utf-8")


def _fmt(v: float | None) -> str:
    return "--" if v is None else f"{v:.2f}"


def _ordered(summary: dict[str, dict[str, Any]], group: str) -> list[str]:
    hs = [h for h, v in summary.items() if v["tier_group"] == group]
    return sorted(hs, key=lambda h: (summary[h]["mean"] is None, -(summary[h]["mean"] or 0), h))


def scorecard_md(summary: dict[str, dict[str, Any]]) -> str:
    lines: list[str] = []
    for group, title in (("A/B", "Tier A/B harnesses"), ("C", "Tier C runtimes and SDKs")):
        lines += [f"**{title}** (mean of scored D01-D15; N/A excluded; '-' = N/A)", ""]
        lines.append("| Harness | " + " | ".join(CORE_DIMS) + " | n | Mean | Min |")
        lines.append("|---|" + "---|" * (len(CORE_DIMS) + 3))
        for h in _ordered(summary, group):
            v = summary[h]
            cells = ["-" if v["scores"][d] == "N/A" else str(v["scores"][d]) for d in CORE_DIMS]
            mean = _fmt(v["mean"]) if v["mean"] is not None else "insuff."
            lines.append(
                f"| {v['name']} | " + " | ".join(cells) + f" | {v['n_scored']} | {mean} | "
                f"{'-' if v['min'] is None else v['min']} |"
            )
        lines.append("")
    return "\n".join(lines)


def _tex_escape(s: str) -> str:
    for a, b in (
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("_", r"\_"),
        ("#", r"\#"),
    ):
        s = s.replace(a, b)
    return s


def scorecard_tex(summary: dict[str, dict[str, Any]]) -> str:
    head = " & ".join(["Harness", *[d[1:] for d in CORE_DIMS], "$n$", "Mean", "Min"])
    out = [
        "% Generated by experiments/e1_matrix.py from matrix/evidence and matrix/scores_rater1.yaml.",
        "% Do not edit by hand.",
        r"\begin{table*}[t]",
        r"\centering\scriptsize\setlength{\tabcolsep}{2.5pt}",
        r"\caption{RQ2 control scorecard (0--3 per dimension, rater 1; -- = N/A, excluded from the "
        r"mean; means need $\geq 8$ scored dimensions; tier C is ranked separately).}",
        r"\label{tab:scorecard}",
        r"\begin{tabular}{l" + "c" * len(CORE_DIMS) + "rrr}",
        r"\toprule",
        head + r" \\",
    ]
    for group, title in (("A/B", "Tier A/B harnesses"), ("C", "Tier C runtimes and SDKs")):
        out += [r"\midrule", rf"\multicolumn{{{len(CORE_DIMS) + 4}}}{{l}}{{\textit{{{title}}}}} \\"]
        for h in _ordered(summary, group):
            v = summary[h]
            cells = ["--" if v["scores"][d] == "N/A" else str(v["scores"][d]) for d in CORE_DIMS]
            mean = _fmt(v["mean"]) if v["mean"] is not None else "insuff."
            mn = "--" if v["min"] is None else str(v["min"])
            out.append(
                " & ".join([_tex_escape(str(v["name"])), *cells, str(v["n_scored"]), mean, mn])
                + r" \\"
            )
    out += [r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""]
    return "\n".join(out)


def matrix_scorecard_md(result: dict[str, Any], rubric: dict[str, dict[str, Any]]) -> str:
    s = result["summary"]
    lines = [
        "# RQ2 control scorecard",
        "",
        "Generated by `experiments/e1_matrix.py` from `matrix/evidence/*.json`, `matrix/rubric.yaml` "
        "and `matrix/scores_rater1.yaml`. Do not edit by hand. Cell-level rationale and evidence "
        "links: `matrix/controls.csv`.",
        "",
        f"- Harnesses: {result['counts']['harnesses']} "
        f"({result['counts']['tier_ab']} tier A/B, {result['counts']['tier_c']} tier C).",
        f"- D01-D15 cells: {result['counts']['core_cells']}, scored "
        f"{result['counts']['core_scored']}, N/A {result['counts']['core_na']}.",
        f"- D16 (proposed, not in means): {result['counts']['d16_cells']} cells scored.",
        "- Scale: 0 absent/unsafe default, 1 opt-in/weak, 2 on by default with gaps, "
        "3 strong default + central enforcement. Means are unweighted over scored D01-D15 "
        "dimensions and require at least 8 scored dimensions. Tier C is never ranked with A/B.",
        "",
        "## Ranking (unweighted mean)",
        "",
    ]
    for group in ("A/B", "C"):
        g = result["rankings"][group]
        name = lambda h: s[h]["name"]  # noqa: E731
        lines.append(
            f"- **{group}**: top {', '.join(f'{name(h)} ({_fmt(s[h]["mean"])})' for h in g['mean']['top'])}; "
            f"bottom {', '.join(f'{name(h)} ({_fmt(s[h]["mean"])})' for h in g['mean']['bottom'])}. "
            f"Top set stable under all three weightings: {'yes' if g['top_stable'] else 'no'}; "
            f"bottom set stable: {'yes' if g['bottom_stable'] else 'no'}. "
            f"In the top 3 under every weighting: "
            f"{', '.join(name(h) for h in g['top_in_all_weightings']) or 'none'}; "
            f"in the bottom 3 under every weighting: "
            f"{', '.join(name(h) for h in g['bottom_in_all_weightings']) or 'none'}. "
            "Ties are broken alphabetically."
        )
    lines += [
        "",
        "## Scorecard",
        "",
        scorecard_md(s),
        "## Per-dimension distribution (all tiers)",
        "",
    ]
    lines.append("| Dim | Name | 0 | 1 | 2 | 3 | N/A | Mean |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for d, e in result["dimension_distribution"].items():
        c = e["all"]["counts"]
        lines.append(
            f"| {d} | {rubric[d]['name']} | {c['0']} | {c['1']} | {c['2']} | {c['3']} | "
            f"{c['N/A']} | {_fmt(e['all']['mean'])} |"
        )
    lines += ["", "## D16 local service exposure (proposed; excluded from means)", ""]
    lines.append("| Harness | Score | Rationale |")
    lines.append("|---|---|---|")
    for r in result["rows"]:
        if r["dimension"] == "D16":
            lines.append(f"| {s[r['harness']]['name']} | {r['score']} | {r['rationale']} |")
    lines.append("")
    return "\n".join(lines)


def heatmap(summary: dict[str, dict[str, Any]], out_dir: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.colors import ListedColormap
    from matplotlib.patches import Rectangle

    plt.rcParams["svg.hashsalt"] = "e1"
    # sequential single hue (blue, light -> dark); N/A is a hatched neutral, never a ramp step
    ramp = ["#cde2fb", "#6da7ec", "#2a78d6", "#104281"]
    ink = {0: "#1f1f1f", 1: "#1f1f1f", 2: "#ffffff", 3: "#ffffff"}
    groups = [("A/B", "Tier A/B harnesses"), ("C", "Tier C runtimes and SDKs")]
    orders = {g: _ordered(summary, g) for g, _ in groups}
    heights = [max(len(orders[g]), 1) for g, _ in groups]
    fig, axes = plt.subplots(
        2,
        1,
        figsize=(3.5, 0.098 * sum(heights) + 0.75),
        gridspec_kw={"height_ratios": heights, "hspace": 0.12},
    )
    cmap = ListedColormap(ramp)
    for ax, (group, title) in zip(axes, groups, strict=True):
        hs = orders[group]
        for i, h in enumerate(hs):
            v = summary[h]
            for j, d in enumerate(CORE_DIMS):
                sc = v["scores"][d]
                if sc == "N/A":
                    ax.add_patch(
                        Rectangle(
                            (j, i),
                            1,
                            1,
                            facecolor="#f0efec",
                            edgecolor="#b8b6b0",
                            hatch="////",
                            linewidth=0,
                        )
                    )
                else:
                    ax.add_patch(Rectangle((j, i), 1, 1, facecolor=cmap(int(sc)), linewidth=0))
                    ax.text(
                        j + 0.5,
                        i + 0.52,
                        str(sc),
                        ha="center",
                        va="center",
                        fontsize=4,
                        color=ink[int(sc)],
                    )
            mean = _fmt(v["mean"]) if v["mean"] is not None else "insuff."
            ax.text(
                len(CORE_DIMS) + 0.25,
                i + 0.52,
                f"{mean} ({v['n_scored']})",
                ha="left",
                va="center",
                fontsize=4,
                color="#3a3a3a",
            )
        for x in range(len(CORE_DIMS) + 1):  # 2px-style surface gaps between cells
            ax.axvline(x, color="white", linewidth=0.4)
        for y in range(len(hs) + 1):
            ax.axhline(y, color="white", linewidth=0.4)
        ax.set_xlim(0, len(CORE_DIMS))
        ax.set_ylim(len(hs), 0)
        ax.set_yticks([i + 0.5 for i in range(len(hs))])
        ax.set_yticklabels([str(summary[h]["name"]) for h in hs], fontsize=4.5)
        ax.set_xticks([j + 0.5 for j in range(len(CORE_DIMS))])
        ax.set_xticklabels([d.replace("D", "") for d in CORE_DIMS], fontsize=4.5)
        ax.xaxis.tick_top()
        ax.tick_params(length=0)
        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_title(
            f"{title} (right: mean, n scored)",
            fontsize=5,
            loc="left",
            pad=7,
        )
    handles = [Rectangle((0, 0), 1, 1, facecolor=c) for c in ramp] + [
        Rectangle((0, 0), 1, 1, facecolor="#f0efec", edgecolor="#b8b6b0", hatch="////")
    ]
    fig.legend(
        handles,
        ["0 absent", "1 opt-in/weak", "2 default, gaps", "3 strong+central", "N/A"],
        loc="lower center",
        ncol=5,
        fontsize=4.5,
        handlelength=1.0,
        columnspacing=0.8,
        frameon=False,
        bbox_to_anchor=(0.5, 0.0),
    )
    fig.subplots_adjust(left=0.33, right=0.86, top=0.95, bottom=0.03)
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_dir / "e1_heatmap.pdf", metadata={"CreationDate": None, "ModDate": None})
    fig.savefig(out_dir / "e1_heatmap.png", dpi=200, metadata={"Software": None})
    plt.close(fig)


# --- driver ----------------------------------------------------------------------------------


def run(
    root: Path = ROOT,
    rater1: Path | None = None,
    rater2: Path | None = None,
    figure: bool = True,
) -> dict[str, Any]:
    rubric = load_rubric(root / "matrix" / "rubric.yaml")
    evidence = load_evidence(root / "matrix" / "evidence")
    profiles = load_profiles(root / "rules" / "harness_profiles")
    scores1 = load_yaml(rater1 or root / "matrix" / "scores_rater1.yaml")
    rows = build_rows(evidence, profiles, scores1, rater=str(scores1.get("rater", "rater1")))
    summary = harness_summary(rows, profiles, rubric)
    core = [r for r in rows if r["dimension"] in CORE_DIMS]
    result: dict[str, Any] = {
        "experiment": "E1",
        "rq": "RQ2",
        "rater": scores1.get("rater", "rater1"),
        "date": str(scores1.get("date", "")),
        "rubric": "matrix/rubric.yaml",
        "counts": {
            "harnesses": len(summary),
            "tier_ab": sum(v["tier_group"] == "A/B" for v in summary.values()),
            "tier_c": sum(v["tier_group"] == "C" for v in summary.values()),
            "core_cells": len(core),
            "core_scored": sum(r["score"] != "N/A" for r in core),
            "core_na": sum(r["score"] == "N/A" for r in core),
            "d16_cells": sum(r["dimension"] == "D16" for r in rows),
            "insufficient_evidence": sorted(h for h, v in summary.items() if v["mean"] is None),
        },
        "summary": summary,
        "dimension_distribution": dimension_distribution(rows),
        "rankings": rankings(summary),
        "rows": rows,
    }
    write_csv(rows, root / "matrix" / "controls.csv")
    results = root / "experiments" / "results"
    results.mkdir(parents=True, exist_ok=True)
    (results / "e1_matrix.json").write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    tables = root / "paper" / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    (tables / "scorecard.md").write_text(
        "<!-- Generated by experiments/e1_matrix.py; do not edit. -->\n\n" + scorecard_md(summary),
        encoding="utf-8",
    )
    (tables / "scorecard.tex").write_text(scorecard_tex(summary), encoding="utf-8")
    (root / "matrix" / "scorecard.md").write_text(
        matrix_scorecard_md(result, rubric), encoding="utf-8"
    )
    r2 = rater2 or root / "matrix" / "scores_rater2.yaml"
    if r2.exists():
        agr = agreement(scores1, load_yaml(r2))
        (results / "e1_agreement.json").write_text(
            json.dumps(agr, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        result["agreement"] = {k: v for k, v in agr.items() if k != "disagreements"}
    if figure:
        heatmap(summary, root / "paper" / "figures")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--no-figure", action="store_true", help="skip the matplotlib heat map")
    args = parser.parse_args()
    res = run(figure=not args.no_figure)
    c = res["counts"]
    print(
        f"E1: {c['harnesses']} harnesses, {c['core_cells']} D01-D15 cells "
        f"({c['core_scored']} scored, {c['core_na']} N/A), {c['d16_cells']} D16 cells"
    )
    for g in ("A/B", "C"):
        r = res["rankings"][g]["mean"]
        print(f"  {g}: top {r['top']} bottom {r['bottom']}")
    if "agreement" in res:
        print(f"  agreement: {res['agreement']}")


if __name__ == "__main__":
    main()
