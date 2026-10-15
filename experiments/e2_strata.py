"""E2 stratified prevalence (offline, from experiments/results/e2_corpus.json).

The corpus pools 17 search strata of about 60 files each, so a pooled repo rate mostly reflects
which files we searched for (hostile review, REVIEW.md). Each rule can only fire on one kind
of file, so here it is divided by the size of the stratum that can carry it:
config/MCP files, instruction files, or agent CI workflows. With dedup at 0, each sampled
file belongs to exactly one repo and one stratum.
Writes experiments/results/e2_strata.json and paper/tables/e2_strata.tex|md.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from harnesswatch.bench.stats import wilson

ROOT = Path(__file__).resolve().parents[1]
STRATA = {
    "config": [
        ".claude/settings.json",
        ".mcp.json",
        ".cursor/mcp.json",
        ".vscode/mcp.json",
        "opencode.json",
        ".kiro/settings/mcp.json",
        ".gemini/settings.json",
        ".codex/config.toml",
        ".agents/mcp_config.json",
        ".grok/config.toml",
    ],
    "instructions": [
        "AGENTS.md",
        "CLAUDE.md",
        ".github/copilot-instructions.md",
        ".windsurf/rules",
    ],
    "workflows": ["workflow:claude-code-action", "workflow:codex exec", "workflow:gemini -p"],
}
RULE_STRATUM = {"CI": "workflows", "INJ": "instructions"}  # everything else: config


def stratum(rule_id: str) -> str:
    return RULE_STRATUM.get(rule_id.split("-")[1], "config")


def analyse(data: dict[str, Any]) -> dict[str, Any]:
    sizes = {
        name: sum(
            data["per_target"][t]["audited_files"] for t in targets if t in data["per_target"]
        )
        for name, targets in STRATA.items()
    }
    rows = []
    for rule in data["prevalence"]["rules"]:
        name = stratum(rule["rule_id"])
        n, k = sizes[name], rule["repos"]
        low, high = wilson(k, n)
        rows.append(
            {
                "rule_id": rule["rule_id"],
                "title": rule["title"],
                "stratum": name,
                "k": k,
                "n": n,
                "rate": round(k / n, 4),
                "ci95": [round(low, 4), round(high, 4)],
            }
        )
    rows.sort(key=lambda r: (-r["rate"], r["rule_id"]))
    return {
        "strata_sizes": sizes,
        "rules": rows,
        "note": "rate = repos with a finding / audited files in the stratum that can carry the rule",
    }


def tables(result: dict[str, Any]) -> None:
    out = ROOT / "paper" / "tables"
    md = ["| Rule | Stratum (n) | Repos | Rate [95% CI] |", "|---|---|---|---|"]
    tex = [
        "\\begin{tabular}{llrl}",
        "\\toprule",
        "Rule & Stratum ($n$) & Repos & Rate [95\\% CI] \\\\",
        "\\midrule",
    ]
    for r in result["rules"][:10]:
        cell = f"{100 * r['rate']:.1f}\\% [{100 * r['ci95'][0]:.1f}, {100 * r['ci95'][1]:.1f}]"
        md.append(
            f"| {r['rule_id']} | {r['stratum']} ({r['n']}) | {r['k']} | {cell.replace(chr(92), '')} |"
        )
        tex.append(f"{r['rule_id']} & {r['stratum']} ({r['n']}) & {r['k']} & {cell} \\\\")
    tex += ["\\bottomrule", "\\end{tabular}"]
    (out / "e2_strata.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out / "e2_strata.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


def main() -> None:
    data = json.loads((ROOT / "experiments" / "results" / "e2_corpus.json").read_text())
    result = analyse(data)
    (ROOT / "experiments" / "results" / "e2_strata.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    tables(result)
    print(result["strata_sizes"], [(r["rule_id"], r["rate"]) for r in result["rules"][:5]])


if __name__ == "__main__":
    main()
