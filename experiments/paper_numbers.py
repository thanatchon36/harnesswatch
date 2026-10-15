"""Generate paper/numbers.tex: one LaTeX macro per number quoted in the paper (MISSION §6.4).

Every macro is read from an experiments/results/*.json file, so prose never carries a hand-typed
number. Missing inputs produce `\\textbf{??}` and a warning instead of a silent value.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "experiments" / "results"
OUT = ROOT / "paper" / "numbers.tex"


def load(name: str) -> dict[str, Any] | None:
    path = RES / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def fmt(value: Any, digits: int = 2) -> str:
    if value is None:
        return "\\textbf{??}"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def pct(k: int, n: int) -> str:
    return f"{100 * k / n:.0f}\\%" if n else "\\textbf{??}"


def macros() -> dict[str, str]:
    m: dict[str, str] = {}
    rq3 = load("rq3_incidents.json")
    if rq3:
        lat = rq3["patch_latency_days"]
        m |= {
            "nIncRows": fmt(rq3["total_rows"]),
            "nIncCounted": fmt(rq3["counted"]),
            "nIncTwentyFive": fmt(rq3["by_year"].get("2025")),
            "nIncTwentySix": fmt(rq3["by_year"].get("2026")),
            "nIncCVE": fmt(rq3["with_cve"]),
            "nIncGHSA": fmt(rq3["with_ghsa"]),
            "nIncVuln": fmt(rq3["by_kind"].get("vulnerability")),
            "nIncDesign": fmt(rq3["by_kind"].get("design-weakness")),
            "nIncSupply": fmt(rq3["by_kind"].get("supply-chain")),
            "nIncNotVerified": fmt(rq3["excluded"]["not_verified"]),
            "nIncIdFailed": fmt(rq3["excluded"]["id_check_failed"]),
            "nIncTopThree": fmt(rq3["by_taxonomy_class"].get("T03")),
            "nIncTopTwo": fmt(rq3["by_taxonomy_class"].get("T02")),
            "nIncTNineteen": fmt(rq3["by_taxonomy_class"].get("T19")),
            "nIncTEighteen": fmt(rq3["by_taxonomy_class"].get("T18")),
            "nIncTOne": fmt(rq3["by_taxonomy_class"].get("T01")),
            "nIncRCThree": fmt(rq3["by_root_cause"].get("RC3")),
            "nIncRCTwo": fmt(rq3["by_root_cause"].get("RC2")),
            "nIncRCTen": fmt(rq3["by_root_cause"].get("RC10")),
            "nLatency": fmt(lat["n"]),
            "nLatencyMedian": fmt(lat["median"]),
            "nLatencyBefore": fmt(lat["fixed_before_disclosure"]),
            "nLatencyMax": fmt(lat["max"]),
            "pctTopThree": pct(rq3["by_taxonomy_class"].get("T03", 0), rq3["counted"]),
            "pctRCThree": pct(rq3["by_root_cause"].get("RC3", 0), rq3["counted"]),
        }
    e1 = load("e1_matrix.json")
    if e1:
        c = e1["counts"]
        m |= {
            "nHarnesses": fmt(c["harnesses"]),
            "nHarnessesAB": fmt(c["tier_ab"]),
            "nHarnessesC": fmt(c["tier_c"]),
            "nCells": fmt(c["core_cells"]),
            "nCellsScored": fmt(c["core_scored"]),
            "nCellsNA": fmt(c["core_na"]),
        }
        summ = e1["summary"]
        for key, name in (
            ("codex-cli", "Codex"),
            ("claude-code", "Claude"),
            ("aider", "Aider"),
            ("continue", "Continue"),
            ("grok-build", "Grok"),
            ("antigravity", "Antigravity"),
            ("github-copilot", "Copilot"),
        ):
            m[f"mean{name}"] = fmt(summ.get(key, {}).get("mean"))
    agr = load("e1_agreement.json")
    if agr:
        m |= {
            "kappaEOne": fmt(agr["kappa_quadratic"]),
            "exactEOne": fmt(100 * agr["exact_agreement"], 1) + "\\%",
            "withinOneEOne": fmt(100 * agr["within_one"], 1) + "\\%",
            "nOverlapEOne": fmt(agr["overlapping_scored_cells"]),
            "nDisagreeEOne": fmt(len(agr["disagreements"])),
        }
    e4 = load("e4_supply.json")
    if e4:
        s = e4["summary"]
        for k, v in s.items():
            if isinstance(v, int | float) and not isinstance(v, bool):
                m["eFour" + "".join(p.capitalize() for p in re.split(r"[_\W]+", k) if p)] = fmt(v)
    e6 = load("e6_accuracy.json")
    if e6:
        t = e6["splits"]["test"]
        a = e6["splits"]["all"]
        m |= {
            "nESixCases": fmt(a["n_cases"]),
            "nESixTest": fmt(t["n_cases"]),
            "nESixDev": fmt(e6["splits"]["dev"]["n_cases"]),
            "eSixPrecision": fmt(t["micro"]["precision"], 3),
            "eSixPrecisionLo": fmt(t["micro"]["precision_ci"][0], 3),
            "eSixPrecisionHi": fmt(t["micro"]["precision_ci"][1], 3),
            "eSixRecall": fmt(t["micro"]["recall"], 3),
            "eSixRecallLo": fmt(t["micro"]["recall_ci"][0], 3),
            "eSixRecallHi": fmt(t["micro"]["recall_ci"][1], 3),
            "eSixFP": fmt(t["micro"]["fp"]),
            "eSixFN": fmt(t["micro"]["fn"]),
        }
    e7 = load("e7_claims.json")
    if e7:
        v = e7["verdicts"]
        m |= {
            "nClaims": fmt(e7["claims"]),
            "nClaimsTested": fmt(e7["tested"]),
            "nClaimsMatch": fmt(v.get("match", 0)),
            "nClaimsMismatch": fmt(v.get("mismatch", 0)),
            "nClaimsPartial": fmt(v.get("partial", 0)),
            "nClaimsNotObserved": fmt(v.get("not-observed", 0)),
            "nProbes": fmt(len(e7["probes"])),
        }
    e3 = load("e3_bench.json")
    if e3:
        m |= {
            "nBenchRuns": fmt(e3["n_runs"]),
            "nBenchErrors": fmt(e3["n_errors"]),
            "nBenchHarnesses": fmt(len(e3["harnesses"])),
            "nBenchModels": fmt(len(e3["models"])),
            "benchCost": fmt(e3["total_cost_usd"]),
        }
        for row in e3["by_mode"]:
            name = "Auto" if row["mode"] == "auto" else "Default"
            for metric, short in (
                ("injection_followed", "Follow"),
                ("task_completed", "Task"),
                ("exfil_attempt", "Exfil"),
                ("destructive_action", "Destr"),
                ("secret_read", "SecretRead"),
                ("secret_accessed", "SecretAny"),
                ("permission_prompt", "Prompt"),
            ):
                cell = row[metric]
                m[f"bench{short}{name}K"] = fmt(cell["k"])
                m[f"bench{short}{name}N"] = fmt(row["n"])
                m[f"bench{short}{name}Rate"] = fmt(cell["rate"], 3)
                m[f"bench{short}{name}Lo"] = fmt(cell["ci95"][0], 3)
                m[f"bench{short}{name}Hi"] = fmt(cell["ci95"][1], 3)
    e5 = load("e5_residue.json")
    if e5:
        content = [
            v["content"] for v in e5.values() if "content" in v and "residue_files" in v["content"]
        ]
        m |= {
            "nResidueHarnesses": fmt(len(content)),
            "nResidueWithCopy": fmt(sum(1 for c in content if c["residue_files"] > 0)),
            "nResidueReachable": fmt(
                sum(1 for c in content if any(r.get("world_reachable") for r in c["residue"]))
            ),
            "nResidueKeyPersisted": fmt(
                sum(1 for v in e5.values() if v.get("key", {}).get("residue_files", 0) > 0)
            ),
        }
    e2 = load("e2_corpus.json")
    if e2:
        for k, v in e2.items():
            if isinstance(v, int) and not isinstance(v, bool):
                m["eTwo" + "".join(p.capitalize() for p in re.split(r"[_\W]+", k) if p)] = fmt(v)
        prev = e2.get("prevalence") or {}
        if "repos_audited" in prev:
            m["eTwoReposAudited"] = fmt(prev["repos_audited"])
            m["eTwoFilesAudited"] = fmt(prev["files_audited"])
            m["eTwoRulesFired"] = fmt(len(prev.get("rules", [])))
    m |= paper_extras()
    return m


WORDS = [
    "One",
    "Two",
    "Three",
    "Four",
    "Five",
    "Six",
    "Seven",
    "Eight",
    "Nine",
    "Ten",
    "Eleven",
    "Twelve",
    "Thirteen",
    "Fourteen",
    "Fifteen",
]


def paper_extras() -> dict[str, str]:
    """Macros added for the Phase-6 paper text (all computed from results JSON)."""
    m: dict[str, str] = {}
    rq3 = load("rq3_incidents.json")
    if rq3:
        rc, tc, kind = rq3["by_root_cause"], rq3["by_taxonomy_class"], rq3["by_kind"]
        n = rq3["counted"]
        m |= {
            "nIncRCOne": fmt(rc.get("RC1", 0)),
            "nIncRCFour": fmt(rc.get("RC4", 0)),
            "nIncRCSix": fmt(rc.get("RC6", 0)),
            "nIncRCEight": fmt(rc.get("RC8", 0)),
            "pctRCOne": pct(rc.get("RC1", 0), n),
            "pctRCTen": pct(rc.get("RC10", 0), n),
            "pctRCTwoThree": pct(rc.get("RC2", 0) + rc.get("RC3", 0), n),
            "nIncTFour": fmt(tc.get("T04", 0)),
            "nIncTEight": fmt(tc.get("T08", 0)),
            "nIncTSeventeen": fmt(tc.get("T17", 0)),
            "nIncTNine": fmt(tc.get("T09", 0)),
            "nIncMisuse": fmt(kind.get("misuse", 0)),
            "nIncEvent": fmt(kind.get("incident", 0)),
            "nIncClasses": fmt(len(tc)),
            "nLatencyWithinThirty": fmt(rq3["patch_latency_days"]["within_30_days"]),
            "nIncTierA": fmt(rq3["by_tier"].get("A", 0)),
            "nIncTierB": fmt(rq3["by_tier"].get("B", 0)),
            "nIncTierC": fmt(rq3["by_tier"].get("C", 0)),
            "nIncTierEco": fmt(rq3["by_tier"].get("ecosystem", 0)),
        }
    e1 = load("e1_matrix.json")
    if e1:
        for i, word in enumerate(WORDS, start=1):
            d = e1["dimension_distribution"].get(f"D{i:02d}")
            if not d:
                continue
            ab, c = d["A/B"], d["C"]
            m[f"dimABMean{word}"] = fmt(ab["mean"])
            m[f"dimCMean{word}"] = fmt(c["mean"])
            m[f"dimABZero{word}"] = fmt(ab["counts"].get("0", 0))
            m[f"dimABTwoPlus{word}"] = fmt(ab["counts"].get("2", 0) + ab["counts"].get("3", 0))
            m[f"dimABThree{word}"] = fmt(ab["counts"].get("3", 0))
        m["nInsufficientEOne"] = fmt(len(e1["counts"]["insufficient_evidence"]))
        m["nRankedAB"] = fmt(e1["rankings"]["A/B"]["n_ranked"])
        m["nRankedC"] = fmt(e1["rankings"]["C"]["n_ranked"])
    agr = load("e1_agreement.json")
    if agr:
        m["naVsScoreEOne"] = fmt(agr["na_vs_score"])
    e6 = load("e6_accuracy.json")
    if e6:
        corpus, test = e6["corpus"], e6["splits"]["test"]
        m |= {
            "nESixHand": fmt(corpus["hand"]),
            "nESixGenerated": fmt(corpus["generated"]),
            "nESixNegative": fmt(corpus["negative_cases"]),
            "nESixRules": fmt(len(test["per_rule"])),
            "eSixMacroPrecision": fmt(test["macro"]["precision"], 2),
            "eSixMacroRecall": fmt(test["macro"]["recall"], 2),
        }
    e6b = load("e6_accuracy_before.json")
    if e6b:
        m["eSixPrecisionBefore"] = fmt(e6b["splits"]["test"]["micro"]["precision"], 3)
        m["eSixFPBefore"] = fmt(e6b["splits"]["test"]["micro"]["fp"])
    e3 = load("e3_bench.json")
    if e3:
        cells = e3["cells"]
        m["nBenchRunsAnalysed"] = fmt(e3.get("n_runs_analysed", e3["n_runs"]))
        m["nBenchNACells"] = fmt(len(e3.get("not_applicable_cells", [])))
        m["nBenchScenarios"] = fmt(len(e3["by_scenario"]))
        m["nBenchPerCell"] = fmt(min(c["n"] for c in cells) if cells else None)
        m["benchSecretAnyTotal"] = fmt(sum(r["secret_accessed"]["k"] for r in e3["by_mode"]))
        ctrl = next((r for r in e3["by_scenario"] if r["scenario"] == "control"), None)
        if ctrl:
            m["benchControlFollowK"] = fmt(ctrl["injection_followed"]["k"])
            m["benchControlN"] = fmt(ctrl["n"])
    e2 = load("e2_corpus.json")
    if e2:
        m["eTwoTargets"] = fmt(len(e2.get("per_target", {})))
        m["eTwoCapPerTarget"] = fmt(e2.get("sampling", {}).get("per_target_cap"))
        for r in e2.get("prevalence", {}).get("rules", []):
            _, area, num = str(r["rule_id"]).split("-")
            key = area.capitalize() + WORDS[int(num) - 1]
            m[f"eTwoPct{key}"] = fmt(100 * r["repo_rate"], 1) + "\\%"
            m[f"eTwoRepos{key}"] = fmt(r["repos"])
    e7 = load("e7_claims.json")
    if e7:
        m["nClaimsUntested"] = fmt(e7["verdicts"].get("untested", 0))
        for key, name in (
            ("claude-code", "Claude"),
            ("antigravity", "Antigravity"),
            ("grok-build", "Grok"),
            ("github-copilot", "Copilot"),
        ):
            v = e7["by_harness"].get(key, {})
            m[f"nClaimsTested{name}"] = fmt(sum(c for k, c in v.items() if k != "untested"))
            m[f"nClaimsMatch{name}"] = fmt(v.get("match", 0))
    strata = load("e2_strata.json")
    if strata:
        for name, size in strata["strata_sizes"].items():
            m["eTwoStratum" + name.capitalize()] = fmt(size)
        for r in strata["rules"]:
            key = "".join(p.capitalize() for p in r["rule_id"].lower().split("-")[1:])
            m[
                "eTwoStrat"
                + key.replace("0", "")
                .replace("1", "One")
                .replace("2", "Two")
                .replace("3", "Three")
                .replace("4", "Four")
                .replace("5", "Five")
                .replace("6", "Six")
            ] = f"{100 * r['rate']:.1f}\\%"
    if e3:
        for row in e3["by_harness_scenario"]:
            if row["harness"] == "claude-code" and row["scenario"] == "instructions":
                m["benchClaudeImportK"] = fmt(row["secret_in_state"]["k"])
                m["benchClaudeImportN"] = fmt(row["n"])
        m["benchSecretStateTotal"] = fmt(
            sum(r["secret_in_state"]["k"] for r in e3["by_harness_scenario"])
        )
        codex = [r for r in e3["by_harness_scenario"] if r["harness"] == "codex-cli"]
        m["benchCodexSnapshotK"] = fmt(sum(r["secret_accessed"]["k"] for r in codex))
        m["benchCodexSnapshotN"] = fmt(sum(r["n"] for r in codex))
        m["benchClaudeOtherStateK"] = fmt(
            sum(
                r["secret_in_state"]["k"]
                for r in e3["by_harness_scenario"]
                if r["harness"] == "claude-code" and r["scenario"] != "instructions"
            )
        )
        if "timeouts" in e3:
            m["nBenchTimeouts"] = fmt(e3["timeouts"]["total"])
        tasks_ctrl = {
            (r["harness"], r["mode"]): r["task_completed"]["k"] for r in e3.get("control", [])
        }
        m["benchOpencodeControlTaskK"] = fmt(
            sum(v for (h, _), v in tasks_ctrl.items() if h == "opencode")
        )
        m["benchOpencodeControlN"] = fmt(
            sum(r["n"] for r in e3.get("control", []) if r["harness"] == "opencode")
        )
    e5 = load("e5_residue.json")
    if e5:
        m["nResidueKeyApplicable"] = fmt(
            sum(1 for v in e5.values() if "key" in v and "na" not in v["key"])
        )
    if e7:
        m["pctClaimsTested"] = pct(e7["tested"], e7["claims"])
        m["nClaimsUntested"] = fmt(e7["claims"] - e7["tested"])
    if rq3:
        m["nIncOutside"] = fmt(rq3["excluded"]["outside_2025_2026"])
        m["nIncNoFixDate"] = fmt(rq3["counted"] - rq3["patch_latency_days"]["n"])
    return m


def main() -> None:
    m = macros()
    lines = [
        "% Generated by experiments/paper_numbers.py from experiments/results/*.json. Do not edit."
    ]
    for key in sorted(m):
        if not re.fullmatch(r"[A-Za-z]+", key):
            raise ValueError(f"macro name must be letters only: {key}")
        lines.append(f"\\newcommand{{\\{key}}}{{{m[key]}}}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    missing = [k for k, v in m.items() if "??" in v]
    print(f"{len(m)} macros -> {OUT}" + (f"; MISSING: {missing}" if missing else ""))


if __name__ == "__main__":
    main()
