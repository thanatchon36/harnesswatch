"""E6: rule-pack precision and recall on the labelled synthetic config corpus.

Corpus layout (experiments/e6_corpus/cases/<case-id>/):
  repo/        the repository being audited
  home/        fake home directory (user-level config, state dirs)
  label.yaml   {expected: [rule ids that SHOULD fire], origin: hand|generated, family, note}
  case.yaml    optional materialisation metadata, same keys as tests/fixtures/rules:
               {chmod: {rel: "0644"}, symlinks: {link: target}, tools_json: [file], osv_cache: file}

Labels are fixed by how each case was constructed (never by running the tool). Every case runs the
full rule pack (all six audits), so a rule firing on a case whose label does not list it is a false
positive, wherever it comes from. The unit of evaluation is the (case, rule) pair: a rule that fires
several findings on one case counts once.

Hold-out: a case belongs to the `test` split when sha256(case_id) mod 100 >= 60 (≈40 %), else `dev`.
Only the dev split was inspected while fixing rules; test-split metrics are the headline.

Materialisation: `{{SYNTH:<kind>}}` placeholders become fresh synthetic secrets (no real secret is
ever stored in the corpus). Files under home/ default to 0600 (0700 if executable) and directories
to 0700, so permission findings (HG-SEC-002) arise only from a case's explicit `chmod`.

Usage: uv run python experiments/e6_eval.py [--out experiments/results/e6_accuracy.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import string
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from harnesswatch import audits
from harnesswatch.bench.stats import wilson
from harnesswatch.resources import load_profiles
from harnesswatch.rules_engine import load_rules

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "experiments" / "e6_corpus" / "cases"
RULES = ROOT / "rules"
OUT_JSON = ROOT / "experiments" / "results" / "e6_accuracy.json"
OUT_TEX = ROOT / "paper" / "tables" / "e6_accuracy.tex"
OUT_MD = ROOT / "paper" / "tables" / "e6_accuracy.md"
TEST_SHARE = 40  # percent of cases in the held-out test split
# Environment variables that would point profile paths at the real machine.
HOST_ENV = (
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
    "COPILOT_HOME",
    "VIBE_HOME",
    "GROK_HOME",
    "KIMI_CODE_HOME",
    "OPENCODE_CONFIG",
    "OPENCODE_CONFIG_CONTENT",
    "CRUSH_SKILLS_DIR",
)


def split_of(case_id: str) -> str:
    bucket = int(hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:8], 16) % 100
    return "test" if bucket >= 100 - TEST_SHARE else "dev"


# --- synthetic secrets (same kinds and shapes as tests/test_rule_fixtures.py) ----------------


def synth(kind: str, rng: random.Random) -> str:
    alnum = string.ascii_letters + string.digits

    def rand(n: int, alphabet: str = alnum) -> str:
        return "".join(rng.choice(alphabet) for _ in range(n))

    makers = {
        "github-token": lambda: "ghp_" + rand(36),
        "anthropic-api-key": lambda: "sk-ant-api03-" + rand(80, alnum + "-_"),
        "openai-api-key": lambda: "sk-proj-" + rand(48),
        "aws-access-key-id": lambda: "AKIA" + rand(16, string.ascii_uppercase + string.digits),
        "high-entropy": lambda: rand(40),
        "slack-token": lambda: "xoxb-" + rand(12, string.digits) + "-" + rand(24),
    }
    return makers[kind]()


def fill_placeholders(text: str, rng: random.Random) -> str:
    while "{{SYNTH:" in text:
        start = text.index("{{SYNTH:")
        end = text.index("}}", start)
        text = text[:start] + synth(text[start + 8 : end], rng) + text[end + 2 :]
    return text


def materialise(case: Path, dest: Path) -> dict[str, Any]:
    shutil.copytree(case, dest, ignore=shutil.ignore_patterns("label.yaml"))
    rng = random.Random(case.name)
    for path in dest.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if "{{SYNTH:" in text:
                path.write_text(fill_placeholders(text, rng), encoding="utf-8")
    home = dest / "home"
    home.mkdir(exist_ok=True)
    (dest / "repo").mkdir(exist_ok=True)
    for path in [home, *home.rglob("*")]:
        if not path.is_symlink():
            executable = path.is_dir() or bool(path.stat().st_mode & 0o100)
            path.chmod(0o700 if executable else 0o600)
    meta_path = dest / "case.yaml"
    meta: dict[str, Any] = yaml.safe_load(meta_path.read_text()) if meta_path.exists() else {}
    meta = meta or {}
    for rel, mode in dict(meta.get("chmod") or {}).items():
        (dest / rel).chmod(int(str(mode), 8))
    for link, target in dict(meta.get("symlinks") or {}).items():
        (dest / link).parent.mkdir(parents=True, exist_ok=True)
        (dest / link).symlink_to(dest / target)
    return meta


# --- running ---------------------------------------------------------------------------------


@dataclass
class CaseResult:
    case_id: str
    split: str
    origin: str
    family: str
    expected: frozenset[str]
    fired: frozenset[str]


def load_label(case: Path) -> dict[str, Any]:
    data = yaml.safe_load((case / "label.yaml").read_text(encoding="utf-8")) or {}
    expected = data.get("expected") or []
    if not isinstance(expected, list):
        raise ValueError(f"{case.name}: `expected` must be a list")
    data["expected"] = [str(r) for r in expected]
    return data


def run_case(case: Path, rule_pack: dict[str, Any], profiles: tuple[Any, ...]) -> CaseResult:
    label = load_label(case)
    unknown = set(label["expected"]) - set(rule_pack)
    if unknown:
        raise ValueError(f"{case.name}: unknown rule ids in label: {sorted(unknown)}")
    with tempfile.TemporaryDirectory(prefix="e6-") as tmp:
        root = Path(tmp) / "case"
        meta = materialise(case, root)
        repo, home = root / "repo", root / "home"
        options = audits.AuditOptions(
            repo=repo,
            home=home,
            include_user=True,
            tool_manifests=[root / p for p in meta.get("tools_json", [])],
            search_path=str(home / "bin"),
            osv_cache=root / str(meta["osv_cache"]) if "osv_cache" in meta else None,
        )
        result = audits.run(audits.AUDITS, profiles, options, rule_pack)
    return CaseResult(
        case_id=case.name,
        split=split_of(case.name),
        origin=str(label.get("origin", "hand")),
        family=str(label.get("family", "")),
        expected=frozenset(label["expected"]),
        fired=frozenset(f.rule_id for f in result.findings),
    )


def run_corpus(corpus: Path = CORPUS) -> tuple[list[CaseResult], list[str]]:
    for var in HOST_ENV:
        os.environ.pop(var, None)
    rule_pack = load_rules(RULES)
    profiles = load_profiles(RULES / "harness_profiles")
    cases = sorted(p for p in corpus.iterdir() if (p / "label.yaml").is_file())
    return [run_case(c, rule_pack, profiles) for c in cases], sorted(rule_pack)


# --- metrics ---------------------------------------------------------------------------------


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _ci(num: int, den: int) -> list[float] | None:
    return [round(x, 4) for x in wilson(num, den)] if den else None


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


def compute_metrics(
    results: Iterable[tuple[frozenset[str] | set[str], frozenset[str] | set[str]]],
    rule_ids: Iterable[str],
) -> dict[str, Any]:
    """Per-rule and pooled metrics over (expected, fired) pairs, one pair per case.

    Precision = TP/(TP+FP) and recall = TP/(TP+FN) with Wilson 95 % CIs; undefined (None) when the
    denominator is zero. Micro pools the counts of all rules; macro averages the per-rule values
    over the rules where each is defined.
    """
    rules = sorted(set(rule_ids))
    counts = {r: {"tp": 0, "fp": 0, "fn": 0, "support": 0} for r in rules}
    n_cases = 0
    for expected, fired in results:
        n_cases += 1
        for rule in set(expected) | set(fired):
            row = counts.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0, "support": 0})
            if rule in expected:
                row["support"] += 1
                row["tp" if rule in fired else "fn"] += 1
            else:
                row["fp"] += 1
    per_rule: dict[str, dict[str, Any]] = {}
    for rule, c in sorted(counts.items()):
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        per_rule[rule] = {
            **c,
            "precision": _round(_ratio(tp, tp + fp)),
            "precision_ci": _ci(tp, tp + fp),
            "recall": _round(_ratio(tp, tp + fn)),
            "recall_ci": _ci(tp, tp + fn),
        }
    tp = sum(c["tp"] for c in counts.values())
    fp = sum(c["fp"] for c in counts.values())
    fn = sum(c["fn"] for c in counts.values())
    precisions = [v["precision"] for v in per_rule.values() if v["precision"] is not None]
    recalls = [v["recall"] for v in per_rule.values() if v["recall"] is not None]
    micro_p, micro_r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if micro_p and micro_r else None
    return {
        "n_cases": n_cases,
        "micro": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": _round(micro_p),
            "precision_ci": _ci(tp, tp + fp),
            "recall": _round(micro_r),
            "recall_ci": _ci(tp, tp + fn),
            "f1": _round(f1),
        },
        "macro": {
            "precision": _round(sum(precisions) / len(precisions)) if precisions else None,
            "recall": _round(sum(recalls) / len(recalls)) if recalls else None,
            "rules_with_precision": len(precisions),
            "rules_with_recall": len(recalls),
        },
        "per_rule": per_rule,
    }


def summarise(results: list[CaseResult], rule_ids: list[str]) -> dict[str, Any]:
    splits: dict[str, Any] = {}
    for name in ("test", "dev", "all"):
        chosen = [r for r in results if name == "all" or r.split == name]
        splits[name] = compute_metrics(((r.expected, r.fired) for r in chosen), rule_ids)
    return {
        "experiment": "E6",
        "unit": "(case, rule) pair; all audits run on every case",
        "split_rule": f"sha256(case_id) mod 100 >= {100 - TEST_SHARE} -> test",
        "corpus": {
            "cases": len(results),
            "dev": sum(r.split == "dev" for r in results),
            "test": sum(r.split == "test" for r in results),
            "hand": sum(r.origin == "hand" for r in results),
            "generated": sum(r.origin == "generated" for r in results),
            "negative_cases": sum(not r.expected for r in results),
            "labelled_positives": sum(len(r.expected) for r in results),
        },
        "splits": splits,
        "errors": [
            {
                "case": r.case_id,
                "split": r.split,
                "false_positives": sorted(r.fired - r.expected),
                "false_negatives": sorted(r.expected - r.fired),
            }
            for r in results
            if r.fired != r.expected and r.split == "dev"
        ],
        "test_error_counts": {
            "cases_with_errors": sum(r.fired != r.expected for r in results if r.split == "test")
        },
    }


# --- tables ----------------------------------------------------------------------------------


def _fmt(value: float | None) -> str:
    return "--" if value is None else f"{value:.2f}"


def _fmt_ci(ci: list[float] | None) -> str:
    return "" if ci is None else f"[{ci[0]:.2f}, {ci[1]:.2f}]"


def table_rows(split: dict[str, Any]) -> list[list[str]]:
    rows = []
    for rule, m in split["per_rule"].items():
        rows.append(
            [
                rule,
                str(m["support"]),
                str(m["tp"]),
                str(m["fp"]),
                str(m["fn"]),
                _fmt(m["precision"]),
                _fmt_ci(m["precision_ci"]),
                _fmt(m["recall"]),
                _fmt_ci(m["recall_ci"]),
            ]
        )
    mi, ma = split["micro"], split["macro"]
    rows.append(
        [
            "micro",
            str(mi["tp"] + mi["fn"]),
            str(mi["tp"]),
            str(mi["fp"]),
            str(mi["fn"]),
            _fmt(mi["precision"]),
            _fmt_ci(mi["precision_ci"]),
            _fmt(mi["recall"]),
            _fmt_ci(mi["recall_ci"]),
        ]
    )
    rows.append(["macro", "", "", "", "", _fmt(ma["precision"]), "", _fmt(ma["recall"]), ""])
    return rows


HEADER = ["Rule", "Support", "TP", "FP", "FN", "Precision", "95% CI", "Recall", "95% CI"]


def render_md(summary: dict[str, Any]) -> str:
    c, test = summary["corpus"], summary["splits"]["test"]
    lines = [
        "<!-- generated by experiments/e6_eval.py; do not edit -->",
        f"**E6 rule-pack accuracy, held-out test split** ({test['n_cases']} of {c['cases']} "
        f"cases; {c['hand']} hand-crafted, {c['generated']} generated). Unit: (case, rule) pair; "
        "Wilson 95% CIs.",
        "",
        "| " + " | ".join(HEADER) + " |",
        "|" + "|".join("---" if i == 0 else "--:" for i in range(len(HEADER))) + "|",
    ]
    for row in table_rows(test):
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def _tex(text: str) -> str:
    return text.replace("_", r"\_").replace("%", r"\%")


def render_tex(summary: dict[str, Any]) -> str:
    c, test = summary["corpus"], summary["splits"]["test"]
    body = []
    for row in table_rows(test):
        if row[0] == "micro":
            body.append(r"\midrule")
        cells = [_tex(x) if x else "" for x in row]
        cells[0] = r"\texttt{" + cells[0] + "}" if cells[0].startswith("HG-") else cells[0]
        body.append(" & ".join(cells) + r" \\")
    return (
        "% generated by experiments/e6_eval.py; do not edit\n"
        r"\begin{table}[t]" + "\n"
        r"\centering\scriptsize\setlength{\tabcolsep}{2.5pt}" + "\n"
        r"\caption{E6 rule-pack accuracy on the held-out test split of the synthetic corpus ("
        + f"{test['n_cases']} of {c['cases']} cases, {c['hand']} hand-crafted). Unit: "
        r"(case, rule) pair; 95\% Wilson intervals.}" + "\n"
        r"\label{tab:e6-accuracy}" + "\n"
        r"\begin{tabular}{lrrrrrlrl}" + "\n"
        r"\toprule" + "\n" + " & ".join(_tex(h) for h in HEADER) + r" \\" + "\n"
        r"\midrule" + "\n" + "\n".join(body) + "\n"
        r"\bottomrule" + "\n"
        r"\end{tabular}" + "\n"
        r"\end{table}" + "\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=OUT_JSON)
    parser.add_argument("--no-tables", action="store_true", help="only write the JSON")
    args = parser.parse_args(argv)
    results, rule_ids = run_corpus()
    summary = summarise(results, rule_ids)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if not args.no_tables:
        OUT_TEX.parent.mkdir(parents=True, exist_ok=True)
        OUT_TEX.write_text(render_tex(summary), encoding="utf-8")
        OUT_MD.write_text(render_md(summary), encoding="utf-8")
    c = summary["corpus"]
    print(f"cases={c['cases']} dev={c['dev']} test={c['test']} hand={c['hand']}")
    for name in ("dev", "test"):
        m = summary["splits"][name]["micro"]
        print(
            f"{name}: P={m['precision']} {m['precision_ci']} R={m['recall']} {m['recall_ci']} "
            f"(tp={m['tp']} fp={m['fp']} fn={m['fn']})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
