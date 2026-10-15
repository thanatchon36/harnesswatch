"""Offline tests for the E6 metric computation, split rule and placeholder materialisation."""

from __future__ import annotations

import importlib.util
import random
import sys
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "e6_eval", Path(__file__).resolve().parent.parent / "experiments" / "e6_eval.py"
)
e6 = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["e6_eval"] = e6  # dataclasses resolve their module through sys.modules
_spec.loader.exec_module(e6)  # type: ignore[union-attr]


def test_per_rule_and_micro_counts() -> None:
    results = [
        ({"R1"}, {"R1"}),  # R1 TP
        ({"R1", "R2"}, {"R1"}),  # R1 TP, R2 FN
        (set(), {"R2"}),  # R2 FP
        (set(), set()),  # clean negative
        ({"R2"}, {"R2", "R3"}),  # R2 TP, R3 FP
    ]
    m = e6.compute_metrics(results, ["R1", "R2", "R3", "R4"])
    r1, r2, r3, r4 = (m["per_rule"][r] for r in ("R1", "R2", "R3", "R4"))
    assert (r1["tp"], r1["fp"], r1["fn"], r1["support"]) == (2, 0, 0, 2)
    assert (r2["tp"], r2["fp"], r2["fn"], r2["support"]) == (1, 1, 1, 2)
    assert (r3["tp"], r3["fp"], r3["fn"]) == (0, 1, 0)
    assert r1["precision"] == 1.0 and r1["recall"] == 1.0
    assert r2["precision"] == 0.5 and r2["recall"] == 0.5
    assert r3["precision"] == 0.0 and r3["recall"] is None and r3["recall_ci"] is None
    assert r4["precision"] is None and r4["recall"] is None  # never expected, never fired
    micro = m["micro"]
    assert (micro["tp"], micro["fp"], micro["fn"]) == (3, 2, 1)
    assert micro["precision"] == 0.6 and micro["recall"] == 0.75
    assert micro["f1"] == pytest.approx(2 * 0.6 * 0.75 / 1.35, abs=1e-4)
    assert m["n_cases"] == 5


def test_macro_averages_only_defined_rules() -> None:
    m = e6.compute_metrics([({"A"}, {"A"}), (set(), {"B"}), ({"C"}, set())], ["A", "B", "C"])
    # precision defined for A (1.0) and B (0.0); recall for A (1.0) and C (0.0)
    assert m["macro"]["precision"] == 0.5 and m["macro"]["rules_with_precision"] == 2
    assert m["macro"]["recall"] == 0.5 and m["macro"]["rules_with_recall"] == 2


def test_wilson_interval_attached() -> None:
    m = e6.compute_metrics([({"A"}, {"A"})] * 9 + [(set(), {"A"})], ["A"])
    low, high = m["per_rule"]["A"]["precision_ci"]
    assert 0.5 < low < 0.9 < high <= 1.0


def test_unlabelled_rule_still_counted() -> None:
    m = e6.compute_metrics([(set(), {"X-NEW"})], ["A"])
    assert m["per_rule"]["X-NEW"]["fp"] == 1 and m["micro"]["fp"] == 1


def test_split_is_deterministic_and_roughly_40_percent() -> None:
    ids = [f"case-{i}" for i in range(2000)]
    splits = [e6.split_of(i) for i in ids]
    assert splits == [e6.split_of(i) for i in ids]
    share = splits.count("test") / len(splits)
    assert 0.35 < share < 0.45


def test_placeholders_become_synthetic_values() -> None:
    text = 'k = "{{SYNTH:github-token}}" and {{SYNTH:aws-access-key-id}}'
    out = e6.fill_placeholders(text, random.Random(1))  # noqa: S311
    assert "{{SYNTH" not in out and "ghp_" in out and "AKIA" in out
    assert out == e6.fill_placeholders(text, random.Random(1))  # noqa: S311


def test_tables_render(tmp_path: Path) -> None:
    results = [
        e6.CaseResult("a", "test", "hand", "x", frozenset({"R1"}), frozenset({"R1"})),
        e6.CaseResult("b", "dev", "generated", "x", frozenset(), frozenset({"R1"})),
    ]
    summary = e6.summarise(results, ["R1"])
    assert summary["corpus"] == {
        "cases": 2,
        "dev": 1,
        "test": 1,
        "hand": 1,
        "generated": 1,
        "negative_cases": 1,
        "labelled_positives": 1,
    }
    assert summary["splits"]["test"]["micro"]["precision"] == 1.0
    assert summary["splits"]["dev"]["micro"]["fp"] == 1
    assert [e["case"] for e in summary["errors"]] == ["b"]  # only dev errors are listed
    md, tex = e6.render_md(summary), e6.render_tex(summary)
    assert "| HG-" not in md and "| R1 | 1 | 1 | 0 | 0 | 1.00 |" in md
    assert r"\begin{tabular}" in tex and "micro" in tex
