"""E1 control matrix: scoring rules, means, agreement and writers on a tiny synthetic tree."""

from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

_SPEC = importlib.util.spec_from_file_location(
    "e1_matrix", Path(__file__).resolve().parent.parent / "experiments" / "e1_matrix.py"
)
assert _SPEC and _SPEC.loader
e1 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(e1)

DIMS = [f"D{i:02d}" for i in range(1, 17)]


def _fact(label: str, n: int) -> dict[str, str]:
    return {
        "claim": f"claim {n}",
        "source": f"https://example.test/{label}/{n}",
        "label": label,
        "accessed": "2026-10-15",
    }


def _tree(tmp_path: Path, rater1: dict[str, Any]) -> Path:
    (tmp_path / "matrix" / "evidence").mkdir(parents=True)
    (tmp_path / "rules" / "harness_profiles").mkdir(parents=True)
    rubric = {
        "dimensions": [
            {"id": d, "name": f"Dim {d}", "incident_exposure": 10 + i} for i, d in enumerate(DIMS)
        ]
    }
    (tmp_path / "matrix" / "rubric.yaml").write_text(yaml.safe_dump(rubric))
    for h, tier, status in (("alpha", "A", "analysed"), ("beta", "C", "docs-only")):
        dims = {
            d: {
                "facts": [
                    _fact("from-official-docs", 0),
                    _fact("unverified", 1),
                    _fact("third-party-report", 2),
                    _fact("verified-by-test", 3),
                ]
            }
            for d in DIMS[:15]
        }
        ev = {"harness": h, "version": "1.0", "status": status, "dimensions": dims}
        (tmp_path / "matrix" / "evidence" / f"{h}.json").write_text(json.dumps(ev))
        prof = {"id": h, "name": f"{h.title()} (long name)", "tier": tier, "status": status}
        (tmp_path / "rules" / "harness_profiles" / f"{h}.yaml").write_text(yaml.safe_dump(prof))
    (tmp_path / "rules" / "harness_profiles" / "_SCHEMA.md").write_text("ignored")
    (tmp_path / "matrix" / "scores_rater1.yaml").write_text(yaml.safe_dump(rater1))
    return tmp_path


def _scores(alpha: int | None = 2, beta_scored: int = 15) -> dict[str, Any]:
    def cell(s: int | None) -> dict[str, Any]:
        return {"s": s, "r": "N/A (not documented)." if s is None else "ok", "f": [0, 3]}

    return {
        "rater": "rater1",
        "date": "2026-10-15",
        "scores": {
            "alpha": {d: cell(alpha) for d in DIMS[:15]},
            "beta": {d: cell(1 if i < beta_scored else None) for i, d in enumerate(DIMS[:15])},
        },
        "d16": {"alpha": {"s": 0, "r": "unauthenticated", "f": ["D08.0"]}},
    }


def test_run_writes_every_output(tmp_path: Path) -> None:
    root = _tree(tmp_path, _scores(alpha=2, beta_scored=5))
    res = e1.run(root=root, figure=False)
    rows = list(csv.DictReader((root / "matrix" / "controls.csv").open()))
    assert list(rows[0]) == e1.CSV_COLUMNS
    assert len(rows) == 15 + 1 + 15  # alpha D01-D16, beta D01-D15
    assert res["counts"]["core_na"] == 10
    s = res["summary"]
    assert s["alpha"]["mean"] == 2.0 and s["alpha"]["name"] == "Alpha"
    assert s["beta"]["mean"] is None  # 5 of 15 scored: insufficient evidence
    assert res["counts"]["insufficient_evidence"] == ["beta"]
    assert res["dimension_distribution"]["D16"]["all"]["counts"]["0"] == 1
    na = next(r for r in rows if r["harness"] == "beta" and r["score"] == "N/A")
    assert na["na_reason"].startswith("N/A (")
    for out in (
        "experiments/results/e1_matrix.json",
        "paper/tables/scorecard.tex",
        "paper/tables/scorecard.md",
        "matrix/scorecard.md",
    ):
        assert (root / out).read_text()
    assert not (root / "experiments/results/e1_agreement.json").exists()


def test_tier_c_and_docs_only_never_cite_verified_by_test(tmp_path: Path) -> None:
    root = _tree(tmp_path, _scores())
    e1.run(root=root, figure=False)
    rows = list(csv.DictReader((root / "matrix" / "controls.csv").open()))
    beta = [r for r in rows if r["harness"] == "beta"]
    alpha = [r for r in rows if r["harness"] == "alpha" and r["dimension"] == "D01"]
    assert all("[verified-by-test]" not in r["evidence"] for r in beta)
    assert "[verified-by-test]" in alpha[0]["evidence"]


@pytest.mark.parametrize(
    ("decision", "msg"),
    [
        ({"s": 2, "r": "x", "f": [1]}, "unverified"),
        ({"s": 2, "r": "x", "f": [2]}, "third-party"),
        ({"s": None, "r": "missing reason", "f": [0]}, "N/A"),
        ({"s": 4, "r": "x", "f": [0]}, "0-3"),
        ({"s": 1, "r": "x", "f": [9]}, "does not exist"),
        ({"s": 1, "r": "x", "f": ["D99.0"]}, "does not exist"),
    ],
)
def test_rule_violations_are_rejected(tmp_path: Path, decision: dict[str, Any], msg: str) -> None:
    scores = _scores()
    scores["scores"]["alpha"]["D03"] = decision
    root = _tree(tmp_path, scores)
    with pytest.raises(e1.ScoringError, match=msg):
        e1.run(root=root, figure=False)


def test_third_party_may_accompany_an_eligible_fact(tmp_path: Path) -> None:
    scores = _scores()
    scores["scores"]["alpha"]["D03"] = {"s": 1, "r": "lowered", "f": [0, 2, "D04.0"]}
    root = _tree(tmp_path, scores)
    e1.run(root=root, figure=False)


def test_missing_harness_is_an_error(tmp_path: Path) -> None:
    scores = _scores()
    del scores["scores"]["beta"]
    with pytest.raises(e1.ScoringError, match="beta"):
        e1.run(root=_tree(tmp_path, scores), figure=False)


def test_quadratic_kappa() -> None:
    assert e1.quadratic_weighted_kappa([0, 1, 2, 3], [0, 1, 2, 3]) == 1.0
    assert e1.quadratic_weighted_kappa([], []) is None
    k = e1.quadratic_weighted_kappa([0, 1, 2, 3, 3], [0, 2, 2, 3, 1])
    assert k is not None and 0 < k < 1
    assert e1.quadratic_weighted_kappa([0, 3], [3, 0]) == -1.0


def test_agreement_with_rater2(tmp_path: Path) -> None:
    root = _tree(tmp_path, _scores(alpha=2))
    r2 = _scores(alpha=2)
    r2["scores"]["alpha"]["D01"]["s"] = 3
    r2["scores"]["beta"]["D02"] = {"s": None, "r": "N/A (x)"}
    (root / "matrix" / "scores_rater2.yaml").write_text(yaml.safe_dump(r2))
    res = e1.run(root=root, figure=False)
    agr = json.loads((root / "experiments/results/e1_agreement.json").read_text())
    assert agr["overlapping_scored_cells"] == 29
    assert agr["na_vs_score"] == 1
    assert {(d["harness"], d["dimension"]) for d in agr["disagreements"]} == {
        ("alpha", "D01"),
        ("beta", "D02"),
    }
    assert res["agreement"]["kappa_quadratic"] < 1


def test_rankings_separate_tiers() -> None:
    summary = {
        h: {"tier_group": g, "mean": m, "mean_exposure_weighted": m, "mean_security_core": m}
        for h, g, m in (("a", "A/B", 2.0), ("b", "A/B", 1.0), ("c", "C", 3.0))
    }
    r = e1.rankings(summary, k=1)
    assert r["A/B"]["mean"]["top"] == ["a"] and r["A/B"]["mean"]["bottom"] == ["b"]
    assert r["C"]["mean"]["top"] == ["c"] and r["A/B"]["top_stable"]
