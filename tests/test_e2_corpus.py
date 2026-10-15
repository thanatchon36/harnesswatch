"""Offline tests for the E2 corpus aggregation and identifier scrubbing (fake data only)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "e2_corpus", Path(__file__).resolve().parent.parent / "experiments" / "e2_corpus.py"
)
e2 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e2)  # type: ignore[union-attr]


def test_hash_id_salted_and_stable() -> None:
    a = e2.hash_id(b"s1", "own/repo")
    assert a == e2.hash_id(b"s1", "own/repo")
    assert a != e2.hash_id(b"s2", "own/repo")
    assert "own" not in a and len(a) == 64
    assert e2.hash_id(b"s", "a", "bc") != e2.hash_id(b"s", "ab", "c")


def test_path_matches_and_safe_relpath() -> None:
    assert e2.path_matches(".mcp.json", ".mcp.json")
    assert not e2.path_matches("sub/.mcp.json", ".mcp.json")
    assert e2.path_matches(".github/workflows/ci.yml", ".github/workflows/")
    assert e2.safe_relpath("../etc/passwd") is None
    assert e2.safe_relpath("/abs") is None
    assert e2.safe_relpath(".claude/settings.json") == ".claude/settings.json"


def test_reduce_findings_drops_messages() -> None:
    rep = {
        "findings": [
            {
                "rule_id": "R1",
                "title": "T1",
                "message": "secret-xyz",
                "evidence": "e",
                "location": {"path": "a.json"},
            },
            {"rule_id": "R1", "title": "T1", "location": {"path": "a.json"}},
            {"rule_id": "R2", "title": "T2", "location": {"path": "b.json"}},
        ]
    }
    pairs, titles = e2.reduce_findings(rep)
    assert pairs == {("R1", "a.json"), ("R2", "b.json")}
    assert titles == {"R1": "T1", "R2": "T2"}
    assert "secret-xyz" not in json.dumps([sorted(pairs), titles])


def test_aggregate_counts_and_ci() -> None:
    repos = [
        {"files": 2, "fired": {("R1", "a"), ("R1", "b"), ("R2", "a")}, "titles": {"R1": "t"}},
        {"files": 1, "fired": {("R1", "a")}, "titles": {}},
        {"files": 1, "fired": set(), "titles": {}},
    ]
    agg = e2.aggregate(repos)
    assert agg["repos_audited"] == 3 and agg["files_audited"] == 4
    r1 = next(r for r in agg["rules"] if r["rule_id"] == "R1")
    assert (r1["repos"], r1["files"]) == (2, 3)
    assert r1["repo_ci95"][0] < 2 / 3 < r1["repo_ci95"][1]
    assert agg["rules"][0]["rule_id"] == "R1"  # sorted by prevalence


def test_aggregate_empty() -> None:
    agg = e2.aggregate([])
    assert agg == {"repos_audited": 0, "files_audited": 0, "rules": []}


def test_scrub_check() -> None:
    e2.scrub_check({"a": "clean"}, {"own/repo", "own", "repo"})
    with pytest.raises(ValueError):
        e2.scrub_check({"a": "see Own/Repo"}, {"own/repo"})
    with pytest.raises(ValueError):
        e2.scrub_check({"a": "https://github.com/x"}, set())
    assert e2.identifiers_of("o/r") == {"o/r", "o", "r"}


def test_renderers() -> None:
    res = {
        "query_date": "d",
        "prevalence": e2.aggregate(
            [{"files": 1, "fired": {("HG_X", "a")}, "titles": {"HG_X": "A & B"}}]
        ),
    }
    assert "HG_X" in e2.render_md(res)
    tex = e2.render_tex(res)
    assert r"HG\_X" in tex and r"A \& B" in tex
