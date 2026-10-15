import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from harnesswatch import audits
from harnesswatch.cli import app
from harnesswatch.models import Severity
from harnesswatch.report import apply_baseline, load_json, summary, to_json, to_markdown, to_sarif
from harnesswatch.resources import load_profiles
from harnesswatch.rules_engine import at_or_above, load_rules

ROOT = Path(__file__).parents[1]
DEMO = Path(__file__).parent / "data" / "repo_demo"
GOLDEN = Path(__file__).parent / "golden"
runner = CliRunner()


@pytest.fixture
def real(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("HARNESSWATCH_RULES_DIR", str(ROOT / "rules"))
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


def _demo_findings() -> list:
    result = audits.run(
        audits.REPO_AUDITS,
        load_profiles(ROOT / "rules" / "harness_profiles"),
        audits.AuditOptions(repo=DEMO, include_user=False),
        load_rules(ROOT / "rules"),
    )
    return result.findings


def test_demo_repo_findings() -> None:
    ids = {f.rule_id for f in _demo_findings()}
    assert {
        "HG-PERM-001",
        "HG-PERM-002",
        "HG-HOOK-001",
        "HG-HOOK-002",
        "HG-MCP-001",
        "HG-MCP-005",
        "HG-INJ-002",
        "HG-CI-001",
        "HG-CI-002",
    } <= ids


def test_sarif_golden() -> None:
    # Regenerated for the code-review fixes (reports/CODE_REVIEW.md): M10 changed every
    # `partialFingerprints` value (rule + path + stable subject key, no line or message text),
    # M7 added `uriBaseId`/`originalUriBaseIds`, and M5 added `invocations` with
    # `toolExecutionNotifications`. Findings, rules and levels are unchanged.
    sarif = to_sarif(_demo_findings(), load_rules(ROOT / "rules"))
    sarif["runs"][0]["tool"]["driver"]["version"] = "TEST"
    text = json.dumps(sarif, indent=2, sort_keys=True) + "\n"
    golden = GOLDEN / "demo.sarif.json"
    if not golden.exists():  # first run writes the golden file; review it before committing
        golden.write_text(text)
    assert text == golden.read_text()
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert all(r["ruleIndex"] < len(run["tool"]["driver"]["rules"]) for r in run["results"])


def test_json_markdown_baseline_roundtrip(tmp_path: Path) -> None:
    findings = _demo_findings()
    path = tmp_path / "r.json"
    path.write_text(to_json(findings, [("x", "warn")], {"files": 1}))
    loaded = load_json(path)
    assert [f.fingerprint for f in loaded] == [f.fingerprint for f in findings]
    assert apply_baseline(findings, loaded) == []
    md = to_markdown(findings)
    assert "| Severity |" in md and "## Remediation" in md
    assert "No findings." in to_markdown([])
    assert summary(findings)["critical"] >= 1
    assert at_or_above(findings, Severity.CRITICAL)


@pytest.mark.real_rules
def test_cli_audit_repo_formats(real: Path, tmp_path: Path) -> None:
    result = runner.invoke(app, ["audit", "repo", str(DEMO)])
    assert result.exit_code == 1  # findings at/above high
    for fmt in ("json", "sarif", "markdown"):
        out = tmp_path / f"r.{fmt}"
        result = runner.invoke(
            app, ["audit", "repo", str(DEMO), "-f", fmt, "-o", str(out), "--fail-on", "critical"]
        )
        assert result.exit_code == 1, result.output
        assert out.read_text()
    base = tmp_path / "r.json"
    result = runner.invoke(app, ["audit", "repo", str(DEMO), "--baseline", str(base), "-f", "json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["findings"] == []
    merged = runner.invoke(app, ["report", str(base), "-f", "markdown"])
    assert "HG-CI-001" in merged.stdout


@pytest.mark.real_rules
@pytest.mark.parametrize(
    "args",
    [
        ["audit", "config", "{demo}", "--no-user"],
        ["audit", "mcp", "{demo}", "--no-user"],
        ["audit", "instructions", "{demo}"],
        ["audit", "ci", "{demo}"],
        ["audit", "secrets"],
        ["audit", "supply", "--sbom", "{tmp}/sbom.json"],
        ["audit", "all", "{demo}"],
    ],
)
def test_cli_commands_run(real: Path, tmp_path: Path, args: list[str]) -> None:
    argv = [a.format(demo=DEMO, tmp=tmp_path) for a in args]
    result = runner.invoke(app, [*argv, "-f", "json"])
    assert result.exit_code in (0, 1), result.output
    json.loads(result.stdout)
    if "--sbom" in argv:
        assert json.loads((tmp_path / "sbom.json").read_text())["bomFormat"] == "CycloneDX"


@pytest.mark.real_rules
def test_cli_rich_output_and_errors(real: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad"
    (bad / ".claude").mkdir(parents=True)
    (bad / ".claude" / "settings.json").write_text("{not json")
    result = runner.invoke(app, ["audit", "config", str(bad), "--no-user"], env={"COLUMNS": "200"})
    assert result.exit_code == 0
    assert "warning" in result.stdout
    clean = runner.invoke(app, ["audit", "ci", str(tmp_path)])
    assert "No findings" in clean.stdout
