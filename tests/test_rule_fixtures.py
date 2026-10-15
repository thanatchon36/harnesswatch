"""Every rule has `should_fire/` and `should_not_fire/` fixture cases; run them all.

Case layout: tests/fixtures/rules/<RULE-ID>/<should_fire|should_not_fire>/<case>/
  repo/        the repository being audited
  home/        optional fake home directory (user-level config, state dirs)
  case.yaml    optional: {chmod: {relative/path: "0644"}, tools_json: [file], audits: [...]}

Fixture files never contain secret-shaped strings: `{{SYNTH:<kind>}}` placeholders are replaced
with freshly generated synthetic values at test time (keeps gitleaks / push protection quiet).
"""

from __future__ import annotations

import random
import shutil
import string
from pathlib import Path

import pytest
import yaml

from harnesswatch import audits
from harnesswatch.resources import load_profiles
from harnesswatch.rules_engine import load_rules

FIXTURES = Path(__file__).parent / "fixtures" / "rules"
REAL_RULES = Path(__file__).parents[1] / "rules"

AREA_AUDITS = {
    "INJ": ("instructions",),
    "CI": ("ci",),
    "MCP": ("mcp", "config"),
    "PERM": ("config",),
    "HOOK": ("config",),
    "NET": ("config",),
    "TEL": ("config",),
    "MEM": ("config",),
    "SUB": ("config",),
    "SEC": ("config", "secrets"),
    "SUP": ("supply",),
}


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


def materialise(case: Path, dest: Path) -> dict[str, object]:
    shutil.copytree(case, dest)
    rng = random.Random(case.name)  # noqa: S311 - deterministic synthetic fixtures, not crypto
    for path in dest.rglob("*"):
        if path.is_file() and path.suffix not in {".bin"}:
            text = path.read_text(encoding="utf-8")
            while "{{SYNTH:" in text:
                start = text.index("{{SYNTH:")
                end = text.index("}}", start)
                text = text[:start] + synth(text[start + 8 : end], rng) + text[end + 2 :]
            path.write_text(text, encoding="utf-8")
    meta_path = dest / "case.yaml"
    meta: dict[str, object] = yaml.safe_load(meta_path.read_text()) if meta_path.exists() else {}
    for rel, mode in dict(meta.get("chmod", {}) or {}).items():  # type: ignore[call-overload]
        (dest / rel).chmod(int(str(mode), 8))
    for link, target in dict(meta.get("symlinks", {}) or {}).items():  # type: ignore[call-overload]
        (dest / link).parent.mkdir(parents=True, exist_ok=True)
        (dest / link).symlink_to(dest / target)
    return meta or {}


def cases() -> list[tuple[str, str, Path]]:
    out = []
    for rule_dir in sorted(FIXTURES.iterdir()):
        for expect in ("should_fire", "should_not_fire"):
            for case in sorted((rule_dir / expect).glob("*")):
                if case.is_dir():
                    out.append((rule_dir.name, expect, case))
    return out


def ids(value: object) -> str:
    return value.name if isinstance(value, Path) else str(value)


@pytest.mark.real_rules
@pytest.mark.parametrize(("rule_id", "expect", "case"), cases(), ids=ids)
def test_rule_fixture(rule_id: str, expect: str, case: Path, tmp_path: Path) -> None:
    root = tmp_path / "case"
    meta = materialise(case, root)
    repo = root / "repo"
    home = root / "home"
    repo.mkdir(exist_ok=True)
    home.mkdir(exist_ok=True)
    area = rule_id.split("-")[1]
    chosen = tuple(meta.get("audits", AREA_AUDITS[area]))  # type: ignore[arg-type]
    osv = root / str(meta["osv_cache"]) if "osv_cache" in meta else None
    options = audits.AuditOptions(
        repo=repo,
        home=home,
        include_user=True,
        tool_manifests=[root / p for p in meta.get("tools_json", [])],  # type: ignore[attr-defined]
        search_path=str(home / "bin"),
        osv_cache=osv,
    )
    profiles = load_profiles(REAL_RULES / "harness_profiles")
    result = audits.run(chosen, profiles, options, load_rules(REAL_RULES))
    fired = [f for f in result.findings if f.rule_id == rule_id]
    if expect == "should_fire":
        assert fired, (
            f"{rule_id} did not fire on {case.name}; got {[f.rule_id for f in result.findings]}"
        )
        expected_severity = meta.get("severity")
        if expected_severity:
            assert fired[0].severity.value == expected_severity, fired[0]
    else:
        assert not fired, f"{rule_id} fired on {case.name}: {[f.message for f in fired]}"


def test_every_rule_has_both_fixture_kinds() -> None:
    rules = load_rules(REAL_RULES)
    for rule_id in rules:
        for expect in ("should_fire", "should_not_fire"):
            folder = FIXTURES / rule_id / expect
            assert folder.is_dir() and any(folder.iterdir()), (
                f"{rule_id}: missing {expect}/ fixtures"
            )


def test_all_real_profiles_load() -> None:
    profiles = load_profiles(REAL_RULES / "harness_profiles")
    assert len({p.id for p in profiles}) == len(profiles)
