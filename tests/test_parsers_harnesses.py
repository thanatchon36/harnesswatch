"""Per-harness parser coverage: each listed harness has a realistic config fixture.

Layout: tests/fixtures/parsers/<harness-id>/{repo/,home/,expect.yaml}
`expect.yaml` keys (all optional except one of `expect: none` or the checks below):
  mcp_servers: [names]        exact set of MCP server names parse_all must produce for the id
  auto_approve: bool          any config has non-empty auto_approve_matches, or a permission_mode
                              equal to one of the profile's auto-approve values
  hooks: N                    at least N hooks
  instruction_files: [paths]  repo-relative files the instruction scanner attributes to the id
  expect: none                the harness has no parseable config format; a comment says why.
                              parse_all must then yield no configs for the id.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from harnesswatch.audits import instructions
from harnesswatch.parsers import generic, parse_all
from harnesswatch.parsers.loaders import get_all
from harnesswatch.resources import load_profiles

FIXTURES = Path(__file__).parent / "fixtures" / "parsers"
REAL_RULES = Path(__file__).parents[1] / "rules"

# Definition of done: every Tier-A harness + Claude Code + Antigravity + Grok Build + Cursor +
# Copilot + Kiro. Adding to this list requires a fixture; removing needs a deliberate edit here.
HARNESSES = (
    "opencode",
    "codex-cli",
    "deepseek-harness",
    "pi",
    "oh-my-pi",
    "cline",
    "roo-code",
    "kilo-code",
    "aider",
    "openhands",
    "goose",
    "continue",
    "qwen-code",
    "kimi-cli",
    "mistral-vibe",
    "hermes-agent",
    "openclaw",
    "gemini-cli",
    "warp",
    "crush",
    "claude-code",
    "antigravity",
    "grok-build",
    "cursor",
    "github-copilot",
    "kiro",
)


def test_every_listed_harness_has_a_fixture() -> None:
    on_disk = {p.name for p in FIXTURES.iterdir() if p.is_dir()}
    assert set(HARNESSES) <= on_disk, f"missing fixtures: {sorted(set(HARNESSES) - on_disk)}"
    assert on_disk <= set(HARNESSES), (
        f"fixtures not in HARNESSES: {sorted(on_disk - set(HARNESSES))}"
    )
    for harness in HARNESSES:
        assert (FIXTURES / harness / "expect.yaml").is_file(), harness
        assert any((FIXTURES / harness / side).is_dir() for side in ("repo", "home")), harness


def test_listed_harnesses_have_profiles() -> None:
    ids = {p.id for p in load_profiles(REAL_RULES / "harness_profiles")}
    assert set(HARNESSES) <= ids


@pytest.mark.real_rules
@pytest.mark.parametrize("harness", HARNESSES)
def test_harness_config_parses(
    harness: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    root = tmp_path / "case"
    shutil.copytree(FIXTURES / harness, root)
    repo, home = root / "repo", root / "home"
    repo.mkdir(exist_ok=True)
    home.mkdir(exist_ok=True)
    expect: dict[str, Any] = yaml.safe_load((root / "expect.yaml").read_text())
    profiles = load_profiles(REAL_RULES / "harness_profiles")
    profile = next(p for p in profiles if p.id == harness)

    result = parse_all(profiles, repo, home=home, include_user=True)
    assert result.errors == [], result.errors
    configs = [c for c in result.configs if c.harness == harness]

    if expect.get("expect") == "none":
        assert configs == [], [c.source.path for c in configs]
    else:
        servers = {s.name for c in configs for s in c.mcp_servers}
        assert servers == set(expect["mcp_servers"]), (servers, [c.source.path for c in configs])
        auto_values = {
            str(item.value).lower()
            for item in (profile.permissions.auto_approve_values if profile.permissions else [])
        }
        auto = any(
            c.auto_approve_matches
            or (c.permission_mode is not None and c.permission_mode.lower() in auto_values)
            for c in configs
        )
        assert auto is expect["auto_approve"], [
            (c.source.path, c.permission_mode, c.auto_approve_matches) for c in configs
        ]
        hooks = [h for c in configs for h in c.hooks]
        assert len(hooks) >= expect["hooks"], hooks
        assert all(h.command.strip() for h in hooks)
        assert all(s.command or s.url for c in configs for s in c.mcp_servers)

    wanted = expect.get("instruction_files", [])
    if wanted:
        docs = instructions.collect(repo, profiles, include_user=True, home=home)
        found = {d.path for d in docs if harness in d.harnesses}
        assert set(wanted) <= found, (wanted, found)


def test_non_empty_list_and_string_bool_auto_approve_values() -> None:
    """Profiles spell some values as prose/strings; list and bool config values must match them."""
    profiles = load_profiles(REAL_RULES / "harness_profiles")
    roo = next(p for p in profiles if p.id == "roo-code")
    assert generic.auto_approve(roo, {"mcpServers": {"s": {"alwaysAllow": ["*"]}}})
    assert not generic.auto_approve(roo, {"mcpServers": {"s": {"alwaysAllow": ["read_file"]}}})
    vibe = next(p for p in profiles if p.id == "mistral-vibe")
    assert generic.auto_approve(vibe, {"bypass_tool_permissions": True})
    assert not generic.auto_approve(vibe, {"bypass_tool_permissions": False})
    assert get_all({"a": {"b": 1}}, "a.b") == [1]


def test_json5_and_dotted_hook_fields() -> None:
    from harnesswatch.parsers.loaders import parse_text

    data = parse_text("{ a: { 'b': [1, 2,], // c\n c: \"x:y\" } }", "jsonc")
    assert data == {"a": {"b": [1, 2], "c": "x:y"}}
    profiles = load_profiles(REAL_RULES / "harness_profiles")
    kiro = next(p for p in profiles if p.id == "kiro")
    from harnesswatch.models import Location, Scope

    found = generic.hooks(
        kiro,
        {"hooks": [{"name": "g", "action": {"type": "command", "command": "./g.sh"}}]},
        Location(path="x"),
        Scope.PROJECT,
        whole_file=True,
    )
    assert [h.command for h in found] == ["./g.sh"]
