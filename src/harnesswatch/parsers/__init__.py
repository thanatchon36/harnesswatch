"""Parse every supported harness's config files into the common `HarnessConfig` schema."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harnesswatch.models import HarnessConfig, HarnessProfile
from harnesswatch.parsers import generic
from harnesswatch.parsers.loaders import ConfigParseError, load_file

# Files read by several harnesses are parsed once, with the semantics of the harness that defines
# the format. Other profiles that "import" these files (Agent SDKs, Devin, oh-my-pi, Grok Build…)
# would otherwise re-read them with partial key maps and report contradictory findings.
OWNERS: tuple[tuple[str, str], ...] = (
    # Warp's own MCP files would otherwise match the generic `.mcp.json` (Claude Code) entry.
    (".warp/", "warp"),
    (".agents/.mcp.json", "warp"),
    (".claude/", "claude-code"),
    (".claude.json", "claude-code"),
    (".mcp.json", "claude-code"),
    (".cursor/", "cursor"),
    (".codex/", "codex-cli"),
    # Antigravity keeps its files under ~/.gemini/ too; these must precede the gemini-cli prefix.
    (".gemini/antigravity", "antigravity"),  # antigravity/, antigravity-cli/, -ide/, -backup/
    (".gemini/config/", "antigravity"),
    (".gemini/config.json", "antigravity"),
    (".gemini/", "gemini-cli"),
    (".qwen/", "qwen-code"),
    (".vscode/", "github-copilot"),
    (".github/", "github-copilot"),
    (".kiro/", "kiro"),
    (".windsurf/", "windsurf"),
    (".roo/", "roo-code"),
    (".continue/", "continue"),
    ("opencode.json", "opencode"),
    (".opencode/", "opencode"),
)


def owner(display: str) -> str | None:
    """Harness that defines the format of a (repo- or home-relative) config path."""
    rel = display.removeprefix("~/")
    for prefix, harness in OWNERS:
        if rel == prefix.rstrip("/") or rel.startswith(prefix) or ("/" + prefix) in ("/" + rel):
            return harness
    return None


@dataclass
class ParseResult:
    configs: list[HarnessConfig] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (path, message)
    raw: dict[str, Any] = field(default_factory=dict)  # display path -> parsed data


def parse_all(
    profiles: tuple[HarnessProfile, ...],
    repo: Path | None,
    *,
    home: Path | None = None,
    include_user: bool = True,
) -> ParseResult:
    from harnesswatch.resources import is_user_path, repo_file_problem  # avoids an import cycle

    home = home or Path.home()
    result = ParseResult()
    seen: set[tuple[str, Path]] = set()
    present = {p.id for p in profiles}
    for profile in profiles:
        for spec, path, display in generic.find_files(profile, repo, home, include_user):
            if (profile.id, path) in seen:
                continue
            native = owner(display)
            if native is not None and native != profile.id and native in present:
                continue
            seen.add((profile.id, path))
            problem = (
                repo_file_problem(path, repo)
                if repo is not None and not is_user_path(spec.path)
                else None
            )
            if problem:
                if (display, problem) not in result.errors:
                    result.errors.append((display, problem))
                continue
            try:
                data = load_file(path, spec.format)
            except (ConfigParseError, OSError) as exc:
                result.errors.append((display, str(exc)[:200]))
                continue
            result.raw[display] = data
            result.configs.append(generic.parse(profile, spec, data, display))
    return result
