"""Locate bundled data (rules, harness profiles) and load harness profiles."""

from __future__ import annotations

import os
import re
import stat
from functools import cache
from pathlib import Path

from harnesswatch.models import HarnessProfile
from harnesswatch.parsers.loaders import load_yaml

_PACKAGE_DIR = Path(__file__).resolve().parent


def rules_dir() -> Path:
    """Return the rules directory: bundled copy in a wheel, else the source checkout."""
    override = os.environ.get("HARNESSWATCH_RULES_DIR")
    if override:
        return Path(override)
    bundled = _PACKAGE_DIR / "_data" / "rules"
    if bundled.is_dir():
        return bundled
    return _PACKAGE_DIR.parents[1] / "rules"


def load_profiles(directory: Path | None = None) -> tuple[HarnessProfile, ...]:
    """Load every `harness_profiles/*.yaml` (files starting with `_` are documentation)."""
    return _load_profiles(directory or rules_dir() / "harness_profiles")


@cache
def _load_profiles(base: Path) -> tuple[HarnessProfile, ...]:
    profiles = []
    for path in sorted(base.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        data = load_yaml(path.read_text(encoding="utf-8"))
        profiles.append(HarnessProfile.model_validate(data))
    return tuple(profiles)


def expand_user_path(pattern: str, home: Path | None = None) -> Path:
    """Expand `~` and `$XDG_CONFIG_HOME` (defaulting to ~/.config) in a profile path.

    An explicit `home` other than the real one (a test or fixture home) also isolates
    `$XDG_CONFIG_HOME`, which would otherwise still point into the real user's config.
    """
    real = home is None or home == Path.home()
    home = home or Path.home()
    xdg = (os.environ.get("XDG_CONFIG_HOME") if real else None) or str(home / ".config")
    pattern = pattern.replace("$XDG_CONFIG_HOME", xdg).replace("${XDG_CONFIG_HOME}", xdg)
    if pattern == "~" or pattern.startswith("~/"):
        pattern = str(home) + pattern[1:]
    return Path(pattern)


def is_user_path(pattern: str) -> bool:
    return pattern.startswith(("~", "$XDG_CONFIG_HOME", "${XDG_CONFIG_HOME}", "/"))


def repo_file_problem(path: Path, repo: Path, *, directory: bool = False) -> str | None:
    """Why a repository path must not be read, or None when it is safe.

    Symlinks may point anywhere on the runner (`AGENTS.md -> ~/.ssh/id_rsa`, `.clinerules -> /`),
    so a path is read only when it resolves inside the repository, and only regular files are read
    (a FIFO or device would block or never end).
    """
    try:
        resolved = path.resolve()
        mode = resolved.stat().st_mode
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop
        return f"unreadable: {exc}"
    if not resolved.is_relative_to(repo.resolve()):
        return "symlink to a location outside the repository; skipped"
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        return "not a regular file; skipped"
    return None


def glob_base(pattern: str, root: Path, home: Path | None = None) -> Path:
    """The fixed (non-glob) leading part of a profile path pattern."""
    path = expand_user_path(pattern, home) if is_user_path(pattern) else root / pattern
    parts = path.parts
    split = next((i for i, part in enumerate(parts) if any(ch in part for ch in "*?[")), None)
    return path if split is None else Path(*parts[:split])


def glob_paths(pattern: str, root: Path, home: Path | None = None) -> list[Path]:
    """Resolve a profile path pattern (user- or repo-relative, may contain globs)."""
    path = expand_user_path(pattern, home) if is_user_path(pattern) else root / pattern
    text = str(path)
    if not any(ch in text for ch in "*?["):
        return [path] if _exists_exact(path) else []
    parts = path.parts
    split = next(i for i, part in enumerate(parts) if any(ch in part for ch in "*?["))
    base = Path(*parts[:split])
    if not base.is_dir():
        return []
    rest = "/".join(parts[split:])
    if "**" in rest:
        return _walk_glob(base, rest)
    return sorted(p for p in base.glob(rest) if p.exists())


def _exists_exact(path: Path) -> bool:
    """`exists()` that also matches the file name's case, so a scan on a case-insensitive
    filesystem (macOS) does not report `AGENTS.md` again as `agents.md`."""
    if not path.exists():
        return False
    try:
        return path.name in os.listdir(path.parent)
    except OSError:
        return True


PRUNE_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", "target"}
)


def _glob_regex(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def _walk_glob(base: Path, pattern: str) -> list[Path]:
    """Recursive glob that skips vendored/VCS directories (they can be huge)."""
    regex = _glob_regex(pattern)
    matches = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
        rel_dir = Path(dirpath).relative_to(base).as_posix()
        for name in filenames + dirnames:
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if regex.match(rel):
                matches.append(Path(dirpath) / name)
    return sorted(matches)
