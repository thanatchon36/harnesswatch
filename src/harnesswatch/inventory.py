"""Detect installed harnesses on this machine and harness config present in a repository.

Read-only: never prints secrets, never reads credential file contents. Harness binaries are
executed (`--version`) only when explicitly requested.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from harnesswatch.models import HarnessProfile, Scope
from harnesswatch.resources import glob_paths, is_user_path

_VERSION_RE = re.compile(r"\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.]+)?")


class BinaryInfo(BaseModel):
    name: str
    path: str
    resolved: str
    install_method: str
    version: str | None = None


class PathInfo(BaseModel):
    path: str
    mode: str
    group_readable: bool
    world_readable: bool


class InventoryItem(BaseModel):
    harness: str
    name: str
    binaries: list[BinaryInfo] = Field(default_factory=list)
    state_dirs: list[PathInfo] = Field(default_factory=list)
    credential_files: list[PathInfo] = Field(default_factory=list)
    repo_files: list[str] = Field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.binaries or self.state_dirs or self.repo_files)


def classify_install(resolved: Path) -> str:
    """Guess the install channel from where the binary really lives."""
    text = resolved.as_posix()
    if "/node_modules/" in text:
        return "npm"
    if "/Cellar/" in text or "/homebrew/" in text or "/linuxbrew/" in text:
        return "homebrew"
    if "/.cargo/bin/" in text:
        return "cargo"
    if "/go/bin/" in text:
        return "go"
    if "/pipx/" in text or "/uv/tools/" in text or "/site-packages/" in text:
        return "pip"
    if "/.local/share/" in text and "/versions/" in text:
        return "native-installer"
    if "/snap/" in text:
        return "snap"
    if _shebang_python(resolved):
        return "pip"
    return "unknown"


def _shebang_python(path: Path) -> Path | None:
    try:
        with path.open("rb") as handle:
            first = handle.readline(512)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    interpreter = first[2:].strip().split(b" ")[0].decode(errors="ignore")
    return Path(interpreter) if "python" in interpreter else None


def static_version(resolved: Path, profile: HarnessProfile) -> str | None:
    """Find a version without executing anything: path names, package.json, dist-info."""
    match = _VERSION_RE.fullmatch(resolved.name)
    if match:
        return match.group(0)
    # Only the harness's own manifest counts: a dotfiles `~/package.json` or a `dist/package.json`
    # holding just `{"type": "module"}` must neither win nor stop the search.
    npm_names = {
        str(p.get("name"))
        for p in profile.packages
        if p.get("ecosystem") == "npm" and p.get("name")
    }
    for parent in resolved.parents:
        if parent == Path.home():
            break
        manifest = parent / "package.json"
        if manifest.is_file():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = None
            ours = not npm_names or (isinstance(data, dict) and data.get("name") in npm_names)
            if ours and isinstance(data, dict) and data.get("version"):
                return str(data["version"])
        if parent.name == "node_modules":
            break
    interpreter = _shebang_python(resolved)
    if interpreter is not None:
        names = {
            str(p.get("name", "")).lower().replace("-", "_")
            for p in profile.packages
            if p.get("ecosystem") in {"pypi", "pip"}
        }
        venv = interpreter.parent.parent
        for dist_info in venv.glob("lib/python*/site-packages/*.dist-info"):
            name, _, version = dist_info.name.removesuffix(".dist-info").rpartition("-")
            if name.lower() in names:
                return version
    return None


def exec_version(binary: Path, timeout: float = 5.0) -> str | None:
    """Run `<binary> --version` (opt-in). Output is reduced to a version-shaped token."""
    try:
        proc = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = _VERSION_RE.search(proc.stdout + proc.stderr)
    return match.group(0) if match else None


def path_info(path: Path) -> PathInfo:
    mode = path.stat().st_mode
    return PathInfo(
        path=_display(path),
        mode=oct(stat.S_IMODE(mode)),
        group_readable=bool(mode & stat.S_IRGRP),
        world_readable=bool(mode & stat.S_IROTH),
    )


def _display(path: Path) -> str:
    """Show home-relative paths so reports do not leak usernames."""
    home = str(Path.home())
    text = str(path)
    return "~" + text[len(home) :] if text.startswith(home + os.sep) or text == home else text


def inventory_profile(
    profile: HarnessProfile,
    repo: Path | None,
    *,
    run_versions: bool = False,
    search_path: str | None = None,
    home: Path | None = None,
) -> InventoryItem:
    item = InventoryItem(harness=profile.id, name=profile.name)
    for binary in profile.binaries:
        found = shutil.which(binary, path=search_path)
        if not found:
            continue
        resolved = Path(found).resolve()
        version = static_version(resolved, profile)
        if version is None and run_versions:
            version = exec_version(Path(found))
        item.binaries.append(
            BinaryInfo(
                name=binary,
                path=_display(Path(found)),
                resolved=_display(resolved),
                install_method=classify_install(resolved),
                version=version,
            )
        )
    for pattern in profile.state_dirs:
        if is_user_path(pattern):
            item.state_dirs.extend(path_info(p) for p in glob_paths(pattern, Path("/"), home))
    for pattern in profile.credential_files:
        if is_user_path(pattern):
            item.credential_files.extend(path_info(p) for p in glob_paths(pattern, Path("/"), home))
    if repo is not None:
        patterns = [c.path for c in profile.config_files if c.scope != Scope.USER]
        patterns += profile.instruction_files
        if profile.mcp:
            patterns += profile.mcp.files
        seen: set[str] = set()
        for pattern in patterns:
            if is_user_path(pattern):
                continue
            for path in glob_paths(pattern, repo):
                rel = path.relative_to(repo).as_posix()
                if rel not in seen:
                    seen.add(rel)
                    item.repo_files.append(rel)
    return item


def run_inventory(
    profiles: tuple[HarnessProfile, ...],
    repo: Path | None,
    *,
    run_versions: bool = False,
    search_path: str | None = None,
    home: Path | None = None,
) -> list[InventoryItem]:
    items = [
        inventory_profile(p, repo, run_versions=run_versions, search_path=search_path, home=home)
        for p in profiles
    ]
    return [i for i in items if i.detected]
