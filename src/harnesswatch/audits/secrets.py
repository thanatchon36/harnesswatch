"""`audit secrets`: secret residue in harness state (HG-SEC-001) and file permissions (HG-SEC-002).

Matches are redacted immediately and never written anywhere.
"""

from __future__ import annotations

import os
import stat
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from harnesswatch.models import HarnessProfile, Location, Severity
from harnesswatch.resources import glob_base, glob_paths, is_user_path
from harnesswatch.rules_engine import Hit, Rule, check
from harnesswatch.secrets import find_secrets

DEFAULT_MAX_FILE_MB = 50
CHUNK_CHARS = 1 << 20  # files are scanned in bounded windows, never as one unbounded line
OVERLAP = 4096  # longer than any secret shape, so a token across a window edge is still seen


@dataclass(frozen=True)
class StateFile:
    path: Path
    display: str
    harness: str
    role: str  # log | memory | credential | state-dir


@dataclass
class SecretsSubject:
    files: list[StateFile] = field(default_factory=list)
    max_file_bytes: int = DEFAULT_MAX_FILE_MB * 1_000_000


def _display(path: Path, home: Path) -> str:
    return "~/" + path.relative_to(home).as_posix() if path.is_relative_to(home) else str(path)


def collect(profiles: tuple[HarnessProfile, ...], home: Path | None = None) -> SecretsSubject:
    home = home or Path.home()
    subject = SecretsSubject()
    seen: set[Path] = set()
    for profile in profiles:
        groups = (
            ("log", profile.log_paths),
            ("memory", profile.memory_paths),
            ("credential", profile.credential_files),
            ("state-dir", profile.state_dirs),
        )
        for role, patterns in groups:
            for pattern in patterns:
                if not is_user_path(pattern):
                    continue
                # A glob must not escape its base through a symlinked directory
                # (`~/.claude/projects/linked -> /elsewhere`); the base itself may be a link.
                base = glob_base(pattern, Path("/"), home).resolve()
                for path in glob_paths(pattern, Path("/"), home):
                    if path in seen or path.is_symlink():
                        continue
                    if not path.resolve().is_relative_to(base):
                        continue
                    seen.add(path)
                    subject.files.append(StateFile(path, _display(path, home), profile.id, role))
    return subject


def _scan_file(path: Path, limit: int) -> tuple[Counter[str], int | None]:
    """Count secret kinds in the first `limit` characters; return the first line with a hit."""
    kinds: Counter[str] = Counter()
    first: int | None = None
    line = 1  # line number at the start of `text`
    carry = ""
    read = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        while True:
            chunk = handle.read(min(CHUNK_CHARS, max(0, limit - read)))
            read += len(chunk)
            text = carry + chunk
            final = len(chunk) < CHUNK_CHARS or read >= limit
            # Matches starting in the overlap are counted with the next window instead.
            cutoff = len(text) if final else len(text) - OVERLAP
            for match in find_secrets(text):
                if match.start < cutoff:
                    kinds[match.kind] += 1
                    hit_line = line + text.count("\n", 0, match.start)
                    first = hit_line if first is None else min(first, hit_line)
            if final:
                return kinds, first
            line += text.count("\n", 0, cutoff)
            carry = text[cutoff:]


@check("HG-SEC-001", "secrets")
def secret_residue(rule: Rule, subject: SecretsSubject) -> Iterator[Hit]:
    for item in subject.files:
        if item.role not in {"log", "memory"} or not item.path.is_file():
            continue
        try:
            kinds, first = _scan_file(item.path, subject.max_file_bytes)
        except OSError:
            continue
        if kinds:
            summary = ", ".join(f"{n}x {k}" for k, n in sorted(kinds.items()))
            yield Hit(
                message=f"Secret-like strings in harness {item.role} file: {summary}",
                location=Location(path=item.display, line=first),
                harness=item.harness,
                key=item.role,
            )


@check("HG-SEC-002", "secrets")
def loose_permissions(rule: Rule, subject: SecretsSubject) -> Iterator[Hit]:
    # Logs/memory can be thousands of files: one hit per (harness, role) with a count.
    readable: dict[tuple[str, str], list[StateFile]] = {}
    for item in subject.files:
        try:
            mode = stat.S_IMODE(item.path.stat().st_mode)
        except OSError:
            continue
        if item.role == "credential" and mode & 0o077:
            yield Hit(
                message=f"Credential file is group/world accessible (mode {oct(mode)})",
                location=Location(path=item.display),
                harness=item.harness,
                severity=Severity.HIGH,
                key=item.role,
            )
        elif item.role == "state-dir" and mode & stat.S_IROTH:
            yield Hit(
                message=f"Harness state directory is world-readable (mode {oct(mode)})",
                location=Location(path=item.display),
                harness=item.harness,
                key=item.role,
            )
        elif item.role in {"log", "memory"} and mode & stat.S_IROTH:
            readable.setdefault((item.harness, item.role), []).append(item)
    for (harness, role), items in sorted(readable.items()):
        # Located at the directory holding them, so a growing file count keeps the fingerprint.
        folder = os.path.commonpath([str(PurePosixPath(i.display).parent) for i in items])
        yield Hit(
            message=f"{len(items)} harness {role} file(s) are world-readable, e.g. {items[0].display}",
            location=Location(path=folder),
            harness=harness,
            key=f"{harness}|{role}",
        )
