"""`audit instructions`: injection indicators in instruction, rules and skill files (HG-INJ-*)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from harnesswatch import textscan
from harnesswatch.models import Confidence, HarnessProfile, Location, Severity
from harnesswatch.resources import glob_paths, is_user_path, repo_file_problem
from harnesswatch.rules_engine import Hit, Rule, check

MAX_BYTES = 2_000_000
INSTRUCTION_KINDS = {"instructions", "rules", "skills", "agents"}

# Files read by many harnesses regardless of profile coverage.
COMMON_INSTRUCTION_FILES = ("AGENTS.md", "AGENT.md", "**/AGENTS.md", "**/SKILL.md")


@dataclass(frozen=True)
class InstructionDoc:
    path: str
    text: str
    harnesses: tuple[str, ...]


def instruction_patterns(profiles: tuple[HarnessProfile, ...]) -> dict[str, set[str]]:
    """Map path pattern → harness ids that load it."""
    patterns: dict[str, set[str]] = {}
    for profile in profiles:
        names = list(profile.instruction_files) + list(profile.skills_paths)
        names += [c.path for c in profile.config_files if c.kind in INSTRUCTION_KINDS]
        for name in names:
            patterns.setdefault(name.rstrip("?"), set()).add(profile.id)
    for name in COMMON_INSTRUCTION_FILES:
        patterns.setdefault(name, set())
    return patterns


def collect(
    root: Path,
    profiles: tuple[HarnessProfile, ...],
    *,
    include_user: bool = False,
    home: Path | None = None,
    errors: list[tuple[str, str]] | None = None,
) -> list[InstructionDoc]:
    """Read every instruction file; unreadable or unsafe paths are recorded in `errors`."""
    home = home or Path.home()
    errors = [] if errors is None else errors
    docs: dict[Path, set[str]] = {}

    def safe(path: Path, user: bool, directory: bool = False) -> bool:
        problem = None if user else repo_file_problem(path, root, directory=directory)
        if problem is None:
            return True
        entry = (_rel(path, root, home), problem)
        if entry not in errors:
            errors.append(entry)
        return False

    for pattern, harnesses in instruction_patterns(profiles).items():
        user = is_user_path(pattern)
        if user and not include_user:
            continue
        for path in glob_paths(pattern, root, home):
            if "node_modules" in path.parts:
                continue
            if path.is_dir():  # e.g. `.clinerules/` may be a directory of rule files
                if safe(path, user, directory=True):
                    for child in _walk_files(path):
                        wanted = child.suffix in {".md", ".mdc", ".txt", ""}
                        if wanted and safe(child, user) and child.is_file():
                            docs.setdefault(child, set()).update(harnesses)
            elif safe(path, user) and path.is_file():
                docs.setdefault(path, set()).update(harnesses)
    out = []
    for path, harnesses in sorted(docs.items()):
        try:
            if path.stat().st_size > MAX_BYTES:
                continue
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            errors.append((_rel(path, root, home), f"unreadable: {exc.strerror or exc}"))
            continue
        out.append(InstructionDoc(_rel(path, root, home), text, tuple(sorted(harnesses))))
    return out


def _walk_files(directory: Path) -> list[Path]:
    """Files under `directory` without descending into symlinked directories."""
    found = []
    for dirpath, _, filenames in os.walk(directory):  # followlinks=False
        found += [Path(dirpath) / name for name in filenames]
    return sorted(found)


def _rel(path: Path, root: Path, home: Path) -> str:
    if path.is_relative_to(root):
        return path.relative_to(root).as_posix()
    return "~/" + path.relative_to(home).as_posix() if path.is_relative_to(home) else str(path)


def _harness(doc: InstructionDoc) -> str | None:
    return doc.harnesses[0] if len(doc.harnesses) == 1 else None


def _summary(indicators: list[textscan.Indicator]) -> str:
    kinds = sorted({i.kind for i in indicators})
    lines = sorted({i.line for i in indicators})[:5]
    return f"{', '.join(kinds)} (lines {', '.join(map(str, lines))})"


@check("HG-INJ-001", "instructions")
def hidden_unicode(rule: Rule, docs: list[InstructionDoc]) -> Iterator[Hit]:
    for doc in docs:
        found = textscan.hidden_unicode(doc.text)
        if not found:
            continue
        strong = any(i.kind in {"unicode-tag", "bidi-control"} for i in found)
        only_confusable = all(i.kind == "confusable" for i in found)
        yield Hit(
            message=f"Hidden or confusable Unicode: {_summary(found)}",
            location=Location(path=doc.path, line=found[0].line),
            harness=_harness(doc),
            severity=Severity.HIGH if strong else (Severity.LOW if only_confusable else None),
            confidence=Confidence.MEDIUM if only_confusable else None,
            key="",
        )


def _severity_for(score: int, thresholds: dict[str, int]) -> Severity:
    if score >= thresholds.get("high", 10):
        return Severity.HIGH
    if score >= thresholds.get("medium", 7):
        return Severity.MEDIUM
    return Severity.LOW


@check("HG-INJ-002", "instructions")
def override_phrases(rule: Rule, docs: list[InstructionDoc]) -> Iterator[Hit]:
    min_score = int(rule.params.get("min_score", 5))
    thresholds = dict(rule.params.get("severity_thresholds", {}))
    for doc in docs:
        found = textscan.phrase_indicators(doc.text)
        total = textscan.score(found)
        if total < min_score or not textscan.has_strong(found):
            continue
        yield Hit(
            message=f"Injection indicators, score {total}: {_summary(found)}",
            location=Location(path=doc.path, line=min(i.line for i in found)),
            harness=_harness(doc),
            severity=_severity_for(total, thresholds),
            evidence=found[0].detail,
            key="",
        )


@check("HG-INJ-003", "instructions")
def remote_content(rule: Rule, docs: list[InstructionDoc]) -> Iterator[Hit]:
    for doc in docs:
        for indicator in textscan.remote_imports(doc.text):
            yield Hit(
                message="Instruction file pulls remote content at load time",
                location=Location(path=doc.path, line=indicator.line),
                harness=_harness(doc),
                evidence=indicator.detail,
                key=indicator.detail,
            )
