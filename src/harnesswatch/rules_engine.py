"""Rule metadata (from `rules/HG-*.yaml`) + Python checks registered per rule ID.

A rule YAML holds what a human reviews (severity, taxonomy, remediation, parameters);
the matching check function holds the detection logic. Checks yield `Hit`s; the engine turns
them into `Finding`s by attaching the rule metadata.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from harnesswatch.models import Confidence, Finding, Location, Severity, message_key, stable_key
from harnesswatch.parsers.loaders import load_yaml
from harnesswatch.resources import rules_dir
from harnesswatch.secrets import redact_text


class Rule(BaseModel):
    id: str
    title: str
    area: str
    severity: Severity
    confidence: Confidence
    taxonomy: list[str]
    kind: str = "vulnerability-pattern"  # | design-weakness | policy
    harnesses: list[str] = Field(default_factory=lambda: ["*"])
    description: str
    remediation: str
    references: list[str] = Field(default_factory=list)
    params: dict[str, Any] = Field(default_factory=dict)


@dataclass
class Hit:
    """What a check reports; the engine adds the rule metadata."""

    message: str
    location: Location
    harness: str | None = None
    evidence: str | None = None
    severity: Severity | None = None  # override (e.g. scored injection findings)
    confidence: Confidence | None = None
    key: str | None = None  # stable subject for the fingerprint (default: message minus numbers)


# C0/C1 control characters (terminal escapes) other than tab/newline.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean_text(text: str) -> str:
    """Redact secrets and drop control characters from text derived from audited files."""
    return _CONTROL.sub("", redact_text(text))


Check = Callable[[Rule, Any], Iterable[Hit]]


@dataclass
class Registry:
    checks: dict[str, tuple[str, Check]] = field(default_factory=dict)

    def register(self, rule_id: str, target: str) -> Callable[[Check], Check]:
        """Register a check for `rule_id`; `target` names the context it consumes."""

        def decorator(func: Check) -> Check:
            self.checks[rule_id] = (target, func)
            return func

        return decorator


REGISTRY = Registry()
check = REGISTRY.register


@cache
def _load_rules(directory: Path) -> dict[str, Rule]:
    rules: dict[str, Rule] = {}
    for path in sorted(directory.glob("HG-*.yaml")):
        rule = Rule.model_validate(load_yaml(path.read_text(encoding="utf-8")))
        if rule.id != path.stem:
            raise ValueError(f"{path.name}: id {rule.id!r} does not match file name")
        rules[rule.id] = rule
    return rules


def load_rules(directory: Path | None = None) -> dict[str, Rule]:
    return _load_rules(directory or rules_dir())


def run_checks(
    target: str, subject: Any, rules: dict[str, Rule] | None = None
) -> Iterator[Finding]:
    """Run every registered check that consumes `target` against `subject`."""
    rules = load_rules() if rules is None else rules
    for rule_id, (check_target, func) in sorted(REGISTRY.checks.items()):
        if check_target != target or rule_id not in rules:
            continue
        rule = rules[rule_id]
        for hit in func(rule, subject):
            if hit.harness and "*" not in rule.harnesses and hit.harness not in rule.harnesses:
                continue
            # Every check's output goes through here, so no check can forget to redact.
            message = clean_text(hit.message)
            yield Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=hit.severity or rule.severity,
                confidence=hit.confidence or rule.confidence,
                message=message,
                location=hit.location.model_copy(update={"path": clean_text(hit.location.path)}),
                harness=hit.harness,
                taxonomy=rule.taxonomy,
                remediation=rule.remediation,
                references=rule.references,
                evidence=None if hit.evidence is None else clean_text(hit.evidence),
                key=stable_key(message_key(message) if hit.key is None else hit.key),
            )


def at_or_above(findings: Iterable[Finding], threshold: Severity) -> list[Finding]:
    return [f for f in findings if f.severity.rank >= threshold.rank]
