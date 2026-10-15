"""`audit config`: permission, hook, network, telemetry and delegation rules over `HarnessConfig`."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from harnesswatch.models import HarnessConfig, HarnessProfile, Scope, Severity
from harnesswatch.parsers.loaders import get_all
from harnesswatch.rules_engine import Hit, Rule, check

PROJECT_SCOPES = {Scope.PROJECT, Scope.PROJECT_LOCAL}


@dataclass
class ConfigSubject:
    configs: list[HarnessConfig] = field(default_factory=list)
    profiles: dict[str, HarnessProfile] = field(default_factory=dict)
    raw: dict[str, object] = field(default_factory=dict)  # source path -> parsed data


def _setting_hits(rule: Rule, subject: ConfigSubject) -> Iterator[tuple[HarnessConfig, str]]:
    """Match `params.settings[harness] = [{key, value}]` against each config's raw data.

    An item without `value` matches any present value; `value: nonempty` any truthy value. Any
    other value (including the literal `"*"`, e.g. a wildcard domain) must equal the setting, be
    an element of a list-valued setting, or be an enabled key of a map-valued setting
    (`{"*": true}`).
    """
    table = rule.params.get("settings", {})
    for config in subject.configs:
        data = subject.raw.get(config.source.path)
        for item in table.get(config.harness, []):
            if "kinds" in item and config.kind not in item["kinds"]:
                continue
            for actual in get_all(data, item["key"]):
                if "value" not in item:
                    yield config, f"{item['key']}={_short(actual)}"
                    break
                expected = item["value"]
                if expected == "nonempty":
                    if actual:
                        yield config, f"{item['key']}={_short(actual)}"
                        break
                    continue
                if _equal(actual, expected):
                    yield config, f"{item['key']}={_short(actual)}"
                    break
                if isinstance(actual, list) and any(_equal(a, expected) for a in actual):
                    yield config, f"{item['key']} contains {expected!r}"
                    break
                if isinstance(actual, dict) and any(
                    _equal(k, expected) and v not in (False, None, "deny")
                    for k, v in actual.items()
                ):
                    yield config, f"{item['key']} enables {expected!r}"
                    break


def _equal(actual: object, expected: object) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.strip().lower() == expected.lower()
    if isinstance(expected, bool) or isinstance(actual, bool):
        return actual is expected or str(actual).lower() == str(expected).lower()
    return actual == expected


def _short(value: object) -> str:
    text = str(value)
    return text if len(text) <= 40 else text[:37] + "..."


def approve_all(rule: Rule, config: HarnessConfig) -> list[str]:
    """Auto-approve matches minus the ones this rule treats as bounded (classifier, edits-only)."""
    ignored_pairs = {str(v).lower() for v in rule.params.get("ignore", [])}
    ignored_keys = set(rule.params.get("ignore_keys", []))
    out = []
    for match in config.auto_approve_matches:
        key = match.partition("=")[0]
        if match.lower() not in ignored_pairs and key not in ignored_keys:
            out.append(match)
    return out


@check("HG-PERM-001", "config")
def auto_approve(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config in subject.configs:
        matches = approve_all(rule, config)
        if not matches:
            continue
        shared = config.scope in PROJECT_SCOPES
        yield Hit(
            message=(
                f"Approve-everything mode enabled ({', '.join(matches)})"
                + (
                    " in a repository config that applies to everyone who opens the repo"
                    if shared
                    else ""
                )
            ),
            location=config.source,
            harness=config.harness,
            severity=Severity.HIGH if shared else None,
            key="",
        )


def _overbroad(profile: HarnessProfile | None, entry: str, generic: list[str]) -> bool:
    patterns = list(generic)
    if profile and profile.permissions:
        patterns += profile.permissions.overbroad_patterns
    normalised = entry.replace(" ", "")
    return any(normalised == p.replace(" ", "") for p in patterns)


@check("HG-PERM-002", "config")
def overbroad_allowlist(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    generic = list(rule.params.get("generic_patterns", []))
    for config in subject.configs:
        profile = subject.profiles.get(config.harness)
        broad = [a for a in config.allow if _overbroad(profile, a, generic)]
        if broad:
            yield Hit(
                message=f"Allowlist grants unrestricted access: {', '.join(sorted(set(broad))[:5])}",
                location=config.source,
                harness=config.harness,
                severity=Severity.HIGH if config.scope in PROJECT_SCOPES else None,
                key="",
            )


@check("HG-PERM-003", "config")
def missing_denylist(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    destructive = [
        re.compile(p, re.IGNORECASE) for p in rule.params.get("destructive_patterns", [])
    ]
    for config in subject.configs:
        broad = bool(approve_all(rule, config)) or any(
            _overbroad(
                subject.profiles.get(config.harness),
                a,
                list(rule.params.get("generic_patterns", [])),
            )
            for a in config.allow
        )
        if not broad:
            continue
        covered = [p.pattern for p in destructive if any(p.search(d) for d in config.deny)]
        if len(covered) < len(destructive):
            missing = len(destructive) - len(covered)
            yield Hit(
                message=f"Unrestricted execution with no deny rule for {missing} destructive command class(es)"
                " (e.g. rm -rf, force-push, credential reads)",
                location=config.source,
                harness=config.harness,
                key="",
            )


@check("HG-HOOK-001", "config")
def repo_hooks(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config in subject.configs:
        if config.scope not in PROJECT_SCOPES or not config.hooks:
            continue
        events = sorted({h.event for h in config.hooks})
        yield Hit(
            message=f"Repository config defines {len(config.hooks)} shell hook(s) ({', '.join(events[:5])}) "
            "that run for anyone who opens the repo with this harness",
            location=config.source,
            harness=config.harness,
            key="",
        )


@check("HG-HOOK-002", "config")
def network_hooks(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    pattern = re.compile(str(rule.params.get("network_pattern", r"\b(curl|wget)\b")), re.IGNORECASE)
    for config in subject.configs:
        for hook in config.hooks:
            match = pattern.search(hook.command)
            if match:
                yield Hit(
                    message=f"Hook ({hook.event}) runs network/remote code: `{match.group(0)}`",
                    location=config.source,
                    harness=config.harness,
                    severity=Severity.HIGH if config.scope in PROJECT_SCOPES else None,
                    evidence=hook.command[:120],
                    key=f"{hook.event}|{hook.command}",
                )


@check("HG-SEC-003", "config")
def plaintext_credentials(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config in subject.configs:
        if config.plaintext_credentials:
            shared = config.scope in PROJECT_SCOPES
            keys = ", ".join(config.plaintext_credentials[:5])
            yield Hit(
                message=f"Literal credential value(s) in config at {keys}"
                + (" — committed repository file" if shared else ""),
                location=config.source,
                harness=config.harness,
                severity=Severity.CRITICAL if shared else None,
                key="",
            )


@check("HG-NET-001", "config")
def unrestricted_network(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config, setting in _setting_hits(rule, subject):
        yield Hit(
            message=f"Unrestricted network egress for agent tools ({setting})",
            location=config.source,
            harness=config.harness,
        )


@check("HG-TEL-001", "config")
def telemetry(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config, setting in _setting_hits(rule, subject):
        yield Hit(
            message=f"Telemetry / data-sharing explicitly enabled ({setting})",
            location=config.source,
            harness=config.harness,
        )


@check("HG-MEM-001", "config")
def memory(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config, setting in _setting_hits(rule, subject):
        yield Hit(
            message=f"Persistent agent-writable memory enabled ({setting})",
            location=config.source,
            harness=config.harness,
        )


@check("HG-SUB-001", "config")
def subagent_bypass(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config, setting in _setting_hits(rule, subject):
        yield Hit(
            message=f"Sub-agent/delegation runs with inherited or bypass permissions ({setting})",
            location=config.source,
            harness=config.harness,
        )


@check("HG-MCP-006", "config")
def auto_enable_project_mcp(rule: Rule, subject: ConfigSubject) -> Iterator[Hit]:
    for config, setting in _setting_hits(rule, subject):
        shared = config.scope in PROJECT_SCOPES
        yield Hit(
            message=f"Project MCP servers are auto-approved without a per-server prompt ({setting})"
            + (" — set by the repository itself" if shared else ""),
            location=config.source,
            harness=config.harness,
            severity=Severity.CRITICAL if shared else None,
        )
