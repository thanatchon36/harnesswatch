"""Render findings: JSON, Markdown, SARIF 2.1.0, Rich terminal. Baseline diffing."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from rich.console import Console
from rich.table import Table
from rich.text import Text

from harnesswatch import __version__
from harnesswatch.models import Finding, Severity
from harnesswatch.rules_engine import Rule

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning maps `security-severity` (0-10) to its own severity buckets.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
REPORT_SCHEMA_VERSION = 1


def to_json(
    findings: list[Finding],
    errors: Iterable[tuple[str, str]] = (),
    scanned: dict[str, int] | None = None,
) -> str:
    payload = {
        "tool": "harnesswatch",
        "version": __version__,
        "schema": REPORT_SCHEMA_VERSION,
        "summary": summary(findings),
        "scanned": scanned or {},
        "findings": [f.model_dump(mode="json") | {"fingerprint": f.fingerprint} for f in findings],
        "errors": [{"path": p, "message": m} for p, m in errors],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def load_report(path: Path) -> tuple[list[Finding], list[tuple[str, str]]]:
    """Findings and errors of a harnesswatch JSON report; ValueError if it is not one."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(f"{path}: not a harnesswatch JSON report (no `findings` list)")
    findings = [
        Finding.model_validate({k: v for k, v in f.items() if k != "fingerprint"})
        for f in data["findings"]
    ]
    errors = [
        (str(e.get("path", "")), str(e.get("message", "")))
        for e in data.get("errors", [])
        if isinstance(e, dict)
    ]
    return findings, errors


def load_json(path: Path) -> list[Finding]:
    return load_report(path)[0]


def summary(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in Severity}


def apply_baseline(findings: list[Finding], baseline: list[Finding]) -> list[Finding]:
    """Drop findings already present in the baseline (matched by fingerprint)."""
    known = {f.fingerprint for f in baseline}
    return [f for f in findings if f.fingerprint not in known]


_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _md_cell(text: str) -> str:
    """Neutralise table, code, link and HTML syntax in text taken from audited files."""
    text = _CONTROL.sub(" ", text).replace("\\", "\\\\").replace("|", "\\|")
    text = text.replace("`", "\\`").replace("](", "]\\(")
    return text.replace("<", "&lt;").replace(">", "&gt;")


def to_markdown(
    findings: list[Finding],
    title: str = "harnesswatch report",
    errors: Iterable[tuple[str, str]] = (),
) -> str:
    lines = [f"# {title}", ""]
    counts = summary(findings)
    lines.append(" · ".join(f"**{k}**: {v}" for k, v in counts.items()))
    lines.append("")
    errors = list(errors)
    if errors:
        lines += ["## Errors", "", "Files that could not be audited:", ""]
        lines += [f"- {_md_cell(path)}: {_md_cell(message)}" for path, message in errors]
        lines.append("")
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines += ["| Severity | Rule | Harness | Location | Finding |", "|---|---|---|---|---|"]
    for f in findings:
        loc = f.location.path + (f":{f.location.line}" if f.location.line else "")
        lines.append(
            f"| {f.severity.value} | {f.rule_id} | {f.harness or '-'} | {_md_cell(loc)} "
            f"| {_md_cell(f.message)} |"
        )
    lines.append("")
    lines.append("## Remediation")
    for rule_id in sorted({f.rule_id for f in findings}):
        first = next(f for f in findings if f.rule_id == rule_id)
        lines += ["", f"**{rule_id} — {first.title}**: {first.remediation.strip()}"]
    return "\n".join(lines) + "\n"


def _is_file_path(path: str) -> bool:
    """Repository-relative paths; home paths, absolute paths and purls are not artifacts."""
    return not (path.startswith(("~", "/")) or re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", path))


def _location(path: str, line: int | None, uri_prefix: str) -> dict[str, Any]:
    if not _is_file_path(path):
        return {"logicalLocations": [{"fullyQualifiedName": path, "kind": "resource"}]}
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": quote(uri_prefix + path), "uriBaseId": "%SRCROOT%"}
    }
    if line:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def to_sarif(
    findings: list[Finding],
    rules: dict[str, Rule],
    errors: Iterable[tuple[str, str]] = (),
    uri_prefix: str = "",
) -> dict[str, Any]:
    """SARIF 2.1.0. `uri_prefix` is the scanned directory relative to the repository root."""
    used = sorted({f.rule_id for f in findings})
    rule_index = {rule_id: i for i, rule_id in enumerate(used)}
    driver_rules = []
    for rule_id in used:
        rule = rules.get(rule_id)
        finding = next(f for f in findings if f.rule_id == rule_id)
        severity = rule.severity if rule else finding.severity
        driver_rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": (rule.description if rule else finding.title).strip()},
                "help": {"text": finding.remediation.strip() or finding.title},
                "helpUri": (
                    finding.references[0]
                    if finding.references
                    else "https://github.com/thanatchon36/harnesswatch"
                ),
                "defaultConfiguration": {"level": SARIF_LEVEL[severity]},
                "properties": {
                    "tags": ["security", *finding.taxonomy],
                    "security-severity": SECURITY_SEVERITY[severity],
                },
            }
        )
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [_location(f.location.path, f.location.line, uri_prefix)],
                "partialFingerprints": {"harnesswatch/v1": f.fingerprint},
                "properties": {
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "harness": f.harness,
                    "security-severity": SECURITY_SEVERITY[f.severity],
                },
            }
        )
    notifications = [
        {
            "level": "error",
            "message": {"text": f"Not audited: {message}"},
            "locations": [_location(path, None, uri_prefix)],
        }
        for path, message in errors
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "harnesswatch",
                        "version": __version__,
                        "informationUri": "https://github.com/thanatchon36/harnesswatch",
                        "rules": driver_rules,
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Repository root"}}},
                "invocations": [
                    {
                        "executionSuccessful": not notifications,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
            }
        ],
    }


STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def plain(text: str) -> Text:
    """Text from audited files, without markup and with control characters removed."""
    return Text(_CONTROL.sub("", text))


def print_rich(
    findings: list[Finding], console: Console, scanned: dict[str, int] | None = None
) -> None:
    if scanned:
        console.print(
            "Scanned: " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in scanned.items())
        )
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    table = Table(show_lines=False)
    for column in ("severity", "rule", "harness", "location", "finding"):
        table.add_column(column, overflow="fold")
    for f in findings:
        loc = f.location.path + (f":{f.location.line}" if f.location.line else "")
        # Names and paths come from the audited repo: plain Text, never Rich markup.
        table.add_row(
            Text(f.severity.value, style=STYLE[f.severity]),
            f.rule_id,
            plain(f.harness or "-"),
            plain(loc),
            plain(f.message),
        )
    console.print(table)
    console.print(" · ".join(f"{k}: {v}" for k, v in summary(findings).items()))
