"""Audit orchestration: build each audit's subject, run its registered checks."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from harnesswatch import parsers
from harnesswatch.audits import ci, config, instructions, mcp, secrets, supply
from harnesswatch.inventory import run_inventory
from harnesswatch.models import Finding, HarnessProfile
from harnesswatch.rules_engine import Rule, load_rules, run_checks

AUDITS = ("config", "mcp", "instructions", "secrets", "supply", "ci")
REPO_AUDITS = ("config", "mcp", "instructions", "ci")  # safe in CI: no home directory access


@dataclass
class AuditOptions:
    repo: Path | None = None
    home: Path | None = None
    include_user: bool = True
    online: bool = False
    tool_manifests: list[Path] = field(default_factory=list)
    max_file_mb: int = secrets.DEFAULT_MAX_FILE_MB
    search_path: str | None = None  # PATH used to find harness binaries (default: $PATH)
    osv_cache: Path | None = None  # offline OSV results: {purl: [vuln, ...]}


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    scanned: dict[str, int] = field(default_factory=dict)


def run(
    audits: tuple[str, ...],
    profiles: tuple[HarnessProfile, ...],
    options: AuditOptions,
    rules: dict[str, Rule] | None = None,
) -> AuditResult:
    rules = load_rules() if rules is None else rules
    result = AuditResult()
    home = options.home or Path.home()
    by_id = {p.id: p for p in profiles}

    if "config" in audits or "mcp" in audits:
        parsed = parsers.parse_all(
            profiles, options.repo, home=home, include_user=options.include_user
        )
        result.errors.extend(parsed.errors)
        result.scanned["config_files"] = len(parsed.raw)
        if "config" in audits:
            subject = config.ConfigSubject(parsed.configs, by_id, parsed.raw)
            result.findings.extend(run_checks("config", subject, rules))
        if "mcp" in audits:
            servers = [s for c in parsed.configs for s in c.mcp_servers]
            manifests = []
            for path in options.tool_manifests:
                try:
                    manifests.append((path.name, mcp.load_manifest(path)))
                except (OSError, ValueError, AttributeError) as exc:
                    result.errors.append((str(path), f"unreadable tool manifest: {exc}"))
            result.scanned["mcp_servers"] = len(servers)
            result.findings.extend(run_checks("mcp", mcp.McpSubject(servers, manifests), rules))
    if "instructions" in audits and options.repo is not None:
        docs = instructions.collect(
            options.repo,
            profiles,
            include_user=options.include_user,
            home=home,
            errors=result.errors,
        )
        result.scanned["instruction_files"] = len(docs)
        result.findings.extend(run_checks("instructions", docs, rules))
    if "secrets" in audits:
        subject_s = secrets.collect(profiles, home)
        subject_s.max_file_bytes = options.max_file_mb * 1_000_000
        result.scanned["state_files"] = len(subject_s.files)
        result.findings.extend(run_checks("secrets", subject_s, rules))
    if "supply" in audits:
        items = run_inventory(profiles, None, search_path=options.search_path, home=home)
        subject_p = supply.SupplySubject(items, by_id, options.online)
        if options.osv_cache is not None:
            subject_p.vulns = json.loads(options.osv_cache.read_text(encoding="utf-8"))
        elif options.online:
            try:
                subject_p.vulns = supply.query_osv(subject_p.components())
            except Exception as exc:  # network failures must not abort an offline-capable audit
                result.errors.append(("osv.dev", f"OSV lookup failed: {type(exc).__name__}"))
        result.scanned["components"] = len(subject_p.components())
        result.findings.extend(run_checks("supply", subject_p, rules))
    if "ci" in audits and options.repo is not None:
        params = rules["HG-CI-001"].params if "HG-CI-001" in rules else {}
        subject_c = ci.CiSubject(
            ci.collect(options.repo, result.errors),
            [a.lower() for a in params.get("agent_actions", [])],
            dict(params.get("agent_commands", {})),
            list(params.get("auto_approve_markers", [])),
        )
        result.scanned["workflows"] = len(subject_c.workflows)
        result.findings.extend(run_checks("ci", subject_c, rules))
    result.findings = dedupe(result.findings)
    return result


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Shared files (AGENTS.md, .vscode/mcp.json) are read by several profiles: keep one finding."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint
        if key in merged:
            if merged[key].harness != finding.harness:
                merged[key] = merged[key].model_copy(update={"harness": None})
        else:
            merged[key] = finding
    order = sorted(
        merged.values(),
        key=lambda f: (-f.severity.rank, f.rule_id, f.location.path, f.location.line or 0),
    )
    return order
