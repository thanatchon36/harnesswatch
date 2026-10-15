"""`audit ci`: headless agent invocations in CI workflows (HG-CI-*)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from harnesswatch.models import Location, Severity
from harnesswatch.parsers.loaders import (
    MAX_CONFIG_BYTES,
    ConfigParseError,
    parse_text,
)
from harnesswatch.resources import repo_file_problem
from harnesswatch.rules_engine import Hit, Rule, check

# Untrusted-input triggers: an outsider controls text the agent will read.
UNTRUSTED_TRIGGERS = {
    "pull_request_target",
    "issue_comment",
    "issues",
    "pull_request_review_comment",
    "pull_request_review",
    "discussion",
    "discussion_comment",
    "workflow_run",
}
UNTRUSTED_EXPRESSIONS = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|comment\.body|review\.body|"
    r"pull_request\.(?:title|body|head\.ref)|discussion\.(?:title|body)|head_commit\.message)"
)
SECRET_REF = re.compile(r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)[A-Za-z0-9_]+")
ACTOR_GATE = re.compile(
    r"author_association|github\.actor\s*==|github\.triggering_actor|contains\(\s*fromJSON|"
    r"permission\s*==|github\.event\.sender\.login\s*=="
)


@dataclass
class Workflow:
    path: str
    text: str
    data: dict[str, Any]
    system: str = "github"  # github | gitlab
    job_lines: dict[str, int] = field(default_factory=dict)  # job name -> line of its key


@dataclass
class CiSubject:
    workflows: list[Workflow] = field(default_factory=list)
    agent_actions: list[str] = field(default_factory=list)
    agent_commands: dict[str, str] = field(default_factory=dict)  # name -> regex
    auto_approve_markers: list[str] = field(default_factory=list)


def collect(repo: Path, errors: list[tuple[str, str]] | None = None) -> list[Workflow]:
    errors = [] if errors is None else errors
    out = []
    paths = sorted((repo / ".github" / "workflows").glob("*.y*ml"))
    for path in [*paths, repo / ".gitlab-ci.yml"]:
        if not path.is_file():
            continue
        display = path.relative_to(repo).as_posix()
        problem = repo_file_problem(path, repo)
        if problem is None and path.stat().st_size > MAX_CONFIG_BYTES:
            problem = f"larger than {MAX_CONFIG_BYTES} bytes; skipped"
        if problem:
            errors.append((display, problem))
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            data = parse_text(text, "yaml")
        except OSError as exc:
            errors.append((display, f"unreadable: {exc.strerror or exc}"))
            continue
        except ConfigParseError as exc:
            errors.append((display, str(exc)[:200]))
            continue
        if isinstance(data, dict):
            system = "gitlab" if path.name == ".gitlab-ci.yml" else "github"
            out.append(Workflow(display, text, data, system, _job_lines(text, system)))
    return out


def _job_lines(text: str, system: str) -> dict[str, int]:
    """Line of each job's key, from the YAML node marks (a text search finds comments too)."""
    root = yaml.compose(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
    if not isinstance(root, yaml.MappingNode):
        return {}
    jobs: yaml.Node | None = root
    if system == "github":
        jobs = next((v for k, v in root.value if getattr(k, "value", None) == "jobs"), None)
    if not isinstance(jobs, yaml.MappingNode):
        return {}
    return {
        str(k.value): k.start_mark.line + 1 for k, _ in jobs.value if isinstance(k, yaml.ScalarNode)
    }


def _triggers(data: dict[str, Any]) -> set[str]:
    yaml_true: Any = True  # PyYAML parses a bare `on:` key as the boolean True
    raw = data.get("on", data.get(yaml_true))
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(t) for t in raw}
    if isinstance(raw, dict):
        return {str(t) for t in raw}
    return set()


def _line(text: str, needle: str, from_line: int | None = None) -> int | None:
    """Line of the first `needle` at or after `from_line` (falls back to the whole text)."""
    offset = 0
    for _ in range((from_line or 1) - 1):
        offset = text.find("\n", offset) + 1
    index = text.find(needle, offset)
    if index < 0:
        index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else None


def _dump(value: Any) -> str:
    return yaml.safe_dump(value, default_flow_style=False) if value is not None else ""


@dataclass
class AgentStep:
    job: str
    marker: str  # action name or command display name
    needle: str  # literal text from the workflow, used to find the line
    text: str  # the step + job env, serialised, for secret / flag / expression checks
    gated: bool


def _agent_steps(wf: Workflow, subject: CiSubject) -> Iterator[AgentStep]:
    if wf.system == "gitlab":
        for name, job in wf.data.items():
            if not isinstance(job, dict) or "script" not in job:
                continue
            body = _dump(job)
            for command, pattern in subject.agent_commands.items():
                match = re.search(pattern, body)
                if match:
                    gated = bool(ACTOR_GATE.search(body))
                    yield AgentStep(str(name), command, match.group(0), body, gated)
                    break
        return
    jobs = wf.data.get("jobs") or {}
    for job_name, job in jobs.items() if isinstance(jobs, dict) else []:
        if not isinstance(job, dict):
            continue
        # Workflow-level `env:` reaches every job's environment too.
        job_ctx = _dump(
            {"workflow_env": wf.data.get("env"), "env": job.get("env"), "if": job.get("if")}
        )
        job_gated = bool(ACTOR_GATE.search(str(job.get("if", ""))))
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            body = _dump(step) + job_ctx
            uses = str(step.get("uses", ""))
            marker = next((a for a in subject.agent_actions if uses.lower().startswith(a)), None)
            needle = uses
            if marker is None:
                run = str(step.get("run", ""))
                for command, pattern in subject.agent_commands.items():
                    match = re.search(pattern, run)
                    if match:
                        marker, needle = command, match.group(0)
                        break
            if marker:
                gated = job_gated or bool(ACTOR_GATE.search(str(step.get("if", ""))))
                yield AgentStep(str(job_name), marker, needle, body, gated)


@check("HG-CI-001", "ci")
def pwn_request(rule: Rule, subject: CiSubject) -> Iterator[Hit]:
    for wf in subject.workflows:
        triggers = _triggers(wf.data)
        untrusted = sorted(triggers & UNTRUSTED_TRIGGERS)
        if wf.system == "gitlab":
            untrusted = ["merge_request_event"] if "merge_request" in wf.text else []
        if not untrusted:
            continue
        for step in _agent_steps(wf, subject):
            secrets = bool(SECRET_REF.search(step.text))
            auto = [m for m in subject.auto_approve_markers if re.search(m, step.text)]
            interpolated = bool(UNTRUSTED_EXPRESSIONS.search(step.text))
            if not (secrets or auto or interpolated):
                continue
            severity = Severity.HIGH
            if (auto or interpolated) and secrets and not step.gated:
                severity = Severity.CRITICAL
            elif step.gated:
                severity = Severity.MEDIUM
            parts = [f"trigger {', '.join(untrusted)}", f"agent `{step.marker}`"]
            parts += ["repository secrets exposed"] if secrets else []
            parts += [f"auto-approve ({', '.join(auto)})"] if auto else []
            parts += ["untrusted event text interpolated"] if interpolated else []
            parts += ["actor-gated"] if step.gated else ["no actor/association gate"]
            yield Hit(
                message=f"Headless agent in untrusted-input workflow (job {step.job}): "
                + "; ".join(parts),
                location=Location(
                    path=wf.path, line=_line(wf.text, step.needle, wf.job_lines.get(step.job))
                ),
                severity=severity,
                key=f"{step.job}|{step.marker}",
            )


WRITE_SCOPES = {
    "contents",
    "pull-requests",
    "issues",
    "actions",
    "packages",
    "id-token",
    "workflows",
}


@check("HG-CI-002", "ci")
def token_permissions(rule: Rule, subject: CiSubject) -> Iterator[Hit]:
    for wf in subject.workflows:
        if wf.system != "github":
            continue
        steps = list(_agent_steps(wf, subject))
        if not steps:
            continue
        top = wf.data.get("permissions")
        jobs = wf.data.get("jobs") or {}
        for job_name in sorted({s.job for s in steps}):
            perms = (jobs.get(job_name) or {}).get("permissions", top)
            problem = None
            if perms is None:
                problem = "no `permissions:` block (GITHUB_TOKEN gets the repository default)"
            elif perms == "write-all":
                problem = "`permissions: write-all`"
            elif isinstance(perms, dict):
                writes = sorted(k for k, v in perms.items() if v == "write" and k in WRITE_SCOPES)
                if writes:
                    problem = f"GITHUB_TOKEN write scopes: {', '.join(writes)}"
            if problem:
                yield Hit(
                    message=f"Agent job `{job_name}` runs with {problem}",
                    location=Location(
                        path=wf.path,
                        line=wf.job_lines.get(job_name) or _line(wf.text, f"{job_name}:"),
                    ),
                    key=job_name,
                )
