"""`audit mcp`: MCP server declarations across harness formats (HG-MCP-001..005)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from harnesswatch import textscan
from harnesswatch.models import Location, McpServer, Scope, Severity
from harnesswatch.rules_engine import Hit, Rule, check
from harnesswatch.secrets import SECRET_NAME, find_secrets, is_secret_value, looks_like_placeholder

LAUNCHERS = {"npx", "bunx", "pnpx", "uvx", "pipx", "deno", "dlx"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
AUTH_HEADERS = {"authorization", "x-api-key", "api-key", "x-auth-token", "cookie"}


@dataclass
class McpSubject:
    servers: list[McpServer] = field(default_factory=list)
    manifests: list[tuple[str, dict[str, str]]] = field(
        default_factory=list
    )  # (path, tool -> description)


def _basename(command: str | None) -> str:
    return Path(command or "").name.removesuffix(".cmd").removesuffix(".exe").lower()


def _package_arg(args: list[str]) -> str | None:
    """First positional argument after launcher flags (`npx -y pkg@1 --flag` → `pkg@1`)."""
    skip_next = {"--package", "-p", "--from", "--with", "--python"}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in skip_next:
            return args[i + 1] if i + 1 < len(args) else None
        flag, eq, value = arg.partition("=")
        if eq and flag in {"--package", "--from"}:  # `npx --package=pkg@1.2.3 bin`
            return value
        if not arg.startswith("-"):
            return arg
        i += 1
    return None


_NPM_PINNED = re.compile(r"^(?:@[^/]+/)?[^@/]+@(?:\d+\.\d+\.\d+[^\s]*|[0-9a-f]{7,40})$")
# git dependency pinned to a full commit hash (`github:org/repo#<sha>`, `git+https://…#<sha>`)
_GIT_PINNED = re.compile(
    r"^(?:github:|gitlab:|bitbucket:|git\+(?:https|ssh)://|https://github\.com/)[^#\s]+#[0-9a-f]{40}$"
)
_PY_PINNED = re.compile(r"^[A-Za-z0-9_.\-\[\]]+(?:==\d[^\s,;]*|@\d+\.\d+[^\s]*)$")


def unpinned_launch(server: McpServer) -> str | None:
    """Return a description when the server is fetched from a registry at launch without a pin."""
    base = _basename(server.command)
    args = list(server.args)
    if base in {"pnpm", "yarn", "bun"} and args[:1] in (["dlx"], ["x"]):
        base, args = "npx", args[1:]
    if base in {"npx", "bunx", "pnpx"}:
        pkg = _package_arg(args)
        if (
            pkg
            and not pkg.startswith((".", "/"))
            and not _NPM_PINNED.match(pkg)
            and not _GIT_PINNED.match(pkg)
        ):
            auto = "-y" in args or "--yes" in args
            return f"`{base} {'-y ' if auto else ''}{pkg}` resolves the latest registry version at every launch"
    if base in {"uvx", "pipx"} or (base == "uv" and args[:2] == ["tool", "run"]):
        if base == "pipx" and args[:1] == ["run"]:
            args = args[1:]
        if base == "uv":
            args = args[2:]
        pkg = _package_arg(args)
        if pkg and not _PY_PINNED.match(pkg):
            return f"`{base} {pkg}` installs the latest PyPI version at every launch"
    joined = " ".join([server.command or "", *args])
    if re.search(r"\bpip3? install\b(?![^;&|]*==)", joined) or re.search(
        r"\b(curl|wget)\b[^|]*\|\s*(ba)?sh", joined
    ):
        return "server command installs or downloads code at launch"
    if base in {"docker", "podman"} and "run" in args:
        image = _docker_image(args[args.index("run") + 1 :])
        if (
            image
            and "@sha256:" not in image
            and (":" not in image.split("/")[-1] or image.endswith(":latest"))
        ):
            return f"`{base} run {image}` uses a mutable image tag"
    return None


_DOCKER_VALUE_FLAGS = {
    "-e",
    "--env",
    "--env-file",
    "-v",
    "--volume",
    "--name",
    "--network",
    "--net",
    "-p",
    "--publish",
    "--mount",
    "-w",
    "--workdir",
    "--entrypoint",
    "-u",
    "--user",
    "-l",
    "--label",
    "--platform",
    "--pull",
    "-m",
    "--memory",
    "--cpus",
    "--add-host",
}


def _docker_image(args: list[str]) -> str | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _DOCKER_VALUE_FLAGS:
            i += 2
            continue
        if not arg.startswith("-"):
            return arg
        i += 1
    return None


@check("HG-MCP-001", "mcp")
def unpinned(rule: Rule, subject: McpSubject) -> Iterator[Hit]:
    for server in subject.servers:
        why = unpinned_launch(server)
        if why:
            yield Hit(
                message=f"MCP server `{server.name}`: {why}",
                location=server.source,
                harness=server.harness,
                key=server.name,
            )


@check("HG-MCP-002", "mcp")
def insecure_remote(rule: Rule, subject: McpSubject) -> Iterator[Hit]:
    for server in subject.servers:
        if not server.url:
            continue
        parsed = urlparse(server.url)
        host = (parsed.hostname or "").lower()
        if host in {"0.0.0.0", "*"} or "*" in host:  # noqa: S104 - detecting, not binding
            yield Hit(
                message=f"MCP server `{server.name}` binds/points to a wildcard host ({host})",
                location=server.source,
                harness=server.harness,
                severity=Severity.HIGH,
                key=server.name,
            )
        elif parsed.scheme == "http" and host not in LOCAL_HOSTS:
            yield Hit(
                message=f"MCP server `{server.name}` uses plaintext HTTP to {host}",
                location=server.source,
                harness=server.harness,
                severity=Severity.HIGH,
                key=server.name,
            )
        elif host not in LOCAL_HOSTS and not {h.lower() for h in server.headers} & AUTH_HEADERS:
            yield Hit(
                message=f"Remote MCP server `{server.name}` ({host}) declares no auth header "
                "(OAuth may still apply; verify)",
                location=server.source,
                harness=server.harness,
                severity=Severity.LOW,
                key=server.name,
            )


def _secret_args(args: list[str]) -> Iterator[tuple[int, str]]:
    """Arguments holding a literal secret: `--api-key=<value>`, `--token <value>`, `KEY=<value>`."""
    for i, arg in enumerate(args):
        flag, eq, value = arg.partition("=")
        if arg.startswith("-"):
            if not (eq and SECRET_NAME.search(flag)):  # only credential-named `--flag=value`
                continue
            candidate, key = value, flag
        elif arg.startswith(("/", ".", "@", "http")):
            continue
        else:
            previous = args[i - 1] if i > 0 else ""
            candidate = arg.split("=", 1)[-1]
            key = previous if previous.startswith("-") else (flag if eq else "")
        if not looks_like_placeholder(candidate) and is_secret_value(candidate, key=key or None):
            yield i, key


def _url_secret(url: str) -> bool:
    """A literal secret in the URL path, query (`?api_key=…`) or userinfo (`user:pass@`)."""
    if any(find_secrets(url)):
        return True
    parsed = urlparse(url)
    if parsed.password and is_secret_value(parsed.password, key="password"):
        return True
    return any(
        SECRET_NAME.search(k) and not looks_like_placeholder(v) and is_secret_value(v, key=k)
        for k, v in parse_qsl(parsed.query)
    )


def _command_secret(command: str) -> bool:
    """`env TOKEN=<value> npx pkg` style commands written as one string."""
    return any(find_secrets(command)) or any(True for _ in _secret_args(command.split()))


@check("HG-MCP-003", "mcp")
def inline_secrets(rule: Rule, subject: McpSubject) -> Iterator[Hit]:
    for server in subject.servers:
        keys = [k for k, v in server.env.items() if is_secret_value(v, key=k)]
        keys += [f"header {k}" for k, v in server.headers.items() if is_secret_value(v, key=k)]
        keys += [f"arg #{i}" for i, _ in _secret_args(server.args)]
        keys += ["url"] if server.url and _url_secret(server.url) else []
        keys += ["command"] if server.command and _command_secret(server.command) else []
        if keys:
            shared = server.scope in {Scope.PROJECT, Scope.PROJECT_LOCAL}
            yield Hit(
                message=f"MCP server `{server.name}` has literal secret value(s) in {', '.join(keys[:5])}",
                location=server.source,
                harness=server.harness,
                severity=Severity.CRITICAL if shared else None,
                key=server.name,
            )


@check("HG-MCP-004", "mcp")
def tool_poisoning(rule: Rule, subject: McpSubject) -> Iterator[Hit]:
    min_score = int(rule.params.get("min_score", 4))
    for path, tools in subject.manifests:
        for tool, description in sorted(tools.items()):
            indicators = textscan.phrase_indicators(description) + textscan.hidden_unicode(
                description
            )
            indicators += [i for i in textscan.endpoints(description) if i.kind == "ip-address"]
            total = textscan.score(indicators)
            if total >= min_score and textscan.has_strong(indicators):
                kinds = ", ".join(sorted({i.kind for i in indicators}))
                yield Hit(
                    message=f"Tool `{tool}` description contains instruction-like content (score {total}: {kinds})",
                    location=Location(path=path),
                    severity=Severity.HIGH if total >= 8 else None,
                    key=tool,
                )


@check("HG-MCP-005", "mcp")
def repo_declared(rule: Rule, subject: McpSubject) -> Iterator[Hit]:
    for server in subject.servers:
        if (
            server.scope in {Scope.PROJECT, Scope.PROJECT_LOCAL}
            and server.enabled
            and server.command
        ):
            yield Hit(
                message=f"Repository declares local MCP server `{server.name}` "
                f"(`{_basename(server.command)}`), started for anyone who approves/opens the project",
                location=server.source,
                harness=server.harness,
                key=server.name,
            )


def load_manifest(path: Path) -> dict[str, str]:
    """Read a `tools/list` result (or a bare list of tools) saved as JSON."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("result", data).get("tools", data.get("tools", []))
    tools: dict[str, str] = {}
    for tool in data if isinstance(data, list) else []:
        if isinstance(tool, dict) and "name" in tool:
            text = str(tool.get("description", ""))
            schema = json.dumps(tool.get("inputSchema", {}))
            tools[str(tool["name"])] = text + "\n" + schema
    return tools
