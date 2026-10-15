"""Profile-driven parser: one settings/MCP/hooks file → `HarnessConfig` in the common schema.

Most harnesses spell the same concepts with different keys; the harness profile supplies the
spelling (config key paths, MCP field names, auto-approve values), so this module stays generic.
Harness-specific quirks live in `parsers/<harness>.py` and are applied after this pass.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from harnesswatch.models import (
    ConfigFileSpec,
    HarnessConfig,
    HarnessProfile,
    Hook,
    Location,
    McpServer,
    Scope,
)
from harnesswatch.parsers.loaders import get_all, get_dotted, has_dotted
from harnesswatch.secrets import is_secret_value

SECRET_KEY = re.compile(r"(?i)(?:api[_\-]?key|secret|token|passw(?:or)?d|credential|auth)$")


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v if isinstance(v, str) else str(v) for v in value]
    if isinstance(value, dict):  # {"pattern": "allow"} style maps
        return [f"{k}={v}" if not isinstance(v, dict) else k for k, v in value.items()]
    return [str(value)]


def _str_map(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): "" if v is None else str(v) for k, v in value.items()}
    if isinstance(value, list):  # ["KEY=value", ...]
        pairs = (str(v).partition("=") for v in value)
        return {k: v for k, _, v in pairs}
    return {}


def _matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, str):
        text = expected.strip()
        if text == "non-empty list":  # profiles describe list-valued flags in prose
            return isinstance(actual, list) and bool(actual)
        if text.startswith("["):  # '["*"]' means a list containing "*"
            try:
                wanted = json.loads(text)
            except ValueError:
                wanted = None
            if isinstance(wanted, list):
                return isinstance(actual, list) and any(item in actual for item in wanted)
        if isinstance(actual, bool):  # 'true' / 'false' spelled as strings in profiles
            return text.lower() == str(actual).lower()
    if isinstance(expected, bool) or isinstance(actual, bool):
        return actual is expected or (
            isinstance(actual, str) and str(expected).lower() == actual.lower()
        )
    if isinstance(expected, str) and isinstance(actual, str):
        return actual.strip().lower() == expected.strip().lower()
    if isinstance(actual, list):
        return any(_matches(a, expected) for a in actual)
    return bool(actual == expected)


def auto_approve(profile: HarnessProfile, data: Any) -> list[str]:
    """Every documented approve-everything `key=value` present in `data`."""
    if profile.permissions is None:
        return []
    hits = []
    for item in profile.permissions.auto_approve_values:
        if " " in item.key.replace('" ', "").replace(' "', ""):
            continue  # UI-only settings are documented with prose keys; they cannot match
        if any(_matches(actual, item.value) for actual in get_all(data, item.key)):
            hits.append(f"{item.key}={item.value}")
    return hits


def mcp_servers(
    profile: HarnessProfile, data: Any, location: Location, scope: Scope, key: str | None = None
) -> list[McpServer]:
    spec = profile.mcp
    servers_key = key if key is not None else (spec.servers_key if spec else "mcpServers")
    if servers_key is None:
        return []
    fields = {
        "command": "command",
        "args": "args",
        "env": "env",
        "url": "url",
        "headers": "headers",
        "type": "type",
    }
    if spec:
        fields.update({k: v for k, v in spec.server_fields.items() if isinstance(v, str)})
    raw = data if servers_key == "" else get_dotted(data, servers_key)
    entries: list[tuple[str, dict[str, Any]]] = []
    if isinstance(raw, dict):
        entries = [(str(name), entry) for name, entry in raw.items() if isinstance(entry, dict)]
    elif isinstance(raw, list):
        entries = [
            (str(entry.get("name", f"server-{i}")), entry)
            for i, entry in enumerate(raw)
            if isinstance(entry, dict)
        ]
    servers = []
    for name, entry in entries:
        command = entry.get(fields["command"])
        args = _as_list(entry.get(fields["args"]))
        if isinstance(command, list):  # OpenCode-style ["npx", "-y", "pkg"]
            parts = [str(c) for c in command]
            command, args = (parts[0] if parts else None), parts[1:] + args
        headers = _str_map(entry.get(fields["headers"]))
        # Codex/Grok spell header auth as env-var references; they count as an auth header.
        if isinstance(entry.get("bearer_token_env_var"), str):
            headers.setdefault("Authorization", "Bearer ${" + entry["bearer_token_env_var"] + "}")
        for header, var in _str_map(entry.get("env_http_headers")).items():
            headers.setdefault(header, "${" + var + "}")
        url = entry.get(fields["url"]) or entry.get("serverUrl") or entry.get("httpUrl")
        kind = str(entry.get(fields["type"]) or entry.get("transport") or "")
        transport = "stdio"
        if url:
            transport = "sse" if "sse" in kind.lower() else "http"
        disabled = entry.get("disabled") is True or entry.get("enabled") is False
        servers.append(
            McpServer(
                name=name,
                harness=profile.id,
                source=location,
                scope=scope,
                transport=transport,
                command=str(command) if command else None,
                args=args,
                env=_str_map(entry.get(fields["env"])),
                url=str(url) if url else None,
                headers=headers,
                enabled=not disabled,
            )
        )
    return servers


def _walk_hooks(node: Any, event: str, command_field: str) -> Iterator[tuple[str, str]]:
    # `command_field` may be dotted (`action.command`) or alternatives (`bash|command`).
    fields = [f.strip() for f in command_field.split("|") if f.strip()]
    if isinstance(node, dict):
        command = next(
            (
                c
                for c in (get_dotted(node, f) for f in fields)
                if (isinstance(c, str) and c.strip()) or (isinstance(c, list) and c)
            ),
            None,
        )
        if isinstance(command, str):
            yield event, command
            return  # a handler node: its children (e.g. `action`) describe the same hook
        if isinstance(command, list):
            yield event, " ".join(map(str, command))
            return
        for key, value in node.items():
            if key not in fields:
                yield from _walk_hooks(value, event, command_field)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_hooks(value, event, command_field)


def hooks(
    profile: HarnessProfile, data: Any, location: Location, scope: Scope, whole_file: bool = False
) -> list[Hook]:
    spec = profile.hooks
    if spec is None or not spec.supported:
        return []
    root = data if whole_file or not spec.config_key else get_dotted(data, spec.config_key)
    if root is None:
        return []
    out = []
    events = root.items() if isinstance(root, dict) else [("hook", root)]
    for event, node in events:
        for name, command in _walk_hooks(node, str(event), spec.command_field or "command"):
            out.append(
                Hook(event=name, command=command, harness=profile.id, source=location, scope=scope)
            )
    return out


def plaintext_credentials(data: Any, prefix: str = "") -> list[str]:
    """Dotted keys whose value is a literal secret (not a ${VAR} reference)."""
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, str):
                block = prefix.rsplit(".", 1)[-1].lower()
                # env blocks and HTTP header maps hold credentials under arbitrary names
                env_block = block in {"env", "environment", "envs", "headers", "http_headers"}
                if (env_block or SECRET_KEY.search(str(key))) and is_secret_value(
                    value, key=str(key)
                ):
                    found.append(path)
            else:
                found.extend(plaintext_credentials(value, path))
    elif isinstance(data, list):
        for i, value in enumerate(data):
            found.extend(plaintext_credentials(value, f"{prefix}[{i}]"))
    return found


def parse(profile: HarnessProfile, spec: ConfigFileSpec, data: Any, display: str) -> HarnessConfig:
    location = Location(path=display)
    config = HarnessConfig(harness=profile.id, source=location, scope=spec.scope, kind=spec.kind)
    if data is None:
        return config
    if spec.kind == "mcp" or (profile.mcp and _same_file(spec.path, profile.mcp.files)):
        override = getattr(spec, "servers_key", None)  # per-file spelling (e.g. VS Code "servers")
        key = (
            override
            if isinstance(override, str)
            else ("" if spec.kind == "mcp" and _root_is_map(profile, data) else None)
        )
        config.mcp_servers = mcp_servers(profile, data, location, spec.scope, key)
    if spec.kind == "hooks":
        config.hooks = hooks(
            profile, data, location, spec.scope, whole_file=not _has_hooks_key(profile, data)
        )
    elif spec.kind == "settings":
        config.hooks = hooks(profile, data, location, spec.scope)
    if spec.kind in {"settings", "mcp", "hooks"}:
        perms = profile.permissions
        if perms:
            mode = get_dotted(data, perms.key("mode") or "\0")
            config.permission_mode = str(mode) if isinstance(mode, str | bool) else None
            config.allow = _as_list(get_dotted(data, perms.key("allow") or "\0"))
            config.deny = _as_list(get_dotted(data, perms.key("deny") or "\0"))
        config.auto_approve_matches = auto_approve(profile, data)
        config.plaintext_credentials = plaintext_credentials(data)
    return config


def _same_file(path: str, files: list[str]) -> bool:
    return path in files


def _has_hooks_key(profile: HarnessProfile, data: Any) -> bool:
    key = profile.hooks.config_key if profile.hooks else None
    return bool(key) and has_dotted(data, key or "")


def _root_is_map(profile: HarnessProfile, data: Any) -> bool:
    """Some MCP files are the server map itself rather than `{"mcpServers": {...}}`."""
    key = profile.mcp.servers_key if profile.mcp else "mcpServers"
    if key is None:
        return False
    return key == "" or (isinstance(data, dict) and not has_dotted(data, key))


def find_files(
    profile: HarnessProfile, repo: Path | None, home: Path, include_user: bool
) -> Iterator[tuple[ConfigFileSpec, Path, str]]:
    from harnesswatch.resources import glob_paths, is_user_path

    specs = list(profile.config_files)
    known = {s.path for s in specs}
    if profile.mcp:
        for mcp_path in profile.mcp.files:
            if mcp_path not in known:
                scope = Scope.USER if is_user_path(mcp_path) else Scope.PROJECT
                fmt = (
                    "toml"
                    if mcp_path.endswith(".toml")
                    else "yaml"
                    if mcp_path.endswith((".yaml", ".yml"))
                    else "json"
                )
                specs.append(ConfigFileSpec(path=mcp_path, scope=scope, format=fmt, kind="mcp"))
    for spec in specs:
        if spec.kind not in {"settings", "mcp", "hooks", "agents"}:
            continue
        if is_user_path(spec.path):
            if not include_user:
                continue
            for path in glob_paths(spec.path, Path("/"), home):
                if path.is_file():
                    yield spec, path, _home_display(path, home)
        elif repo is not None:
            for path in glob_paths(spec.path, repo):
                if path.is_file():
                    yield spec, path, path.relative_to(repo).as_posix()


def _home_display(path: Path, home: Path) -> str:
    return "~/" + path.relative_to(home).as_posix() if path.is_relative_to(home) else str(path)
