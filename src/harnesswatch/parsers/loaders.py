"""Format loaders: JSON, JSONC (comments + trailing commas), TOML, YAML, Markdown front matter."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

MAX_CONFIG_BYTES = 5_000_000
# Untrusted configs: no real harness config nests this deep or expands to this many nodes. Deeper
# input would overflow libyaml's C stack or our recursive walkers; YAML alias trees ("billion
# laughs") would otherwise expand to ~10^9 nodes from a 1 KB file.
MAX_DEPTH = 64
MAX_NODES = 1_000_000
_SafeLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # libyaml when available: ~10x faster


def load_yaml(text: str) -> Any:
    """`yaml.safe_load` semantics, using the C loader when PyYAML was built with libyaml."""
    return yaml.load(text, Loader=_SafeLoader)  # noqa: S506 - a SafeLoader subclass


class ConfigParseError(ValueError):
    pass


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving string literals intact.

    Single-quoted (JSON5) strings are strings too: `'http://x'` holds no comment.
    """
    out: list[str] = []
    i, n = 0, len(text)
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
        elif ch in "\"'":
            quote = ch
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
        else:
            out.append(ch)
            i += 1
    return _drop_trailing_commas("".join(out))


def _drop_trailing_commas(text: str) -> str:
    """Remove commas directly before `}` or `]` (ignoring whitespace), outside strings."""
    out: list[str] = []
    quote = ""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
            out.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


_BARE_KEY = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def json5_to_json(text: str) -> str:
    """Normalise the common JSON5 extras (bare keys, single-quoted strings) after comments are gone."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            body = text[i + 1 : j]
            if ch == "'":
                body = body.replace("\\'", "'").replace('"', '\\"')
            out.append('"' + body + '"')
            i = j + 1
            continue
        match = _BARE_KEY.match(text, i)
        if match and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$.-")):
            rest = text[match.end() :].lstrip()
            if rest.startswith(":"):
                out.append('"' + match.group() + '"')
                i = match.end()
                continue
        out.append(ch)
        i += 1
    return "".join(out)


_FRONT_MATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)


def _loads_relaxed(text: str) -> Any:
    stripped = strip_jsonc(text)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return json.loads(json5_to_json(stripped))  # e.g. OpenClaw's JSON5 openclaw.json


def _check_yaml_events(text: str) -> None:
    """Reject YAML that nests too deep or whose aliases expand too far, before composing it.

    Streams parser events (libyaml's parser is iterative), tracking the expanded size of each
    anchored node. An alias to a node that is still open is a self-reference.
    """
    stack: list[list[Any]] = []  # [expanded size, anchor] per open collection
    sizes: dict[str, int] = {}
    for event in yaml.parse(text, Loader=_SafeLoader):
        if isinstance(event, yaml.CollectionStartEvent):
            stack.append([1, event.anchor])
            if len(stack) > MAX_DEPTH:
                raise ConfigParseError(f"nested deeper than {MAX_DEPTH} levels")
            continue
        if isinstance(event, yaml.CollectionEndEvent):
            size, anchor = stack.pop()
        elif isinstance(event, yaml.ScalarEvent):
            size, anchor = 1, event.anchor
        elif isinstance(event, yaml.AliasEvent):
            if event.anchor not in sizes:
                raise ConfigParseError(f"recursive or undefined alias *{event.anchor}")
            size, anchor = sizes[event.anchor], None
        else:
            continue
        if anchor:
            sizes[anchor] = size
        if stack:
            stack[-1][0] += size
            size = stack[-1][0]
        if size > MAX_NODES:
            raise ConfigParseError(f"aliases expand to more than {MAX_NODES} nodes")


def _check_depth(data: Any) -> None:
    """Iteratively reject parsed data deeper than MAX_DEPTH (the walkers recurse)."""
    pending: list[tuple[Any, int]] = [(data, 0)]
    while pending:
        node, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise ConfigParseError(f"nested deeper than {MAX_DEPTH} levels")
        if isinstance(node, dict):
            pending.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            pending.extend((v, depth + 1) for v in node)


def _load_untrusted_yaml(text: str) -> Any:
    _check_yaml_events(text)
    return load_yaml(text)


def parse_text(text: str, fmt: str) -> Any:
    """Parse untrusted config text; any malformed or hostile input raises `ConfigParseError`."""
    try:
        data = _parse(text, fmt)
    except RecursionError as exc:
        raise ConfigParseError(f"nested deeper than {MAX_DEPTH} levels") from exc
    except (ValueError, yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
        if isinstance(exc, ConfigParseError):
            raise
        raise ConfigParseError(str(exc)) from exc
    _check_depth(data)
    return data


def _parse(text: str, fmt: str) -> Any:
    if fmt == "json":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return _loads_relaxed(text)  # many "json" configs tolerate comments
    if fmt == "jsonc":
        return _loads_relaxed(text)
    if fmt == "toml":
        return tomllib.loads(text)
    if fmt == "yaml":
        return _load_untrusted_yaml(text)
    if fmt == "markdown":
        match = _FRONT_MATTER.match(text)
        return _load_untrusted_yaml(match.group(1)) if match else None
    return None


def load_file(path: Path, fmt: str) -> Any:
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ConfigParseError(f"{path.name}: larger than {MAX_CONFIG_BYTES} bytes")
    text = path.read_bytes().decode("utf-8", errors="replace").lstrip("﻿")
    if not text.strip():
        return None
    return parse_text(text, fmt)


_MISSING = object()


def get_dotted(data: Any, key: str, default: Any = None) -> Any:
    """Look up `a.b.c`, also matching flat keys that contain dots (VS Code style settings)."""
    value = _get(data, key)
    return default if value is _MISSING else value


def _get(data: Any, key: str) -> Any:
    if not isinstance(data, dict):
        return _MISSING
    if key in data:
        return data[key]
    parts = key.split(".")
    for i in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:i])
        if head in data:
            found = _get(data[head], ".".join(parts[i:]))
            if found is not _MISSING:
                return found
    return _MISSING


def has_dotted(data: Any, key: str) -> bool:
    return _get(data, key) is not _MISSING


def _split_key(key: str) -> list[str]:
    """Split a dotted key; `"quoted.parts"` stay whole and `<placeholder>` becomes `*`."""
    parts: list[str] = []
    current = ""
    quoted = False
    for ch in key:
        if ch == '"':
            quoted = not quoted
        elif ch == "." and not quoted:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    return ["*" if p.startswith("<") and p.endswith(">") else p for p in parts]


def get_all(data: Any, key: str) -> list[Any]:
    """Values at a dotted key where `*` / `<name>` segments match any map key."""
    parts = _split_key(key)
    if "*" not in parts and '"' not in key:
        value = _get(data, key)
        return [] if value is _MISSING else [value]
    nodes = [data]
    for part in parts:
        nxt: list[Any] = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            if part == "*":
                nxt.extend(node.values())
            elif part in node:
                nxt.append(node[part])
        nodes = nxt
    return nodes
