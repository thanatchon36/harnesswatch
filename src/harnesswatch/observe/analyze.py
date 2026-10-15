"""Turn raw `observe` captures into an `ObserveReport`. Pure functions, no Docker, easy to test.

Inputs (all produced by the sidecars or by Docker):
- the egress proxy log (JSONL: action, method, host, port);
- the capture sidecar's network events (DNS query names, SYNs, QUIC);
- process samples (JSONL from capture.py);
- `docker diff` lines plus tar headers of the changed paths (mode, size, type);
- the target's stdout/stderr, scanned only for permission and trust prompts.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
import stat
from collections.abc import Iterable
from pathlib import PurePosixPath
from typing import Any

from pydantic import BaseModel, Field

from harnesswatch.secrets import find_secrets

HostTable = dict[str, list[str]]


class HostContact(BaseModel):
    host: str
    port: int | None = None
    category: str
    via: list[str] = Field(default_factory=list)  # proxy | dns | syn | quic
    allowed: bool | None = None  # proxy verdict, None when never seen by the proxy
    count: int = 0


class FileRecord(BaseModel):
    path: str
    change: str  # A (added) | C (changed) | D (deleted)
    type: str = "file"  # file | dir | symlink
    mode: str | None = None
    size: int | None = None
    category: str = "other"  # credential | config | log | state | workspace | other
    group_readable: bool = False
    world_readable: bool = False
    world_reachable: bool | None = None  # o+r and every known ancestor dir o+x
    canary_hit: bool = False


class ProcessRecord(BaseModel):
    cmd: str
    uid: str | None = None
    seccomp: int | None = None
    seccomp_filters: int | None = None
    no_new_privs: bool | None = None
    new_namespaces: list[str] = Field(default_factory=list)
    sandbox_tool: str | None = None


class SandboxEvidence(BaseModel):
    sandbox_tools: list[str] = Field(default_factory=list)
    new_namespaces: list[str] = Field(default_factory=list)
    extra_seccomp_filters: bool = False
    no_new_privs_set: bool = False

    @property
    def observed(self) -> bool:
        return bool(
            self.sandbox_tools
            or self.new_namespaces
            or self.extra_seccomp_filters
            or self.no_new_privs_set
        )


class ObserveReport(BaseModel):
    harness: str
    image: str
    command: list[str]
    started: float
    duration_s: float
    exit_code: int | None
    timed_out: bool = False
    hosts: list[HostContact] = Field(default_factory=list)
    files: list[FileRecord] = Field(default_factory=list)
    credential_files: list[FileRecord] = Field(default_factory=list)
    processes: list[ProcessRecord] = Field(default_factory=list)
    sandbox: SandboxEvidence = Field(default_factory=SandboxEvidence)
    prompts: list[str] = Field(default_factory=list)
    canary_files: int | None = None  # files containing the synthetic canary (count only)
    artifacts: dict[str, str] = Field(default_factory=dict, exclude=True)  # bench-only files
    notes: list[str] = Field(default_factory=list)


# --- hosts ------------------------------------------------------------------------------------


def classify_host(host: str, table: HostTable) -> str:
    name = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local):
        return "local"
    for category, patterns in table.items():
        if any(fnmatch.fnmatchcase(name, p) for p in patterns):
            return category
    return "unknown"


def parse_proxy_log(lines: Iterable[str]) -> list[dict[str, Any]]:
    return [entry for entry in parse_jsonl(lines) if entry.get("host")]


def parse_net_log(lines: Iterable[str]) -> tuple[list[str], list[tuple[str, int, str]]]:
    """Return (DNS query names, [(dst ip, dst port, 'syn'|'quic')]) from the sidecar's net.jsonl."""
    queries: list[str] = []
    flows: list[tuple[str, int, str]] = []
    for event in parse_jsonl(lines):
        if event.get("kind") == "dns" and event.get("name"):
            queries.append(str(event["name"]).lower())
        elif event.get("kind") in {"syn", "quic"} and event.get("dst"):
            flows.append((str(event["dst"]), int(event.get("port") or 0), str(event["kind"])))
    return queries, flows


def parse_jsonl(lines: Iterable[str]) -> list[dict[str, Any]]:
    out = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            out.append(entry)
    return out


def merge_hosts(
    proxy: list[dict[str, Any]],
    dns: list[str],
    flows: list[tuple[str, int, str]],
    table: HostTable,
    ip_names: dict[str, str] | None = None,
) -> list[HostContact]:
    """One HostContact per (host, port); container IPs are mapped to their names first."""
    ip_names = ip_names or {}
    contacts: dict[tuple[str, int | None], HostContact] = {}

    def add(host: str, port: int | None, via: str, allowed: bool | None = None) -> None:
        key = (host, port)
        item = contacts.get(key)
        if item is None:
            item = contacts[key] = HostContact(
                host=host, port=port, category=classify_host(host, table)
            )
        item.count += 1
        if via not in item.via:
            item.via.append(via)
        if allowed is not None:
            item.allowed = allowed if item.allowed is None else item.allowed or allowed

    for entry in proxy:
        add(
            str(entry["host"]).lower(),
            int(entry.get("port") or 0) or None,
            "proxy",
            entry.get("action") == "allowed",
        )
    for name in dns:
        if name.endswith((".in-addr.arpa", ".ip6.arpa")):
            continue
        add(name, None, "dns")
    for ip, port, kind in flows:
        add(ip_names.get(ip, ip), port, kind)
    # A DNS-only entry for a host also reached on a port is redundant.
    reached = {h for (h, p) in contacts if p is not None}
    for host, maybe_port in list(contacts):
        if maybe_port is None and host in reached:
            via = contacts.pop((host, None)).via
            for (h, _p), item in contacts.items():
                if h == host:
                    item.via = sorted(set(item.via) | set(via))
    return sorted(contacts.values(), key=lambda c: (c.category, c.host, c.port or 0))


# --- files ------------------------------------------------------------------------------------

_CREDENTIAL_NAME = re.compile(
    r"(credential|auth|token|oauth|secret|apikey|api_key|\.netrc|keychain|session[-_]?key|"
    r"\.pem$|\.key$|id_rsa|id_ed25519)",
    re.IGNORECASE,
)
_LOG_NAME = re.compile(r"(\.log$|/logs?/|transcript|history|\.jsonl$|/sessions?/|trajector)", re.I)
_CONFIG_NAME = re.compile(r"(\.json$|\.jsonc$|\.toml$|\.ya?ml$|\.ini$|config|settings|rc$)", re.I)
IGNORED_PREFIXES = ("/proc", "/sys", "/dev", "/tmp/.hw_ready", "/hw")


def parse_docker_diff(lines: Iterable[str]) -> list[tuple[str, str]]:
    out = []
    for line in lines:
        change, _, path = line.strip().partition(" ")
        if change in {"A", "C", "D"} and path and not path.startswith(IGNORED_PREFIXES):
            out.append((change, path))
    return out


def subtract_baseline(
    diff: list[tuple[str, str]],
    headers: dict[str, dict[str, Any]],
    baseline: dict[str, dict[str, Any]],
) -> list[tuple[str, str]]:
    """Drop copied-in files the run left untouched; report the ones it changed or deleted.

    The workspace is copied in before start, so `docker diff` lists every repo file as added.
    """
    out = []
    present = set()
    for change, path in diff:
        present.add(path)
        before = baseline.get(path)
        if before is None:
            out.append((change, path))
            continue
        after = headers.get(path, {})
        same = all(after.get(k) == before.get(k) for k in ("mode", "size", "mtime"))
        if not same and before.get("type") != "dir":
            out.append(("C", path))
    out.extend(("D", path) for path in sorted(baseline) if path not in present)
    return out


def categorise_file(path: str, workspace: str = "/workspace") -> str:
    if path == workspace or path.startswith(workspace + "/"):
        return "workspace"
    if _CREDENTIAL_NAME.search(PurePosixPath(path).name) or "/credentials" in path:
        return "credential"
    if _LOG_NAME.search(path):
        return "log"
    if _CONFIG_NAME.search(PurePosixPath(path).name):
        return "config"
    if "/." in path or "/.cache/" in path or "/.local/" in path:
        return "state"
    return "other"


def build_files(
    diff: list[tuple[str, str]],
    headers: dict[str, dict[str, Any]],
    canary_paths: set[str] | None = None,
    workspace: str = "/workspace",
) -> list[FileRecord]:
    """Combine `docker diff` with tar headers {path: {mode, size, type}}."""
    canary_paths = canary_paths or set()
    records = []
    for change, path in diff:
        head = headers.get(path, {})
        mode = head.get("mode")
        record = FileRecord(
            path=path,
            change=change,
            type=head.get("type", "file"),
            mode=oct(mode) if isinstance(mode, int) else None,
            size=head.get("size"),
            category=categorise_file(path, workspace),
            group_readable=bool(isinstance(mode, int) and mode & stat.S_IRGRP),
            world_readable=bool(isinstance(mode, int) and mode & stat.S_IROTH),
            canary_hit=path in canary_paths,
        )
        if isinstance(mode, int):
            record.world_reachable = bool(mode & stat.S_IROTH) and _ancestors_traversable(
                path, headers
            )
        records.append(record)
    return records


def _ancestors_traversable(path: str, headers: dict[str, dict[str, Any]]) -> bool:
    """Other users can reach `path` unless a known ancestor directory lacks o+x.

    Ancestors missing from `headers` (unchanged image directories) are assumed traversable,
    which matches the bench image (home 0755) but is reported as an assumption.
    """
    for parent in PurePosixPath(path).parents:
        mode = headers.get(str(parent), {}).get("mode")
        if isinstance(mode, int) and not mode & stat.S_IXOTH:
            return False
    return True


# --- processes and sandboxing -----------------------------------------------------------------

SANDBOX_TOOLS = (
    "bwrap",
    "bubblewrap",
    "sandbox-exec",
    "firejail",
    "nsjail",
    "landrun",
    "codex-linux-sandbox",
    "minijail",
    "gvisor",
    "runsc",
    "srt",
)


def _redact(text: str) -> str:
    for match in sorted(find_secrets(text), key=lambda m: m.start, reverse=True):
        text = text[: match.start] + "[REDACTED]" + text[match.end :]
    return text


def analyse_processes(records: list[dict[str, Any]]) -> tuple[list[ProcessRecord], SandboxEvidence]:
    """Compare every process against the target's PID 1 (the container's baseline)."""
    if not records:
        return [], SandboxEvidence()
    base = next((r for r in records if r.get("pid") == 1), records[0])
    base_ns = base.get("ns", {})
    base_filters = _int(base.get("Seccomp_filters"))
    base_nnp = base.get("NoNewPrivs") == "1"
    evidence = SandboxEvidence()
    out: list[ProcessRecord] = []
    seen_cmds: set[str] = set()
    for rec in records:
        ns = rec.get("ns", {})
        new_ns = sorted(k for k, v in ns.items() if v and base_ns.get(k) and v != base_ns[k])
        filters = _int(rec.get("Seccomp_filters"))
        cmd = _redact(str(rec.get("cmd", "")))
        argv0 = PurePosixPath(cmd.split(" ", 1)[0]).name if cmd else str(rec.get("Name", ""))
        tool = next((t for t in SANDBOX_TOOLS if argv0 == t or argv0.startswith(t + "-")), None)
        nnp = rec.get("NoNewPrivs") == "1"
        if tool and tool not in evidence.sandbox_tools:
            evidence.sandbox_tools.append(tool)
        for name in new_ns:
            if name not in evidence.new_namespaces:
                evidence.new_namespaces.append(name)
        if filters is not None and base_filters is not None and filters > base_filters:
            evidence.extra_seccomp_filters = True
        if nnp and not base_nnp:
            evidence.no_new_privs_set = True
        key = cmd or argv0
        if key in seen_cmds:
            continue
        seen_cmds.add(key)
        out.append(
            ProcessRecord(
                cmd=cmd[:200],
                uid=str(rec.get("Uid", "")).split("\t")[0] or None,
                seccomp=_int(rec.get("Seccomp")),
                seccomp_filters=filters,
                no_new_privs=nnp,
                new_namespaces=new_ns,
                sandbox_tool=tool,
            )
        )
    return out, evidence


def _int(value: Any) -> int | None:
    try:
        return int(str(value).split()[0])
    except (ValueError, IndexError):
        return None


# --- prompts ----------------------------------------------------------------------------------

_PROMPT = re.compile(
    r"(do you trust|trust (this|the) (folder|workspace|directory|files)|"
    r"\(y/n\)|\[y/N\]|\[Y/n\]|allow (this|once|always)|approve|permission|"
    r"requires? approval|authentication required|log ?in|sign ?in)",
    re.IGNORECASE,
)


def find_prompts(output: str, limit: int = 50) -> list[str]:
    prompts: list[str] = []
    for raw in output.splitlines():
        line = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", raw).strip()
        if line and not line.startswith(("{", "[")) and _PROMPT.search(line):
            text = _redact(line)[:200]
            if text not in prompts:
                prompts.append(text)
        if len(prompts) >= limit:
            break
    return prompts
