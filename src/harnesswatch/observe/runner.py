"""Docker orchestration for `harnesswatch observe` (MISSION §1.1, §5.2).

The target runs in its own container on an internal Docker network, which has no route to the
internet. Two sidecars run beside it:
- an egress proxy (HTTP(S)_PROXY) that allows only the hosts in `allow`; everything else gets 403;
- a capture sidecar sharing the target's network and PID namespaces (packet headers plus /proc sampling).

The workspace is copied in, never bind-mounted, so `docker diff` sees every file the harness
writes. No host credential or directory is mounted into the target. Every docker call uses an
argument list; nothing goes through a shell.
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from harnesswatch.observe import analyze
from harnesswatch.resources import rules_dir

SIDECARS = Path(__file__).parent / "sidecars"
PYTHON_IMAGE = (
    "python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
)
DEFAULT_NETWORK = "hw-bench-net"
WAIT_FOR_READY = (
    'i=0; while [ ! -e /tmp/.hw_ready ] && [ "$i" -lt 300 ]; do sleep 0.1; i=$((i+1)); done; '
    'exec "$@"'
)
SNAPSHOT_ROOTS = ("/home", "/root", "/tmp", "/etc", "/var/tmp", "/opt", "/usr/local", "/workspace")


MAX_ARTIFACT_BYTES = 20_000_000  # cap on any single file read back from a container (M9)


class ObserveError(RuntimeError):
    pass


@dataclass
class ObserveSpec:
    harness: str
    image: str
    command: list[str]
    repo: Path | None = None
    workdir: str = "/workspace"
    env: dict[str, str] = field(default_factory=dict)
    allow: list[str] = field(default_factory=lambda: ["ollama:11434"])
    network: str = DEFAULT_NETWORK
    timeout: float = 300.0
    canary: str | None = None
    user: str | None = None
    keep: bool = False
    inject_dir: Path | None = None  # copied to /hw before start (bench runner, sink)
    collect: list[str] = field(default_factory=list)  # small text files read back after the run


def docker(*args: str, check: bool = True, input_bytes: bytes | None = None) -> str:
    proc = subprocess.run(
        ["docker", *args], capture_output=True, input=input_bytes, check=False, timeout=900
    )
    if check and proc.returncode != 0:
        raise ObserveError(
            f"docker {args[0]} failed: {proc.stderr.decode(errors='replace')[-400:]}"
        )
    return proc.stdout.decode(errors="replace")


def ensure_network(name: str, allow: list[str] | None = None) -> None:
    if docker("network", "inspect", name, check=False).strip() in {"", "[]"}:
        docker("network", "create", "--internal", name)
    info = json.loads(docker("network", "inspect", name))
    if not info or not info[0].get("Internal"):
        raise ObserveError(f"network {name} exists but is not --internal; refusing to run")
    # An allowed host that is also attached to a routable network is an egress path (H1).
    hosts = {target.split(":")[0] for target in allow or []}
    for cid in info[0].get("Containers") or {}:
        data = json.loads(docker("inspect", cid))[0]
        nets = data.get("NetworkSettings", {}).get("Networks", {})
        names = {data.get("Name", "").lstrip("/")} | set(nets.get(name, {}).get("Aliases") or [])
        if not names & hosts:
            continue
        for net in nets:
            details = json.loads(docker("network", "inspect", net))
            if details and not details[0].get("Internal"):
                raise ObserveError(
                    f"allowed host {sorted(names & hosts)[0]} is also on non-internal network "
                    f"{net}; disconnect it first"
                )


def load_host_table() -> analyze.HostTable:
    data = yaml.safe_load((rules_dir() / "observe_hosts.yaml").read_text(encoding="utf-8"))
    return {str(k): [str(p) for p in v] for k, v in data.items()}


def network_names(network: str) -> dict[str, str]:
    """Map container IPs on the network to container names (so SYNs show `ollama`, not IPs)."""
    info = json.loads(docker("network", "inspect", network))
    names: dict[str, str] = {}
    for container in (info[0].get("Containers") or {}).values():
        ip = str(container.get("IPv4Address", "")).split("/")[0]
        if ip:
            names[ip] = str(container.get("Name", ip))
    return names


def _tar_headers(
    container: str, roots: set[str], wanted: set[str] | None, canary: bytes | None
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Mode/size/mtime of `wanted` paths (all paths when None) under `roots`; canary hits."""
    headers: dict[str, dict[str, Any]] = {}
    hits: set[str] = set()
    for root in sorted(roots):
        proc = subprocess.run(
            ["docker", "cp", f"{container}:{root}", "-"],
            capture_output=True,
            check=False,
            timeout=300,
        )
        if proc.returncode != 0:
            continue
        parent = str(PurePosixPath(root).parent)
        with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
            for member in tar:
                path = str(PurePosixPath(parent) / member.name)
                if wanted is not None and path not in wanted:
                    continue
                kind = "dir" if member.isdir() else "symlink" if member.issym() else "file"
                headers[path] = {
                    "mode": member.mode,
                    "size": member.size,
                    "mtime": member.mtime,
                    "type": kind,
                }
                if canary and member.isfile() and member.size < 20_000_000:
                    handle = tar.extractfile(member)
                    if handle is not None and canary in handle.read():
                        hits.add(path)
    return headers, hits


def run(spec: ObserveSpec) -> analyze.ObserveReport:
    ensure_network(spec.network, spec.allow)
    run_id = uuid.uuid4().hex[:8]
    target, proxy, capture = (f"hw-obs-{run_id}-{n}" for n in ("target", "proxy", "capture"))
    proxy_url = f"http://{proxy}:3128"
    no_proxy = ",".join(["localhost", "127.0.0.1", *(a.split(":")[0] for a in spec.allow)])
    env = {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
        **spec.env,
    }
    created: list[str] = []
    started = time.time()
    try:
        docker(
            "run",
            "-d",
            "--name",
            proxy,
            "--network",
            spec.network,
            "-e",
            "HW_ALLOW=" + ",".join(spec.allow),
            "-e",
            "HW_EGRESS_LOG=/tmp/egress.jsonl",
            "-v",
            f"{SIDECARS / 'egress_proxy.py'}:/proxy.py:ro",
            PYTHON_IMAGE,
            "python",
            "-u",
            "/proxy.py",
        )
        created.append(proxy)
        args = [
            "create",
            "--name",
            target,
            "--network",
            spec.network,
            "-w",
            spec.workdir,
            "--entrypoint",
            "/bin/sh",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            "512",
            "--memory",
            "4g",
        ]
        if spec.user:
            args += ["--user", spec.user]
        for key, value in env.items():
            args += ["-e", f"{key}={value}"]
        docker(*args, spec.image, "-c", WAIT_FOR_READY, "sh", *spec.command)
        created.append(target)
        if spec.repo is not None:
            docker("cp", "-a", f"{spec.repo.resolve()}/.", f"{target}:{spec.workdir}")
        if spec.inject_dir is not None:
            docker("cp", "-a", f"{spec.inject_dir.resolve()}/.", f"{target}:/hw")
        baseline: dict[str, dict[str, Any]] = {}
        if spec.repo is not None:
            baseline, _ = _tar_headers(target, {spec.workdir}, None, None)
        docker("start", target)
        docker(
            "run",
            "-d",
            "--name",
            capture,
            "--network",
            f"container:{target}",
            "--pid",
            f"container:{target}",
            "--cap-add",
            "NET_RAW",
            "--cap-add",
            "SYS_PTRACE",
            "-v",
            f"{SIDECARS / 'capture.py'}:/capture.py:ro",
            PYTHON_IMAGE,
            "python",
            "-u",
            "/capture.py",
        )
        created.append(capture)
        timed_out = False
        try:
            proc = subprocess.run(
                ["docker", "wait", target], capture_output=True, timeout=spec.timeout, check=False
            )
            exit_code: int | None = int(proc.stdout.decode().strip() or -1)
        except subprocess.TimeoutExpired:
            timed_out, exit_code = True, None
            docker("kill", target, check=False)
        duration = time.time() - started
        names = network_names(spec.network)
        docker("stop", "-t", "1", proxy, check=False)
        docker("stop", "-t", "1", capture, check=False)
        output = _logs(target)
        return _collect(
            spec,
            target,
            proxy,
            capture,
            output,
            names,
            started,
            duration,
            exit_code,
            timed_out,
            baseline,
        )
    finally:
        if not spec.keep:
            for name in created:
                docker("rm", "-f", name, check=False)


def _logs(container: str) -> str:
    proc = subprocess.run(
        ["docker", "logs", "--tail", "20000", container],
        capture_output=True,
        check=False,
        timeout=120,
    )
    return (proc.stdout + proc.stderr).decode(errors="replace")


def _read_from(container: str, path: str) -> str:
    proc = subprocess.run(
        ["docker", "cp", f"{container}:{path}", "-"],
        capture_output=True,
        check=False,
        timeout=300,
    )
    if proc.returncode != 0:
        return ""
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r:") as tar:
        member = tar.next()
        if member is None or not member.isfile():  # symlink planted by the agent: ignore (M2)
            return ""
        handle = tar.extractfile(member)
        return handle.read(MAX_ARTIFACT_BYTES).decode(errors="replace") if handle else ""


def _collect(
    spec: ObserveSpec,
    target: str,
    proxy: str,
    capture: str,
    output: str,
    names: dict[str, str],
    started: float,
    duration: float,
    exit_code: int | None,
    timed_out: bool,
    baseline: dict[str, dict[str, Any]],
) -> analyze.ObserveReport:
    table = load_host_table()
    proxy_log = analyze.parse_proxy_log(_read_from(proxy, "/tmp/egress.jsonl").splitlines())
    queries, flows = analyze.parse_net_log(_read_from(capture, "/out/net.jsonl").splitlines())
    hosts = analyze.merge_hosts(proxy_log, queries, flows, table, names)
    procs = []
    for line in _read_from(capture, "/out/procs.jsonl").splitlines():
        try:
            procs.append(json.loads(line))
        except ValueError:
            continue
    processes, sandbox = analyze.analyse_processes(procs)
    diff = analyze.parse_docker_diff(docker("diff", target, check=False).splitlines())
    wanted = {path for change, path in diff if change != "D"}
    roots = {r for r in SNAPSHOT_ROOTS if any(p == r or p.startswith(r + "/") for p in wanted)}
    canary = spec.canary.encode() if spec.canary else None
    headers, hits = _tar_headers(target, roots, wanted, canary)
    diff = analyze.subtract_baseline(diff, headers, baseline)
    files = analyze.build_files(diff, headers, hits, spec.workdir)
    artifacts = {path: _read_from(target, path) for path in spec.collect}
    notes = []
    if not procs:
        notes.append("no process samples captured (target exited before the sidecar sampled)")
    return analyze.ObserveReport(
        harness=spec.harness,
        image=spec.image,
        command=spec.command,
        started=started,
        duration_s=round(duration, 2),
        exit_code=exit_code,
        timed_out=timed_out,
        hosts=hosts,
        files=files,
        credential_files=[f for f in files if f.category == "credential" and f.type == "file"],
        processes=processes,
        sandbox=sandbox,
        prompts=analyze.find_prompts(output),
        canary_files=len(hits) if canary else None,
        artifacts=artifacts,
        notes=notes,
    )
