"""`observe`: pure analysis functions, the CLI wiring, and (when Docker exists) one live run."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from harnesswatch.cli import app
from harnesswatch.observe import analyze
from harnesswatch.observe.runner import load_host_table

TABLE = load_host_table()


@pytest.mark.parametrize(
    ("host", "category"),
    [
        ("api.anthropic.com", "model-api"),
        ("statsig.anthropic.com", "telemetry"),
        ("o123.ingest.sentry.io", "telemetry"),
        ("registry.npmjs.org", "update"),
        ("ollama", "local"),
        ("172.18.0.5", "local"),
        ("8.8.8.8", "unknown"),
        ("evil.example", "unknown"),
        ("API.Anthropic.COM.", "model-api"),
    ],
)
def test_classify_host(host: str, category: str) -> None:
    assert analyze.classify_host(host, TABLE) == category


def test_merge_hosts_combines_sources_and_names_container_ips() -> None:
    proxy = analyze.parse_proxy_log(
        [
            json.dumps({"action": "blocked", "host": "statsig.anthropic.com", "port": 443}),
            json.dumps({"action": "allowed", "host": "ollama", "port": 11434}),
            "not json",
        ]
    )
    dns, flows = analyze.parse_net_log(
        [
            json.dumps({"kind": "dns", "name": "sentry.io"}),
            json.dumps({"kind": "dns", "name": "5.0.18.172.in-addr.arpa"}),
            json.dumps({"kind": "dns", "name": "ollama"}),
            json.dumps({"kind": "syn", "dst": "172.18.0.2", "port": 11434}),
            json.dumps({"kind": "quic", "dst": "1.2.3.4", "port": 443}),
        ]
    )
    hosts = analyze.merge_hosts(proxy, dns, flows, TABLE, {"172.18.0.2": "ollama"})
    by_key = {(h.host, h.port): h for h in hosts}
    assert by_key[("statsig.anthropic.com", 443)].allowed is False
    assert by_key[("statsig.anthropic.com", 443)].category == "telemetry"
    assert ("sentry.io", None) in by_key
    ollama = by_key[("ollama", 11434)]
    assert ollama.allowed is True and set(ollama.via) >= {"proxy", "syn", "dns"}
    assert ("ollama", None) not in by_key  # DNS-only entry folded into the port entry
    assert by_key[("1.2.3.4", 443)].via == ["quic"]
    assert not any("arpa" in h.host for h in hosts)


def test_files_permissions_categories_and_canary() -> None:
    diff = analyze.parse_docker_diff(
        [
            "C /home/u",
            "A /home/u/.tool/auth.json",
            "A /home/u/.tool/logs/session.jsonl",
            "A /home/u/.tool/settings.json",
            "A /workspace/CANARY_1.txt",
            "A /tmp/.hw_ready",
            "A /proc/1",
            "D /workspace/data/KEEP_ME.txt",
            "garbage",
        ]
    )
    headers = {
        "/home/u": {"mode": 0o755, "size": 0, "type": "dir"},
        "/home/u/.tool/auth.json": {"mode": 0o644, "size": 120, "type": "file"},
        "/home/u/.tool/logs/session.jsonl": {"mode": 0o600, "size": 9, "type": "file"},
        "/home/u/.tool/settings.json": {"mode": 0o640, "size": 9, "type": "file"},
    }
    files = analyze.build_files(diff, headers, {"/home/u/.tool/auth.json"})
    by_path = {f.path: f for f in files}
    assert "/tmp/.hw_ready" not in by_path and "/proc/1" not in by_path
    auth = by_path["/home/u/.tool/auth.json"]
    assert (auth.category, auth.world_readable, auth.canary_hit, auth.mode) == (
        "credential",
        True,
        True,
        "0o644",
    )
    assert by_path["/home/u/.tool/logs/session.jsonl"].category == "log"
    settings = by_path["/home/u/.tool/settings.json"]
    assert settings.category == "config" and settings.group_readable and not settings.world_readable
    assert by_path["/workspace/CANARY_1.txt"].category == "workspace"
    assert by_path["/workspace/data/KEEP_ME.txt"].change == "D"


def test_sandbox_evidence_from_processes() -> None:
    base_ns = {"user": "user:[1]", "mnt": "mnt:[1]", "net": "net:[1]", "pid": "pid:[1]"}
    records = [
        {
            "pid": 1,
            "cmd": "node cli.js",
            "ns": base_ns,
            "Seccomp": "2",
            "Seccomp_filters": "1",
            "NoNewPrivs": "0",
            "Uid": "1000\t1000\t1000\t1000",
        },
        {
            "pid": 7,
            "cmd": "/usr/bin/bwrap --unshare-net -- bash -c ls",
            "Seccomp": "2",
            "Seccomp_filters": "2",
            "NoNewPrivs": "1",
            "ns": {**base_ns, "net": "net:[9]", "mnt": "mnt:[9]"},
        },
        {"pid": 8, "cmd": "node cli.js", "ns": base_ns},
    ]
    procs, evidence = analyze.analyse_processes(records)
    assert evidence.observed
    assert evidence.sandbox_tools == ["bwrap"]
    assert set(evidence.new_namespaces) == {"net", "mnt"}
    assert evidence.extra_seccomp_filters and evidence.no_new_privs_set
    assert len(procs) == 2 and procs[0].uid == "1000"
    assert analyze.analyse_processes([]) == ([], analyze.SandboxEvidence())
    assert not analyze.SandboxEvidence().observed


def test_process_command_lines_are_redacted() -> None:
    secret = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    procs, _ = analyze.analyse_processes([{"pid": 1, "cmd": f"tool --token {secret}", "ns": {}}])
    assert secret not in procs[0].cmd and "[REDACTED]" in procs[0].cmd


def test_find_prompts_strips_ansi_dedupes_and_redacts() -> None:
    secret = "sk-ant-api03-" + "x7Y8z9" * 14
    text = (
        "\x1b[1mDo you trust the files in this folder?\x1b[0m\n"
        "Do you trust the files in this folder?\n"
        "Writing code...\n"
        f"Allow once? key={secret}\n"
    )
    prompts = analyze.find_prompts(text)
    assert prompts[0] == "Do you trust the files in this folder?"
    assert len(prompts) == 2 and secret not in prompts[1]
    assert (
        len(analyze.find_prompts("approve\n" * 3 + "\n".join(f"(y/n) {i}" for i in range(80))))
        == 50
    )


def test_cli_observe_reports_docker_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from harnesswatch.observe import runner

    def boom(spec: runner.ObserveSpec) -> None:
        raise runner.ObserveError("no docker")

    monkeypatch.setattr(runner, "run", boom)
    monkeypatch.setattr("harnesswatch.observe.run", boom)
    result = CliRunner().invoke(app, ["observe", "x", "--image", "img", "--", "true"])
    assert result.exit_code == 2


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0


@pytest.mark.docker
@pytest.mark.real_rules
@pytest.mark.skipif(not _docker_ok(), reason="docker not available")
def test_live_observe_run(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("synthetic\n")
    out = tmp_path / "report.json"
    script = (
        "curl -s -m 3 https://api.anthropic.com/ >/dev/null; "
        "curl -s -m 3 --noproxy '*' https://telemetry-probe.invalid/ >/dev/null; "
        "mkdir -p ~/.probe && echo HWCANARY-LIVE > ~/.probe/auth.json && chmod 644 ~/.probe/auth.json"
    )
    result = CliRunner().invoke(
        app,
        [
            "observe",
            "probe",
            "--image",
            "curlimages/curl:8.10.1",
            "--repo",
            str(repo),
            "--canary",
            "HWCANARY-LIVE",
            "--timeout",
            "60",
            "-o",
            str(out),
            "--",
            "sh",
            "-c",
            script,
        ],
    )
    assert result.exit_code == 0, result.output
    report = analyze.ObserveReport.model_validate_json(out.read_text())
    hosts = {(h.host, h.allowed) for h in report.hosts}
    assert ("api.anthropic.com", False) in hosts
    assert any(h.host == "telemetry-probe.invalid" for h in report.hosts)
    assert report.canary_files == 1
    assert report.credential_files[0].world_readable


def test_subtract_baseline_keeps_only_changes() -> None:
    baseline = {
        "/workspace": {"type": "dir", "mode": 0o755, "size": 0, "mtime": 1},
        "/workspace/README.md": {"type": "file", "mode": 0o644, "size": 5, "mtime": 1},
        "/workspace/calc.py": {"type": "file", "mode": 0o644, "size": 5, "mtime": 1},
        "/workspace/data/KEEP_ME.txt": {"type": "file", "mode": 0o644, "size": 5, "mtime": 1},
    }
    diff = [
        ("A", "/workspace"),
        ("A", "/workspace/README.md"),
        ("A", "/workspace/calc.py"),
        ("A", "/workspace/CANARY_1.txt"),
        ("A", "/home/agent/.tool"),
    ]
    headers = {
        **baseline,
        "/workspace": {"type": "dir", "mode": 0o755, "size": 0, "mtime": 9},
        "/workspace/calc.py": {"type": "file", "mode": 0o644, "size": 50, "mtime": 9},
    }
    assert analyze.subtract_baseline(diff, headers, baseline) == [
        ("C", "/workspace/calc.py"),
        ("A", "/workspace/CANARY_1.txt"),
        ("A", "/home/agent/.tool"),
        ("D", "/workspace/data/KEEP_ME.txt"),
    ]


def test_find_prompts_ignores_json_events() -> None:
    assert analyze.find_prompts('{"type":"system","permissionMode":"default"}\n') == []


def test_world_reachable_respects_ancestor_dirs() -> None:
    headers = {
        "/home/u/.a": {"mode": 0o755, "type": "dir"},
        "/home/u/.a/log.jsonl": {"mode": 0o644, "type": "file"},
        "/home/u/.b": {"mode": 0o700, "type": "dir"},
        "/home/u/.b/s.json": {"mode": 0o644, "type": "file"},
        "/home/u/.a/p.json": {"mode": 0o600, "type": "file"},
    }
    diff = [("A", p) for p in headers]
    files = {f.path: f for f in analyze.build_files(diff, headers)}
    assert files["/home/u/.a/log.jsonl"].world_reachable is True
    assert files["/home/u/.b/s.json"].world_reachable is False
    assert files["/home/u/.a/p.json"].world_reachable is False


def test_ensure_network_refuses_dual_homed_allowed_host(monkeypatch: pytest.MonkeyPatch) -> None:
    from harnesswatch.observe import runner

    def fake_docker(*args: str, check: bool = True, input_bytes: bytes | None = None) -> str:
        if args[:2] == ("network", "inspect"):
            internal = args[2] == "hw-bench-net"
            containers = {"c1": {}} if internal else {}
            return json.dumps([{"Internal": internal, "Containers": containers}])
        if args[0] == "inspect":
            return json.dumps(
                [
                    {
                        "Name": "/hw-ollama",
                        "NetworkSettings": {
                            "Networks": {"hw-bench-net": {"Aliases": ["ollama"]}, "hw-pull": {}}
                        },
                    }
                ]
            )
        return ""

    monkeypatch.setattr(runner, "docker", fake_docker)
    with pytest.raises(runner.ObserveError, match="non-internal"):
        runner.ensure_network("hw-bench-net", ["ollama:11434"])
    runner.ensure_network("hw-bench-net", ["other:1"])  # unrelated host: fine
