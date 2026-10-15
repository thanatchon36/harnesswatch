import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from harnesswatch.cli import app
from harnesswatch.inventory import (
    classify_install,
    exec_version,
    inventory_profile,
    run_inventory,
    static_version,
)
from harnesswatch.models import HarnessProfile


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return home


def _profile(**extra: object) -> HarnessProfile:
    data: dict[str, object] = {
        "id": "demo",
        "name": "Demo",
        "binaries": ["demo"],
        "state_dirs": ["~/.demo"],
        "credential_files": ["~/.demo/creds.json"],
        "config_files": [
            {
                "path": ".demo/settings.json",
                "scope": "project",
                "format": "json",
                "kind": "settings",
            },
            {
                "path": "~/.demo/settings.json",
                "scope": "user",
                "format": "json",
                "kind": "settings",
            },
        ],
        "instruction_files": ["DEMO.md", ".demo/rules/*.md"],
        "mcp": {"files": [".demo/mcp.json"]},
        "packages": [{"ecosystem": "pypi", "name": "demo-agent"}],
    }
    data.update(extra)
    return HarnessProfile.model_validate(data)


def _exe(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(0o755)
    return path


def test_native_installer_version_from_path(home: Path) -> None:
    target = _exe(home / ".local/share/demo/versions/1.2.3", "#!/bin/sh\n")
    bindir = home / ".local/bin"
    bindir.mkdir(parents=True)
    (bindir / "demo").symlink_to(target)
    item = inventory_profile(_profile(), None, search_path=str(bindir))
    assert item.binaries[0].version == "1.2.3"
    assert item.binaries[0].install_method == "native-installer"
    assert item.binaries[0].path == "~/.local/bin/demo"


def test_npm_version_from_package_json(tmp_path: Path) -> None:
    pkg = tmp_path / "lib/node_modules/demo"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "demo", "version": "0.9.1"}))
    cli = _exe(pkg / "bin/cli.js", "#!/usr/bin/env node\n")
    assert classify_install(cli) == "npm"
    assert static_version(cli, _profile()) == "0.9.1"


def test_pip_version_from_dist_info(tmp_path: Path) -> None:
    venv = tmp_path / "venv"
    (venv / "lib/python3.12/site-packages/demo_agent-4.5.6.dist-info").mkdir(parents=True)
    _exe(venv / "bin/python", "")
    script = _exe(venv / "bin/demo", f"#!{venv}/bin/python\nimport demo\n")
    assert classify_install(script) == "pip"
    assert static_version(script, _profile()) == "4.5.6"


@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/opt/homebrew/Cellar/demo/1/bin/demo", "homebrew"),
        ("/home/u/.cargo/bin/demo", "cargo"),
        ("/home/u/go/bin/demo", "go"),
        ("/snap/bin/demo", "snap"),
        ("/usr/bin/demo", "unknown"),
    ],
)
def test_classify_install(path: str, method: str) -> None:
    assert classify_install(Path(path)) == method


def test_exec_version_opt_in(tmp_path: Path) -> None:
    script = _exe(tmp_path / "demo", "#!/bin/sh\necho 'demo v7.8.9 (build)'\n")
    assert exec_version(script) == "7.8.9"
    assert exec_version(tmp_path / "missing") is None


def test_state_dirs_permissions_and_repo_files(home: Path, tmp_path: Path) -> None:
    state = home / ".demo"
    state.mkdir()
    state.chmod(0o755)
    (state / "creds.json").write_text("{}")
    (state / "creds.json").chmod(0o644)
    repo = tmp_path / "repo"
    (repo / ".demo/rules").mkdir(parents=True)
    (repo / ".demo/settings.json").write_text("{}")
    (repo / ".demo/rules/a.md").write_text("x")
    (repo / "DEMO.md").write_text("x")
    item = inventory_profile(_profile(), repo, search_path=str(tmp_path / "nobin"))
    assert item.state_dirs[0].world_readable
    assert item.credential_files[0].path == "~/.demo/creds.json"
    assert item.credential_files[0].mode == "0o644"
    assert sorted(item.repo_files) == [".demo/rules/a.md", ".demo/settings.json", "DEMO.md"]
    assert run_inventory((_profile(id="none", state_dirs=[], credential_files=[]),), None) == []


def test_cli_inventory_json(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "CLAUDE.md").write_text("hello")
    monkeypatch.setenv("PATH", str(tmp_path / "nobin"))
    result = CliRunner().invoke(app, ["inventory", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert any("CLAUDE.md" in i["repo_files"] for i in data)
    assert str(home) not in result.stdout
    table = CliRunner().invoke(app, ["inventory", str(tmp_path)], env={"COLUMNS": "200"})
    assert table.exit_code == 0
    assert os.sep in table.stdout or "CLAUDE.md" in table.stdout
