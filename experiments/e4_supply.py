"""E4 - supply-chain audit of the Tier-A harness packages (+ Claude Code, Grok Build, Copilot CLI).

Metadata only. Nothing is installed or executed on the host (ASSUMPTIONS A06):
  * npm registry metadata and lockfile resolution run in a disposable ``node:22-slim`` container
    (``npm view``; ``npm install --ignore-scripts --package-lock-only``);
  * PyPI closure runs ``uv pip compile --no-build`` inside a ``python:3.12-slim`` container;
  * installer scripts are downloaded as text and pattern-scanned, never run.

Usage: ``python experiments/e4_supply.py [--only id,id] [--workers N]``
Outputs: experiments/results/e4_supply.json, experiments/results/e4_sbom/<harness>.cdx.json,
paper/tables/e4_supply.{tex,md}.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import subprocess
import tomllib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx as requests  # httpx mirrors the requests API used here (declared dependency)
import yaml

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "experiments" / "results"
SBOM_DIR = RESULTS / "e4_sbom"
TABLES = ROOT / "paper" / "tables"
PROFILES = ROOT / "rules" / "harness_profiles"
ACCESS_DATE = date.today().isoformat()
NODE_IMAGE = "node:22-slim"
PY_IMAGE = "python:3.12-slim"
UA = {"User-Agent": "harnesswatch-e4/1.0 (research; metadata only)"}

# harness id -> pinned primary package (VERSIONS.md) and the GitHub release holding binaries.
# tag lists are tried in order; the repo is None when there is no usable release.
TARGETS: dict[str, dict[str, Any]] = {
    "aider": {
        "eco": "pypi",
        "name": "aider-chat",
        "version": "0.86.2",
        "gh": ("Aider-AI/aider", ["v0.86.2"]),
    },
    "cline": {
        "eco": "npm",
        "name": "cline",
        "version": "3.0.71",
        "gh": ("cline/cline", ["v3.0.71", "cli-v3.0.71"]),
    },
    "codex-cli": {
        "eco": "npm",
        "name": "@openai/codex",
        "version": "0.162.1",
        "gh": ("openai/codex", ["rust-v0.162.1"]),
    },
    "continue": {
        "eco": "npm",
        "name": "@continuedev/cli",
        "version": "1.5.47",
        "gh": ("continuedev/continue", ["v1.5.47", "cli-v1.5.47"]),
    },
    "crush": {
        "eco": "go",
        "name": "github.com/charmbracelet/crush",
        "version": "v0.98.1",
        "gh": ("charmbracelet/crush", ["v0.98.1"]),
    },
    "deepseek-harness": {
        "eco": "npm",
        "name": "@deepseek-ai/dsh",
        "version": "0.2.1-alpha.3",
        "gh": ("deepseek-ai/deepseek-harness", ["dsh-v0.2.1-alpha.3"]),
    },
    "gemini-cli": {
        "eco": "npm",
        "name": "@google/gemini-cli",
        "version": "0.64.0",
        "gh": ("google-gemini/gemini-cli", ["v0.64.0"]),
    },
    "goose": {
        "eco": "cargo",
        "name": "goose-cli",
        "version": "1.54.0",
        "gh": ("aaif-goose/goose", ["v1.54.0"]),
        "lock_ref": "v1.54.0",
    },
    "hermes-agent": {
        "eco": "pypi",
        "name": "hermes-agent",
        "version": "0.22.1",
        "gh": ("NousResearch/hermes-agent", ["v0.22.1"]),
    },
    "kilo-code": {
        "eco": "npm",
        "name": "@kilocode/cli",
        "version": "7.8.10",
        "gh": ("Kilo-Org/kilocode", ["v7.8.10", "cli-v7.8.10"]),
    },
    "kimi-cli": {
        "eco": "npm",
        "name": "@moonshot-ai/kimi-code",
        "version": "2.2.0",
        "gh": ("MoonshotAI/kimi-code", ["v2.2.0"]),
    },
    "mistral-vibe": {
        "eco": "pypi",
        "name": "mistral-vibe",
        "version": "2.26.1",
        "gh": ("mistralai/mistral-vibe", ["v2.26.1"]),
    },
    "oh-my-pi": {
        "eco": "npm",
        "name": "@oh-my-pi/pi-coding-agent",
        "version": "18.11.0",
        "gh": ("can1357/oh-my-pi", ["v18.11.0"]),
    },
    "openclaw": {
        "eco": "npm",
        "name": "openclaw",
        "version": "2026.10.3",
        "gh": ("openclaw/openclaw", ["v2026.10.3"]),
    },
    "opencode": {
        "eco": "npm",
        "name": "opencode-ai",
        "version": "1.19.0",
        "gh": ("anomalyco/opencode", ["v1.19.0"]),
    },
    "openhands": {
        "eco": "pypi",
        "name": "openhands",
        "version": "1.16.0",
        "gh": ("OpenHands/OpenHands-CLI", ["1.16.0", "v1.16.0"]),
    },
    "pi": {
        "eco": "npm",
        "name": "@earendil-works/pi-coding-agent",
        "version": "1.2.0",
        "gh": ("earendil-works/pi", ["v1.2.0"]),
    },
    "qwen-code": {
        "eco": "npm",
        "name": "@qwen-code/qwen-code",
        "version": "0.25.1",
        "gh": ("QwenLM/qwen-code", ["v0.25.1"]),
    },
    "roo-code": {
        "eco": "npm",
        "name": "@roo-code/cli",
        "version": "0.1.17",
        "gh": ("RooCodeInc/Roo-Code", ["cli-v0.1.17", "v0.1.17"]),
    },
    "warp": {
        "eco": "github-release",
        "name": "warpdotdev/warp",
        "version": "v0.2026.06.03.09.49.stable_00",
        "gh": ("warpdotdev/warp", ["v0.2026.06.03.09.49.stable_00"]),
        "lock_ref": "v0.2026.06.03.09.49.stable_00",
    },
    # Tier B / hybrid black-box: metadata only
    "claude-code": {
        "eco": "npm",
        "name": "@anthropic-ai/claude-code",
        "version": "2.1.300",
        "gh": ("anthropics/claude-code", ["v2.1.300"]),
    },
    "grok-build": {"eco": "npm", "name": "@xai-official/grok", "version": "1.0.52", "gh": None},
    "github-copilot": {
        "eco": "npm",
        "name": "@github/copilot",
        "version": "1.0.98",
        "gh": ("github/copilot-cli", ["v1.0.98"]),
    },
}

CHECKSUM_RE = re.compile(
    r"(?i)sha-?256|sha512|sha256sum|shasum|checksums?\b|\.sha256|openssl\s+dgst"
)
SIGNATURE_RE = re.compile(
    r"(?i)cosign|minisign|\bgpg\b|gpgv|sigstore|\.sig\b|\.asc\b|\bsignify\b|slsa-verifier"
    r"|gh\s+attestation\s+verify|codesign\s+--verify|signature"
)
ASSET_KINDS = {
    "checksum": re.compile(
        r"(?i)(\.sha256(sum)?|\.sha512|sha256sums?(\.txt)?|checksums?(\.txt)?|\.sha256\.txt)$"
    ),
    "signature": re.compile(
        r"(?i)(\.sig|\.asc|\.minisig|\.pem|\.sigstore(\.json)?|\.intoto\.jsonl|\.bundle)$"
    ),
    "sbom": re.compile(r"(?i)(sbom|\.spdx(\.json)?|\.cdx(\.json)?|cyclonedx|bom\.json)"),
}


# --------------------------------------------------------------------------- helpers


def run(cmd: list[str], timeout: int = 900, input_text: str | None = None) -> tuple[int, str, str]:
    p = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, input=input_text, check=False
    )
    return p.returncode, p.stdout, p.stderr


def docker(image: str, script: str, timeout: int = 900) -> tuple[int, str, str]:
    return run(["docker", "run", "--rm", "-i", image, "sh", "-c", script], timeout=timeout)


def purl(eco: str, name: str, version: str) -> str:
    if eco == "npm":
        return f"pkg:npm/{name.replace('@', '%40', 1)}@{version}"
    if eco == "pypi":
        return f"pkg:pypi/{name.lower().replace('_', '-')}@{version}"
    if eco == "cargo":
        return f"pkg:cargo/{name}@{version}"
    if eco == "go":
        return f"pkg:golang/{name}@{version}"
    return f"pkg:generic/{name}@{version}"


OSV_ECO = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "go": "Go"}


# --------------------------------------------------------------------------- npm


def parse_npm_view(text: str) -> dict[str, Any]:
    """Reduce ``npm view <pkg>@<ver> --json`` output to the audit fields."""
    d = json.loads(text)
    if isinstance(d, list):
        d = d[-1]
    scripts = d.get("scripts") or {}
    hooks = {k: scripts[k] for k in ("preinstall", "install", "postinstall") if k in scripts}
    dist = d.get("dist") or {}
    att = dist.get("attestations") or {}
    sigs = dist.get("signatures") or []
    lic = d.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    return {
        "install_hooks": hooks,
        "has_install_hooks": bool(hooks),
        "direct_dependencies": len(d.get("dependencies") or {}),
        "optional_dependencies": len(d.get("optionalDependencies") or {}),
        "bundled_dependencies": len(
            d.get("bundleDependencies") or d.get("bundledDependencies") or []
        )
        if isinstance(d.get("bundleDependencies") or d.get("bundledDependencies") or [], list)
        else None,
        "attestations_url": att.get("url"),
        "attestations_predicate": (att.get("provenance") or {}).get("predicateType"),
        "registry_signatures": len(sigs),
        "license": lic,
        "unpacked_size": dist.get("unpackedSize"),
        "repository": (d.get("repository") or {}).get("url")
        if isinstance(d.get("repository"), dict)
        else d.get("repository"),
    }


def parse_attestations(doc: dict[str, Any]) -> list[str]:
    """Predicate types in an npm attestations document (publish and/or SLSA provenance)."""
    out = []
    for a in doc.get("attestations", []):
        pt = a.get("predicateType")
        if pt:
            out.append(pt)
    return out


def parse_npm_lock(lock: dict[str, Any]) -> dict[str, Any]:
    """Transitive set from a package-lock.json (v2/v3), excluding the synthetic root."""
    comps: list[dict[str, Any]] = []
    with_hooks: list[str] = []
    for path, meta in (lock.get("packages") or {}).items():
        if path == "" or not path:
            continue
        name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
        ver = meta.get("version")
        if not ver:
            continue
        comps.append(
            {
                "name": name,
                "version": ver,
                "license": meta.get("license"),
                "optional": bool(meta.get("optional")),
                "dev": bool(meta.get("dev")),
            }
        )
        if meta.get("hasInstallScript"):
            with_hooks.append(f"{name}@{ver}")
    comps = [c for c in comps if not c["dev"]]
    uniq = {(c["name"], c["version"]) for c in comps}
    return {
        "components": comps,
        "transitive_packages": len(comps),
        "transitive_unique": len(uniq),
        "transitive_with_install_scripts": len(with_hooks),
        "install_script_packages": sorted(with_hooks)[:30],
    }


def measure_npm(name: str, version: str) -> dict[str, Any]:
    spec = f"{name}@{version}"
    res: dict[str, Any] = {"nulls": {}}
    rc, out, err = docker(NODE_IMAGE, f"npm view '{spec}' --json 2>/dev/null")
    if rc != 0 or not out.strip():
        probe = requests.get(
            f"https://registry.npmjs.org/{quote(name, safe='@')}", headers=UA, timeout=30
        )
        why = (
            "package not found on the npm registry (HTTP 404)"
            if probe.status_code == 404
            else f"npm view failed rc={rc}"
        )
        res["nulls"]["registry_metadata"] = why
        res["has_provenance"] = None
        return res
    res.update(parse_npm_view(out))
    res["provenance_url"] = res.get("attestations_url")
    if res.get("attestations_url"):
        try:
            r = requests.get(res["attestations_url"], headers=UA, timeout=30, follow_redirects=True)
            res["attestation_predicates"] = parse_attestations(r.json()) if r.is_success else []
        except (requests.HTTPError, ValueError) as e:
            res["attestation_predicates"] = []
            res["nulls"]["attestation_fetch"] = str(e)
    res["has_provenance"] = bool(res.get("attestations_url"))
    script = (
        "mkdir /w && cd /w && npm init -y >/dev/null 2>&1 && "
        f"npm install --ignore-scripts --package-lock-only --no-audit --no-fund '{spec}' >/dev/null 2>&1; "
        "cat package-lock.json"
    )
    rc, out, err = docker(NODE_IMAGE, script)
    try:
        lock = json.loads(out)
        res.update(parse_npm_lock(lock))
    except ValueError:
        res["nulls"]["transitive"] = f"lockfile resolution failed: {err[-200:] or out[-200:]}"
    return res


# --------------------------------------------------------------------------- PyPI


def parse_pypi_json(doc: dict[str, Any]) -> dict[str, Any]:
    info = doc.get("info", {})
    reqs = info.get("requires_dist") or []
    base = [r for r in reqs if "extra ==" not in r.replace("'", '"').replace('"', "")]
    files = doc.get("urls", [])
    return {
        "license": info.get("license_expression") or (info.get("license") or "")[:80] or None,
        "requires_dist": len(reqs),
        "direct_dependencies": len(base),
        "files": [{"filename": f["filename"], "packagetype": f["packagetype"]} for f in files],
        "has_wheel": any(f["packagetype"] == "bdist_wheel" for f in files),
        "has_sdist": any(f["packagetype"] == "sdist" for f in files),
    }


def parse_compile(text: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;#]+)", line.strip())
        if m:
            out.append({"name": m.group(1), "version": m.group(2)})
    return out


def parse_provenance(status: int, body: dict[str, Any] | None) -> dict[str, Any]:
    if status == 200 and body is not None:
        bundles = body.get("attestation_bundles", [])
        preds = [
            a.get("statement", a).get("predicateType") if isinstance(a, dict) else None
            for b in bundles
            for a in b.get("attestations", [])
        ]
        publishers = [b.get("publisher", {}).get("kind") for b in bundles]
        return {"present": True, "publishers": publishers, "predicates": [p for p in preds if p]}
    return {"present": False, "status": status}


def measure_pypi(name: str, version: str) -> dict[str, Any]:
    res: dict[str, Any] = {"nulls": {}}
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    res["metadata_url"] = url
    r = requests.get(url, headers=UA, timeout=30, follow_redirects=True)
    if not r.is_success:
        res["nulls"]["registry_metadata"] = (
            f"HTTP {r.status_code}: {name}=={version} is not published on PyPI"
        )
        res["has_provenance"] = None
        return res
    res.update(parse_pypi_json(r.json()))
    prov = []
    for f in res["files"]:
        pu = f"https://pypi.org/integrity/{name}/{version}/{f['filename']}/provenance"
        pr = requests.get(pu, headers=UA, timeout=30, follow_redirects=True)
        body = pr.json() if pr.status_code == 200 else None
        prov.append(
            {"filename": f["filename"], "url": pu, **parse_provenance(pr.status_code, body)}
        )
    res["provenance_files"] = prov
    res["has_provenance"] = any(p["present"] for p in prov)
    res["provenance_url"] = prov[0]["url"] if prov else None
    res["install_hooks"] = {}
    res["has_install_hooks"] = None
    res["nulls"]["install_hooks"] = (
        "PyPI has no install-script field; wheel installs run no code, sdist builds may "
        f"(wheel available: {res['has_wheel']})"
    )

    def compile_script(extra: str) -> str:
        return (
            "pip install -q uv >/dev/null 2>&1 && "
            f"echo '{name}=={version}' | uv pip compile - {extra} --python-version 3.12 --no-header --quiet"
        )

    rc, out, err = docker(PY_IMAGE, compile_script("--no-build"))
    if (
        rc != 0
    ):  # some dependencies ship sdists only; retry letting uv read metadata (container only)
        rc, out, err = docker(PY_IMAGE, compile_script(""))
        res["closure_built_sdists_in_container"] = rc == 0
    comps = parse_compile(out) if rc == 0 else []
    if comps:
        res["components"] = comps
        res["transitive_packages"] = len(comps)
        res["transitive_unique"] = len({(c["name"], c["version"]) for c in comps})
    else:
        res["nulls"]["transitive"] = f"uv pip compile failed rc={rc}: {err[-300:]}"
    return res


# --------------------------------------------------------------------------- cargo / go / releases


def parse_cargo_lock(text: str, root: str) -> list[dict[str, str]]:
    """Registry crates reachable from ``root`` in a Cargo.lock (workspace members excluded)."""
    lock = tomllib.loads(text)
    pkgs = lock.get("package", [])
    by_name: dict[str, list[dict[str, Any]]] = {}
    for p in pkgs:
        by_name.setdefault(p["name"], []).append(p)
    seen: set[tuple[str, str]] = set()
    stack = [(p["name"], p["version"]) for p in by_name.get(root, [])]
    index = {(p["name"], p["version"]): p for p in pkgs}
    while stack:
        key = stack.pop()
        if key in seen or key not in index:
            continue
        seen.add(key)
        for dep in index[key].get("dependencies", []):
            parts = dep.split(" ")
            if len(parts) >= 2:
                stack.append((parts[0], parts[1]))
            else:
                cands = by_name.get(parts[0], [])
                if cands:
                    stack.append((parts[0], cands[0]["version"]))
    return [
        {"name": n, "version": v}
        for n, v in sorted(seen)
        if (index[(n, v)].get("source") or "").startswith("registry")
    ]


def parse_go_mod(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if in_block or s.startswith("require "):
            body = s.removeprefix("require ").split("//")[0].split()
            if len(body) >= 2 and body[1].startswith("v"):
                out.append({"name": body[0], "version": body[1]})
    return out


def classify_assets(names: list[str]) -> dict[str, list[str]]:
    res: dict[str, list[str]] = {k: [] for k in ASSET_KINDS}
    for n in names:
        for kind, rx in ASSET_KINDS.items():
            if rx.search(n):
                res[kind].append(n)
    return res


def gh_release(repo: str, tags: list[str], version: str = "") -> dict[str, Any]:
    ver = version.removeprefix("v")
    for tag in tags:
        if ver and ver not in tag:
            continue  # never substitute a different version's release
        rc, out, _ = run(["gh", "api", f"repos/{repo}/releases/tags/{tag}"])
        if rc == 0:
            d = json.loads(out)
            names = [a["name"] for a in d.get("assets", [])]
            cls = classify_assets(names)
            return {
                "repo": repo,
                "tag": tag,
                "url": d.get("html_url"),
                "asset_count": len(names),
                "checksum_assets": cls["checksum"][:8],
                "signature_assets": cls["signature"][:8],
                "sbom_assets": cls["sbom"][:8],
                "has_checksums": bool(cls["checksum"]),
                "has_signatures": bool(cls["signature"]),
                "has_sbom": bool(cls["sbom"]),
                "api_url": f"https://api.github.com/repos/{repo}/releases/tags/{tag}",
            }
    return {
        "repo": repo,
        "tags_tried": tags,
        "release": None,
        "reason": "no GitHub release found for the pinned tag",
    }


def fetch_raw(repo: str, ref: str, path: str) -> str | None:
    r = requests.get(
        f"https://raw.githubusercontent.com/{repo}/{ref}/{path}", headers=UA, timeout=60
    )
    return r.text if r.is_success else None


def measure_lock_ecosystem(h: dict[str, Any]) -> dict[str, Any]:
    res: dict[str, Any] = {
        "nulls": {},
        "install_hooks": {},
        "has_install_hooks": None,
        "has_provenance": None,
    }
    repo, _tags = h["gh"]
    ref = h.get("lock_ref") or h["version"]
    if h["eco"] == "go":
        txt = fetch_raw(repo, ref, "go.mod")
        comps = parse_go_mod(txt) if txt else []
        res["lock_url"] = f"https://github.com/{repo}/blob/{ref}/go.mod"
        res["nulls"]["install_hooks"] = "go modules have no install scripts"
        res["has_install_hooks"] = False
        res["nulls"]["provenance"] = (
            "no registry-level provenance for Go modules; see release assets"
        )
        res["license"] = "FSL-1.1-MIT (VERSIONS.md)"
    else:
        txt = fetch_raw(repo, ref, "Cargo.lock")
        root = "goose-cli" if h["eco"] == "cargo" else None
        res["lock_url"] = f"https://github.com/{repo}/blob/{ref}/Cargo.lock"
        res["has_install_hooks"] = None
        res["nulls"]["install_hooks"] = (
            "cargo build.rs scripts run at build time, not install, for binary releases"
        )
        res["nulls"]["provenance"] = (
            "crates.io has no provenance attestations"
            if root
            else "no package-registry artifact (GitHub release only)"
        )
        if txt and root:
            comps = parse_cargo_lock(txt, root)
        elif txt:  # warp: whole-workspace registry crates (upper bound)
            lock = tomllib.loads(txt)
            comps = [
                {"name": p["name"], "version": p["version"]}
                for p in lock.get("package", [])
                if (p.get("source") or "").startswith("registry")
            ]
            res["scope_note"] = (
                "whole Cargo.lock registry crates (workspace upper bound, not release-pruned)"
            )
        else:
            comps = []
        res["license"] = None
        res["nulls"]["license"] = "not read for this ecosystem (see VERSIONS.md)"
    if comps:
        res["components"] = comps
        res["transitive_packages"] = len(comps)
        res["transitive_unique"] = len({(c["name"], c["version"]) for c in comps})
    else:
        res["nulls"]["transitive"] = f"no lockfile found at {repo}@{ref}"
    return res


# --------------------------------------------------------------------------- installers


def scan_installer(text: str) -> dict[str, Any]:
    lines = text.splitlines()
    ck = [
        ln.strip()[:160]
        for ln in lines
        if CHECKSUM_RE.search(ln) and not ln.strip().startswith("#")
    ]
    sg = [
        ln.strip()[:160]
        for ln in lines
        if SIGNATURE_RE.search(ln) and not ln.strip().startswith("#")
    ]
    return {
        "bytes": len(text.encode()),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "verifies_checksum": bool(ck),
        "verifies_signature": bool(sg),
        "checksum_evidence": ck[:3],
        "signature_evidence": sg[:3],
    }


def installer_urls(profile: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    for m in profile.get("install_methods") or []:
        if m.get("method") == "curl-installer":
            u = re.search(r"https?://[^\s|'\"]+", m.get("command", ""))
            if u:
                out.append(
                    {
                        "url": u.group(0),
                        "declared_command": m["command"],
                        "declared_signed": m.get("signed"),
                        "declared_checksum_verified": m.get("checksum_verified"),
                    }
                )
    return out


def measure_installers(profile: dict[str, Any]) -> list[dict[str, Any]]:
    res = []
    for inst in installer_urls(profile):
        row: dict[str, Any] = {**inst, "accessed": ACCESS_DATE}
        try:
            r = requests.get(inst["url"], headers=UA, timeout=60, follow_redirects=True)
            row["final_url"] = r.url
            row["status"] = r.status_code
            if r.is_success:
                row.update(scan_installer(r.text))
            else:
                row["reason"] = f"HTTP {r.status_code}"
        except requests.HTTPError as e:
            row["reason"] = f"fetch failed: {e.__class__.__name__}"
        res.append(row)
    return res


# --------------------------------------------------------------------------- OSV


def osv_query(components: list[tuple[str, str, str]]) -> dict[tuple[str, str, str], list[str]]:
    """components: (eco, name, version) -> vuln ids, via /v1/querybatch (paginated)."""
    out: dict[tuple[str, str, str], list[str]] = {}
    items = [c for c in components if c[0] in OSV_ECO]
    for i in range(0, len(items), 500):
        chunk = items[i : i + 500]
        queries = [
            {"package": {"name": n, "ecosystem": OSV_ECO[e]}, "version": v} for e, n, v in chunk
        ]
        pending = list(range(len(chunk)))
        while pending:
            r = requests.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": [queries[j] for j in pending]},
                headers=UA,
                timeout=120,
            )
            r.raise_for_status()
            nxt = []
            for j, res in zip(pending, r.json().get("results", []), strict=False):
                out.setdefault(chunk[j], []).extend(v["id"] for v in res.get("vulns", []))
                if res.get("next_page_token"):
                    queries[j]["page_token"] = res["next_page_token"]
                    nxt.append(j)
            pending = nxt
    return out


_VULN_CACHE: dict[str, str] = {}


def severity_of(vuln: dict[str, Any]) -> str:
    if vuln.get("id", "").startswith("MAL-"):
        return "malicious"
    sev = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if sev == "MODERATE":
        sev = "MEDIUM"
    if sev in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return sev.lower()
    return "unrated"


def vuln_severity(vid: str) -> str:
    if vid not in _VULN_CACHE:
        r = requests.get(f"https://api.osv.dev/v1/vulns/{vid}", headers=UA, timeout=60)
        _VULN_CACHE[vid] = severity_of(r.json()) if r.is_success else "unrated"
    return _VULN_CACHE[vid]


def summarise_osv(
    hits: dict[tuple[str, str, str], list[str]], own: tuple[str, str, str]
) -> dict[str, Any]:
    ids = sorted({v for vs in hits.values() for v in vs})
    with ThreadPoolExecutor(8) as ex:
        sevs = dict(zip(ids, ex.map(vuln_severity, ids), strict=True))
    by_sev = Counter(sevs.values())
    own_ids = sorted(set(hits.get(own, [])))
    return {
        "queried_at": ACCESS_DATE,
        "endpoint": "https://api.osv.dev/v1/querybatch",
        "vulnerable_packages": sum(1 for v in hits.values() if v),
        "unique_vulns": len(ids),
        "by_severity": dict(by_sev),
        "own_package_vulns": own_ids,
        "vuln_ids": ids[:60],
    }


# --------------------------------------------------------------------------- SBOM


def cyclonedx(
    harness: str, root: tuple[str, str, str], comps: list[dict[str, Any]]
) -> dict[str, Any]:
    eco, name, version = root
    seen: set[str] = set()
    components = []
    for c in comps:
        p = purl(eco, c["name"], c["version"])
        if p in seen:
            continue
        seen.add(p)
        entry: dict[str, Any] = {
            "type": "library",
            "name": c["name"],
            "version": c["version"],
            "purl": p,
            "bom-ref": p,
        }
        if c.get("license"):
            entry["licenses"] = [{"license": {"name": str(c["license"])}}]
        components.append(entry)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": f"{ACCESS_DATE}T00:00:00Z",
            "tools": [{"name": "harnesswatch experiments/e4_supply.py"}],
            "component": {
                "type": "application",
                "name": name,
                "version": version,
                "purl": purl(eco, name, version),
                "bom-ref": f"root:{harness}",
            },
            "properties": [
                {
                    "name": "harnesswatch:note",
                    "value": "resolved from lockfile/compile output; not installed",
                }
            ],
        },
        "components": components,
    }


# --------------------------------------------------------------------------- orchestration


def load_profile(hid: str) -> dict[str, Any]:
    return yaml.safe_load((PROFILES / f"{hid}.yaml").read_text())


def measure(hid: str) -> dict[str, Any]:
    t = TARGETS[hid]
    prof = load_profile(hid)
    row: dict[str, Any] = {
        "harness": hid,
        "tier": prof.get("tier"),
        "ecosystem": t["eco"],
        "package": t["name"],
        "version": t["version"],
        "accessed": ACCESS_DATE,
        "sources": [],
    }
    eco = t["eco"]
    if eco == "npm":
        m = measure_npm(t["name"], t["version"])
        row["sources"].append(
            f"https://registry.npmjs.org/{quote(t['name'], safe='@')}/{t['version']}"
        )
    elif eco == "pypi":
        m = measure_pypi(t["name"], t["version"])
        row["sources"].append(m.get("metadata_url", ""))
    else:
        m = measure_lock_ecosystem(t)
        row["sources"].append(m.get("lock_url", ""))
    comps = m.pop("components", [])
    nulls = m.pop("nulls", {})
    row.update(m)
    if t.get("gh"):
        row["release"] = gh_release(*t["gh"], t["version"])
        if row["release"].get("api_url"):
            row["sources"].append(row["release"]["api_url"])
    else:
        row["release"] = None
        nulls["release"] = "no public GitHub release (npm-only distribution)"
    row["installers"] = measure_installers(prof)
    row["sources"] += [i["url"] for i in row["installers"]]
    au = prof.get("auto_update") or {}
    row["auto_update"] = {
        "default": au.get("default"),
        "config": au.get("config"),
        "source": au.get("source"),
        "evidence_label": "from-official-docs" if au.get("default") is not None else None,
    }
    if au.get("default") is None:
        nulls["auto_update"] = "profile records default as unverified"
    own = (eco, t["name"], t["version"])
    if comps:
        all_c = [(eco, c["name"], c["version"]) for c in comps]
        if own not in all_c:
            all_c.append(own)
        try:
            row["osv"] = summarise_osv(osv_query(all_c), own)
            row["sources"].append("https://api.osv.dev/v1/querybatch")
        except requests.HTTPError as e:
            row["osv"] = None
            nulls["osv"] = f"OSV query failed: {e}"
        SBOM_DIR.mkdir(parents=True, exist_ok=True)
        (SBOM_DIR / f"{hid}.cdx.json").write_text(
            json.dumps(cyclonedx(hid, own, comps), indent=1) + "\n"
        )
        row["sbom"] = f"experiments/results/e4_sbom/{hid}.cdx.json"
    else:
        row["osv"] = None
        row["sbom"] = None
        nulls.setdefault("osv", "no dependency set could be resolved")
    row["null_reasons"] = nulls
    return row


# --------------------------------------------------------------------------- tables


def unsigned_installers(row: dict[str, Any]) -> tuple[int, int]:
    """(# curl installers fetched, # with no signature verification)."""
    got = [i for i in row.get("installers", []) if "sha256" in i]
    return len(got), sum(1 for i in got if not i["verifies_signature"])


def installer_cell(row: dict[str, Any]) -> str:
    got = [i for i in row.get("installers", []) if "sha256" in i]
    if not row.get("installers"):
        return "none"
    if not got:
        return "n/a"
    return "/".join(
        "sig" if i["verifies_signature"] else "sum" if i["verifies_checksum"] else "none"
        for i in got
    )


def fmt(v: Any) -> str:
    return "n/a" if v is None else str(v)


def osv_cell(row: dict[str, Any]) -> str:
    o = row.get("osv")
    if not o:
        return "n/a"
    s = o["by_severity"]
    return f"{o['unique_vulns']} ({s.get('critical', 0)}/{s.get('high', 0)}/{s.get('medium', 0)}/{s.get('low', 0)}/{s.get('unrated', 0)})"


HEAD = [
    "Harness",
    "Package@version",
    "Eco",
    "Install hooks",
    "Direct",
    "Transitive",
    "Provenance",
    "Release sums/sigs/SBOM",
    "curl installer",
    "OSV vulns (C/H/M/L/unrated)",
    "Auto-update",
]


def table_rows(rows: list[dict[str, Any]]) -> list[list[str]]:
    out = []
    for r in rows:
        rel = r.get("release") or {}
        rel_cell = (
            "n/a"
            if not rel or "tag" not in rel
            else "/".join(
                "Y" if rel[k] else "N" for k in ("has_checksums", "has_signatures", "has_sbom")
            )
        )
        hooks = r.get("has_install_hooks")
        prov = r.get("has_provenance")
        out.append(
            [
                r["harness"],
                f"{r['package']}@{r['version']}",
                r["ecosystem"],
                "n/a" if hooks is None else "yes" if hooks else "no",
                fmt(r.get("direct_dependencies")),
                fmt(r.get("transitive_packages")),
                "n/a" if prov is None else "yes" if prov else "no",
                rel_cell,
                installer_cell(r),
                osv_cell(r),
                {True: "on", False: "off", None: "unverified"}[r["auto_update"]["default"]],
            ]
        )
    return out


def tex_escape(s: str) -> str:
    return (
        s.replace("\\", "\\textbackslash{}")
        .replace("_", "\\_")
        .replace("&", "\\&")
        .replace("#", "\\#")
        .replace("%", "\\%")
        .replace("@", "@")
    )


def write_tables(rows: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    body = table_rows(rows)
    md = ["| " + " | ".join(HEAD) + " |", "|" + "---|" * len(HEAD)]
    md += ["| " + " | ".join(r) + " |" for r in body]
    md += [
        "",
        f"Accessed {ACCESS_DATE}. Install hooks = own preinstall/install/postinstall (npm only). "
        "Transitive = packages in the resolved lockfile (not installed). Release = checksum/signature/SBOM "
        "assets on the GitHub release (Y/N). curl installer: sig = verifies a signature, sum = checksum only, "
        "none = neither (text scan, not executed). n/a = not obtainable (reason in "
        "`experiments/results/e4_supply.json`).",
        "",
        f"Summary: {json.dumps(summary)}",
    ]
    (TABLES / "e4_supply.md").write_text("\n".join(md) + "\n")
    cols = "llllrrlllll"
    tex = [
        "% generated by experiments/e4_supply.py",
        "\\begin{table*}[t]",
        "\\centering\\scriptsize",
        f"\\resizebox{{\\textwidth}}{{!}}{{\\begin{{tabular}}{{{cols}}}",
        "\\toprule",
        " & ".join(tex_escape(h) for h in HEAD) + " \\\\",
        "\\midrule",
    ]
    tex += [" & ".join(tex_escape(c) for c in r) + " \\\\" for r in body]
    tex += [
        "\\bottomrule",
        "\\end{tabular}}",
        "\\caption{Supply-chain audit of Tier-A harness packages (plus Claude Code, Grok Build, Copilot CLI), "
        f"accessed {ACCESS_DATE}. Transitive = lockfile packages (not installed); release = "
        "checksums/signatures/SBOM assets; installer: sig = signature check, sum = checksum only, none = neither.}",
        "\\label{tab:e4-supply}",
        "\\end{table*}",
    ]
    (TABLES / "e4_supply.tex").write_text("\n".join(tex) + "\n")


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    trans = [r["transitive_packages"] for r in rows if r.get("transitive_packages") is not None]
    inst = [unsigned_installers(r) for r in rows]
    sev: Counter[str] = Counter()
    for r in rows:
        if r.get("osv"):
            sev.update(r["osv"]["by_severity"])
    return {
        "harnesses": len(rows),
        "with_transitive_count": len(trans),
        "median_transitive": statistics.median(trans) if trans else None,
        "with_provenance": sum(1 for r in rows if r.get("has_provenance")),
        "provenance_known": sum(1 for r in rows if r.get("has_provenance") is not None),
        "harnesses_with_curl_installer": sum(1 for n, _ in inst if n),
        "harnesses_with_unsigned_curl_installer": sum(1 for n, u in inst if u),
        "harnesses_with_install_hooks": sum(1 for r in rows if r.get("has_install_hooks")),
        "osv_unique_vulns_total": sum(r["osv"]["unique_vulns"] for r in rows if r.get("osv")),
        "osv_by_severity_sum": dict(sev),
        "auto_update_default_on": sum(1 for r in rows if r["auto_update"]["default"] is True),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument(
        "--tables-only",
        action="store_true",
        help="re-render tables from the committed JSON (offline)",
    )
    a = ap.parse_args()
    if a.tables_only:
        doc = json.loads((RESULTS / "e4_supply.json").read_text())
        write_tables(doc["rows"], doc["summary"])
        return
    ids = [i for i in TARGETS if not a.only or i in a.only.split(",")]
    RESULTS.mkdir(parents=True, exist_ok=True)

    def safe(hid: str) -> dict[str, Any]:
        try:
            print("measuring", hid, flush=True)
            return measure(hid)
        except Exception as e:  # keep the grid going; record the failure as nulls
            return {
                "harness": hid,
                "ecosystem": TARGETS[hid]["eco"],
                "package": TARGETS[hid]["name"],
                "version": TARGETS[hid]["version"],
                "accessed": ACCESS_DATE,
                "auto_update": {"default": None},
                "installers": [],
                "release": None,
                "osv": None,
                "null_reasons": {"all": f"{e.__class__.__name__}: {e}"},
            }

    with ThreadPoolExecutor(a.workers) as ex:
        rows = list(ex.map(safe, ids))
    summary = summarise(rows)
    doc = {"experiment": "E4", "accessed": ACCESS_DATE, "summary": summary, "rows": rows}
    (RESULTS / "e4_supply.json").write_text(json.dumps(doc, indent=1) + "\n")
    write_tables(rows, summary)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
