"""Offline tests for the E4 supply-chain parsers (recorded, trimmed fixtures)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "e4_supply", Path(__file__).resolve().parent.parent / "experiments" / "e4_supply.py"
)
assert _SPEC and _SPEC.loader
e4 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(e4)

NPM_VIEW = json.dumps(
    {
        "name": "@scope/tool",
        "version": "1.2.3",
        "license": "Apache-2.0",
        "scripts": {"postinstall": "node setup.js", "test": "vitest"},
        "dependencies": {"a": "^1", "b": "^2"},
        "optionalDependencies": {"c": "1.0.0"},
        "dist": {
            "unpackedSize": 1234,
            "signatures": [{"keyid": "SHA256:x", "sig": "abc"}],
            "attestations": {
                "url": "https://registry.npmjs.org/-/npm/v1/attestations/@scope%2ftool@1.2.3",
                "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
            },
        },
    }
)


def test_parse_npm_view_hooks_and_provenance() -> None:
    r = e4.parse_npm_view(NPM_VIEW)
    assert r["install_hooks"] == {"postinstall": "node setup.js"}
    assert r["has_install_hooks"] is True
    assert r["direct_dependencies"] == 2
    assert r["optional_dependencies"] == 1
    assert r["registry_signatures"] == 1
    assert r["attestations_predicate"].startswith("https://slsa.dev")
    assert r["license"] == "Apache-2.0"


def test_parse_npm_view_bare_package_and_list() -> None:
    r = e4.parse_npm_view(json.dumps([{"name": "x", "version": "1", "dist": {}}]))
    assert r["has_install_hooks"] is False
    assert r["attestations_url"] is None
    assert r["registry_signatures"] == 0


def test_parse_attestations() -> None:
    doc = {
        "attestations": [
            {"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"},
            {"predicateType": "https://slsa.dev/provenance/v1"},
        ]
    }
    assert len(e4.parse_attestations(doc)) == 2


def test_parse_npm_lock_counts_and_excludes_root_and_dev() -> None:
    lock = {
        "packages": {
            "": {"name": "w"},
            "node_modules/@scope/tool": {"version": "1.2.3", "hasInstallScript": True},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/a/node_modules/b": {"version": "2.0.0", "optional": True},
            "node_modules/devonly": {"version": "9.0.0", "dev": True},
        }
    }
    r = e4.parse_npm_lock(lock)
    assert r["transitive_packages"] == 3
    assert r["transitive_with_install_scripts"] == 1
    assert {c["name"] for c in r["components"]} == {"@scope/tool", "a", "b"}


def test_parse_pypi_json_filters_extras() -> None:
    doc = {
        "info": {
            "license_expression": "MIT",
            "requires_dist": ["requests>=2", 'pytest; extra == "dev"'],
        },
        "urls": [
            {"filename": "x-1.whl", "packagetype": "bdist_wheel"},
            {"filename": "x-1.tar.gz", "packagetype": "sdist"},
        ],
    }
    r = e4.parse_pypi_json(doc)
    assert r["requires_dist"] == 2
    assert r["direct_dependencies"] == 1
    assert r["has_wheel"] and r["has_sdist"]


def test_parse_compile_output() -> None:
    text = "aiohttp==3.9.5\n    # via aider-chat\nPyYAML==6.0.1 ; python_version>'3'\n# comment\n"
    assert e4.parse_compile(text) == [
        {"name": "aiohttp", "version": "3.9.5"},
        {"name": "PyYAML", "version": "6.0.1"},
    ]


def test_parse_provenance() -> None:
    body = {
        "attestation_bundles": [
            {
                "publisher": {"kind": "GitHub"},
                "attestations": [{"statement": {"predicateType": "p"}}],
            }
        ]
    }
    assert e4.parse_provenance(200, body)["present"] is True
    assert e4.parse_provenance(404, None) == {"present": False, "status": 404}


CARGO_LOCK = """
[[package]]
name = "goose-cli"
version = "1.0.0"
dependencies = ["serde", "local-lib", "tokio 1.40.0"]

[[package]]
name = "local-lib"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.40.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "unrelated"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""


def test_parse_cargo_lock_reachable_registry_only() -> None:
    comps = e4.parse_cargo_lock(CARGO_LOCK, "goose-cli")
    assert [c["name"] for c in comps] == ["serde", "tokio"]


def test_parse_go_mod() -> None:
    txt = "module m\n\ngo 1.24\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgolang.org/x/sys v0.1.0 // indirect\n)\n\nrequire github.com/c/d v0.0.1\n"
    assert [c["name"] for c in e4.parse_go_mod(txt)] == [
        "github.com/a/b",
        "golang.org/x/sys",
        "github.com/c/d",
    ]


def test_classify_assets() -> None:
    cls = e4.classify_assets(
        ["checksums.txt", "checksums.txt.sigstore.json", "a.tar.gz.sbom.json", "a.tar.gz"]
    )
    assert cls["checksum"] == ["checksums.txt"]
    assert cls["signature"] == ["checksums.txt.sigstore.json"]
    assert cls["sbom"] == ["a.tar.gz.sbom.json"]


def test_scan_installer_checksum_vs_signature() -> None:
    plain = "#!/bin/sh\ncurl -fsSL https://x/y -o bin\nchmod +x bin\n"
    ck = "#!/bin/sh\n# sha256 mention in comment only\nsha256sum -c SHA256SUMS\n"
    sig = ck + "cosign verify-blob --bundle b.json bin\n"
    assert not e4.scan_installer(plain)["verifies_checksum"]
    r = e4.scan_installer(ck)
    assert r["verifies_checksum"] and not r["verifies_signature"]
    assert e4.scan_installer(sig)["verifies_signature"]


def test_installer_urls_only_curl() -> None:
    prof = {
        "install_methods": [
            {
                "method": "curl-installer",
                "command": "curl -fsSL https://x.ai/i.sh | bash",
                "signed": None,
            },
            {"method": "npm", "command": "npm i -g x"},
        ]
    }
    assert [i["url"] for i in e4.installer_urls(prof)] == ["https://x.ai/i.sh"]


@pytest.mark.parametrize(
    ("vuln", "expected"),
    [
        ({"id": "GHSA-1", "database_specific": {"severity": "MODERATE"}}, "medium"),
        ({"id": "GHSA-2", "database_specific": {"severity": "CRITICAL"}}, "critical"),
        ({"id": "PYSEC-3"}, "unrated"),
        ({"id": "MAL-2026-1"}, "malicious"),
    ],
)
def test_severity_of(vuln: dict, expected: str) -> None:
    assert e4.severity_of(vuln) == expected


def test_cyclonedx_and_purl() -> None:
    assert e4.purl("npm", "@scope/tool", "1.0.0") == "pkg:npm/%40scope/tool@1.0.0"
    assert e4.purl("pypi", "Foo_Bar", "1") == "pkg:pypi/foo-bar@1"
    bom = e4.cyclonedx(
        "h",
        ("npm", "tool", "1.0.0"),
        [{"name": "a", "version": "1", "license": "MIT"}, {"name": "a", "version": "1"}],
    )
    assert bom["bomFormat"] == "CycloneDX"
    assert len(bom["components"]) == 1
    assert bom["components"][0]["licenses"][0]["license"]["name"] == "MIT"
