"""`audit supply`: harness distribution supply chain (HG-SUP-*) and a CycloneDX SBOM.

Offline by default. With `online=True` only package name + version are sent to OSV.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from harnesswatch import __version__
from harnesswatch.inventory import InventoryItem
from harnesswatch.models import HarnessProfile, Location, Severity
from harnesswatch.rules_engine import Hit, Rule, check

OSV_URL = "https://api.osv.dev/v1/query"
ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "pip": "PyPI", "cargo": "crates.io", "go": "Go"}


@dataclass
class Component:
    harness: str
    ecosystem: str
    name: str
    version: str | None


@dataclass
class SupplySubject:
    items: list[InventoryItem] = field(default_factory=list)
    profiles: dict[str, HarnessProfile] = field(default_factory=dict)
    online: bool = False
    vulns: dict[str, list[dict[str, Any]]] = field(default_factory=dict)  # purl -> OSV vulns

    def components(self) -> list[Component]:
        out = []
        for item in self.items:
            profile = self.profiles.get(item.harness)
            version = next((b.version for b in item.binaries if b.version), None)
            for pkg in profile.packages if profile else []:
                eco = str(pkg.get("ecosystem", "")).lower()
                if eco in ECOSYSTEMS and item.binaries:
                    out.append(Component(item.harness, eco, str(pkg.get("name")), version))
        return out


def purl(component: Component) -> str:
    eco = {"pypi": "pypi", "pip": "pypi", "npm": "npm", "cargo": "cargo", "go": "golang"}[
        component.ecosystem
    ]
    name = component.name.replace("@", "%40") if eco == "npm" else component.name
    return f"pkg:{eco}/{name}" + (f"@{component.version}" if component.version else "")


def query_osv(
    components: list[Component], client: httpx.Client | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Look up known vulnerabilities. Sends only ecosystem, package name and version."""
    results: dict[str, list[dict[str, Any]]] = {}
    own = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        for component in components:
            if not component.version:
                continue
            body = {
                "package": {"name": component.name, "ecosystem": ECOSYSTEMS[component.ecosystem]},
                "version": component.version,
            }
            response = client.post(OSV_URL, json=body)
            response.raise_for_status()
            results[purl(component)] = list(response.json().get("vulns", []))
    finally:
        if own:
            client.close()
    return results


def cyclonedx(subject: SupplySubject) -> dict[str, Any]:
    components = [
        {
            "type": "application",
            "name": c.name,
            "version": c.version or "unknown",
            "purl": purl(c),
            "properties": [{"name": "harnesswatch:harness", "value": c.harness}],
        }
        for c in subject.components()
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {"type": "application", "name": "harnesswatch", "version": __version__}
                ]
            }
        },
        "components": components,
    }


@check("HG-SUP-001", "supply")
def unverified_installer(rule: Rule, subject: SupplySubject) -> Iterator[Hit]:
    for item in subject.items:
        profile = subject.profiles.get(item.harness)
        if profile is None:
            continue
        methods = getattr(profile, "install_methods", None) or []
        curl = [
            m
            for m in methods
            if isinstance(m, dict)
            and "curl" in str(m.get("method", ""))
            and m.get("checksum_verified") is not True
            and m.get("signed") is not True
        ]
        auto = getattr(profile, "auto_update", None) or {}
        for binary in item.binaries:
            if binary.install_method in {"native-installer", "unknown"} and curl:
                updates = (
                    " with auto-update on by default"
                    if isinstance(auto, dict) and auto.get("default")
                    else ""
                )
                yield Hit(
                    message=f"{profile.name} appears installed via a `curl | sh` installer that does not "
                    f"verify a checksum/signature{updates}",
                    location=Location(path=binary.path),
                    harness=item.harness,
                )


@check("HG-SUP-002", "supply")
def known_vulnerable(rule: Rule, subject: SupplySubject) -> Iterator[Hit]:
    for component in subject.components():
        vulns = subject.vulns.get(purl(component), [])
        if vulns:
            ids = ", ".join(sorted(v.get("id", "?") for v in vulns)[:6])
            yield Hit(
                message=f"{component.name}@{component.version} has {len(vulns)} known vulnerabilit"
                f"{'y' if len(vulns) == 1 else 'ies'} (OSV: {ids})",
                location=Location(path=purl(component)),
                harness=component.harness,
                severity=Severity.HIGH if len(vulns) > 0 else None,
            )


def write_sbom(subject: SupplySubject, path: Path) -> None:
    path.write_text(json.dumps(cyclonedx(subject), indent=2) + "\n", encoding="utf-8")
