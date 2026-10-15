"""Independently re-check every CVE (NVD API 2.0) and GHSA (GitHub advisory API) in incidents.csv.

Writes evidence/verification/incidents_check.json with, per incident: whether each ID resolves,
the record's published date, and whether the record text mentions the harness/vendor. Results are
cached so re-runs only fetch missing IDs. NVD without an API key allows ~5 requests / 30 s.
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence" / "verification" / "incidents_check.json"
CACHE = ROOT / "evidence" / "verification" / "advisory_cache.json"
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", re.IGNORECASE)
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def load_cache() -> dict[str, dict[str, object]]:
    return json.loads(CACHE.read_text()) if CACHE.exists() else {}


def fetch_cve(client: httpx.Client, cve: str) -> dict[str, object]:
    for attempt in range(5):
        resp = client.get(NVD, params={"cveId": cve})
        if resp.status_code in (403, 429, 503):
            time.sleep(10 * (attempt + 1))
            continue
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return {"found": False}
        item = vulns[0]["cve"]
        desc = next((d["value"] for d in item.get("descriptions", []) if d["lang"] == "en"), "")
        cpes = json.dumps(item.get("configurations", []))[:4000]
        refs = " ".join(r.get("url", "") for r in item.get("references", []))[:4000]
        return {
            "found": True,
            "published": item.get("published", "")[:10],
            "status": item.get("vulnStatus"),
            "text": (desc + " " + cpes + " " + refs).lower()[:6000],
            "description": desc[:400],
        }
    return {"found": None, "error": "rate-limited"}


def fetch_ghsa(ghsa: str, source_urls: str) -> dict[str, object]:
    proc = subprocess.run(
        ["gh", "api", f"/advisories/{ghsa}"], capture_output=True, text=True, check=False
    )
    data = json.loads(proc.stdout) if proc.returncode == 0 and proc.stdout.startswith("{") else None
    if data is None:  # repository advisories are not always in the global database
        repo = re.search(r"github\.com/([^/\s]+/[^/\s]+)/security/advisories", source_urls)
        if repo:
            proc = subprocess.run(
                ["gh", "api", f"repos/{repo.group(1)}/security-advisories/{ghsa}"],
                capture_output=True,
                text=True,
                check=False,
            )
            data = (
                json.loads(proc.stdout)
                if proc.returncode == 0 and proc.stdout.startswith("{")
                else None
            )
    if not data or "ghsa_id" not in data:
        return {"found": False}
    vulns = json.dumps(data.get("vulnerabilities", []))
    text = " ".join(
        [
            data.get("summary") or "",
            (data.get("description") or "")[:3000],
            vulns,
            data.get("html_url") or "",
            data.get("source_code_location") or "",
        ]
    ).lower()
    return {
        "found": True,
        "published": (data.get("published_at") or "")[:10],
        "cve": data.get("cve_id"),
        "text": text[:6000],
        "summary": (data.get("summary") or "")[:200],
    }


def tokens(row: dict[str, str]) -> set[str]:
    words = set()
    for field in ("harness", "vendor"):
        for part in re.split(r"[\s/,;()+]+", row[field].lower()):
            part = part.strip()
            if len(part) >= 3 and part not in {
                "the",
                "and",
                "inc",
                "llc",
                "ltd",
                "corp",
                "agent",
                "cli",
                "sdk",
                "ai",
            }:
                words.add(part)
                words.update(p for p in part.split("-") if len(p) >= 4)
    return words


def main() -> int:
    rows = list(csv.DictReader((ROOT / "evidence" / "incidents.csv").open(encoding="utf-8")))
    cache = load_cache()
    client = httpx.Client(timeout=30.0, headers={"User-Agent": "harnesswatch-research"})
    todo = sorted({c for r in rows for c in CVE.findall(r["cve"])} - set(cache))
    for i, cve in enumerate(todo):
        cache[cve] = fetch_cve(client, cve)
        CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True))
        time.sleep(6.5)
        print(f"[{i + 1}/{len(todo)}] {cve} {cache[cve].get('found')}", flush=True)
    for row in rows:
        for ghsa in {g.upper().replace("GHSA", "GHSA") for g in GHSA.findall(row["ghsa"])}:
            key = "GHSA" + ghsa[4:].lower()
            if key not in cache:
                cache[key] = fetch_ghsa(key, row["primary_source"] + " " + row["secondary_source"])
                CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True))
    results = []
    for row in rows:
        ids = CVE.findall(row["cve"]) + ["GHSA" + g[4:].lower() for g in GHSA.findall(row["ghsa"])]
        words = tokens(row)
        checks = []
        for ident in ids:
            rec = cache.get(ident, {})
            text = str(rec.get("text", ""))
            checks.append(
                {
                    "id": ident,
                    "found": rec.get("found"),
                    "published": rec.get("published"),
                    "mentions_product": any(w in text for w in words) if rec.get("found") else None,
                }
            )
        if not ids:
            status = "no-id (primary-source only)"
        elif all(c["found"] for c in checks) and any(c["mentions_product"] for c in checks):
            status = "confirmed"
        elif all(c["found"] for c in checks):
            status = "found-product-unmatched"
        elif any(c["found"] for c in checks):
            status = "partially-found"
        else:
            status = "not-found"
        results.append(
            {
                "id": row["id"],
                "harness": row["harness"],
                "title": row["title"][:120],
                "verified_by_agent": row["verified"],
                "status": status,
                "checks": checks,
            }
        )
    OUT.write_text(json.dumps(results, indent=1) + "\n")
    counts: dict[str, int] = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(json.dumps(counts, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
