"""Merge Phase 1 research fragments into the canonical evidence files.

- evidence/ledger.d/*.csv      -> evidence/ledger.csv
- evidence/incidents.d/*.csv   -> evidence/incidents.csv (deduplicated by CVE / GHSA / title)
- evidence/sources_*.bib       -> evidence/sources.bib (deduplicated by key)
- VERSIONS.d/*.md              -> harness table appended to VERSIONS.md

Label policy (ASSUMPTIONS A09): `verified-by-test` is reserved for behaviour observed by running
something locally (source_url `local:` or a bench/experiment id); reading official source code or
vendor API metadata is `from-official-docs`.
"""

from __future__ import annotations

import csv
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER_COLS = [
    "id",
    "claim",
    "harness",
    "label",
    "source_url",
    "publisher",
    "source_date",
    "accessed",
    "verified_by",
    "confidence",
]
INCIDENT_COLS = [
    "id",
    "date_disclosed",
    "harness",
    "vendor",
    "title",
    "cve",
    "ghsa",
    "kind",
    "taxonomy_class",
    "root_cause_class",
    "affected_versions",
    "fixed_version",
    "fix_date",
    "patch_latency_days",
    "primary_source",
    "secondary_source",
    "reporter",
    "verified",
    "notes",
]
# Same incident filed under different titles/ids by two research agents (B3 review).
MANUAL_DUPLICATES = {"G4-I039": "B3-I001", "G7-I092": "B3-I001"}
CVO_COLS = [
    "id",
    "harness",
    "version",
    "dimension",
    "documented_claim",
    "claim_source",
    "claim_label",
    "observed",
    "observed_method",
    "observed_date",
    "verdict",
    "notes",
]
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")


def merge_ledger() -> int:
    rows = []
    for path in sorted((ROOT / "evidence" / "ledger.d").glob("*.csv")):
        for row in csv.DictReader(path.open(encoding="utf-8")):
            row = {k: (row.get(k) or "").strip() for k in LEDGER_COLS}
            if row["label"] == "verified-by-test" and not row["source_url"].startswith("local:"):
                row["label"] = "from-official-docs"
                row["verified_by"] += " (relabelled: source/API read, A09)"
            rows.append(row)
    with (ROOT / "evidence" / "ledger.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, LEDGER_COLS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _ids(row: dict[str, str]) -> set[str]:
    text = row["cve"] + " " + row["ghsa"]
    return set(CVE.findall(text)) | {g.upper() for g in GHSA.findall(text)}


def merge_incidents() -> tuple[int, int]:
    merged: list[dict[str, str]] = []
    index: dict[str, int] = {}
    dropped = 0
    for path in sorted((ROOT / "evidence" / "incidents.d").glob("*.csv")):
        for raw in csv.DictReader(path.open(encoding="utf-8")):
            row = {k: (raw.get(k) or "").strip() for k in INCIDENT_COLS}
            keys = _ids(row) or {"title:" + re.sub(r"\W+", " ", row["title"].lower()).strip()}
            keys.add("id:" + MANUAL_DUPLICATES.get(row["id"], row["id"]))
            hits = sorted({index[k] for k in keys if k in index})  # deterministic (no set order)
            hit = hits[0] if hits else None
            if hit is None:
                index.update({k: len(merged) for k in keys})
                merged.append(row)
                continue
            dropped += 1
            kept = merged[hit]
            # Prefer the verified, more complete row; keep provenance of both.
            if kept["verified"] != "yes" and row["verified"] == "yes":
                row["notes"] = (row["notes"] + f" | also reported as {kept['id']}").strip(" |")
                merged[hit] = row
            else:
                for col in INCIDENT_COLS:
                    if not kept[col] and row[col]:
                        kept[col] = row[col]
                kept["notes"] = (kept["notes"] + f" | also reported as {row['id']}").strip(" |")
            index.update({k: hit for k in keys})
    for row in merged:  # recompute from the dates; agent-entered values were inconsistent (REVIEW)
        try:
            delta = date.fromisoformat(row["fix_date"][:10]) - date.fromisoformat(
                row["date_disclosed"][:10]
            )
            row["patch_latency_days"] = str(delta.days)
        except ValueError:
            row["patch_latency_days"] = ""
    merged.sort(key=lambda r: (r["date_disclosed"], r["harness"], r["id"]))
    with (ROOT / "evidence" / "incidents.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, INCIDENT_COLS)
        writer.writeheader()
        writer.writerows(merged)
    return len(merged), dropped


def merge_bib() -> int:
    entries: dict[str, str] = {}
    for path in sorted((ROOT / "evidence").glob("sources_*.bib")):
        text = path.read_text(encoding="utf-8")
        for start in (m.start() for m in re.finditer(r"@\w+\{", text)):
            depth, end = 0, start
            for end in range(text.index("{", start), len(text)):
                depth += {"{": 1, "}": -1}.get(text[end], 0)
                if depth == 0:
                    break
            entry = text[start : end + 1]
            key = entry[entry.index("{") + 1 : entry.index(",")].strip()
            entries.setdefault(key, entry)
    (ROOT / "evidence" / "sources.bib").write_text(
        "\n\n".join(entries[k] for k in sorted(entries)) + "\n", encoding="utf-8"
    )
    return len(entries)


def merge_versions() -> int:
    header = "| harness | vendor | tier | license (verified) | version analysed | release date | status | source |"
    rows: list[str] = []
    for path in sorted((ROOT / "VERSIONS.d").glob("*.md")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if (
                line.startswith("|")
                and not line.startswith("|---")
                and "harness" not in line.lower()[:12]
            ):
                rows.append(line)
    versions = ROOT / "VERSIONS.md"
    text = versions.read_text(encoding="utf-8")
    table = "\n".join([header, "|" + "---|" * 8, *sorted(rows, key=str.lower)])
    text = re.sub(r"## Harnesses\n.*", "## Harnesses\n\n" + table + "\n", text, flags=re.DOTALL)
    versions.write_text(text, encoding="utf-8")
    return len(rows)


def merge_claims() -> int:
    """matrix/claims_vs_observed.d/*.csv -> matrix/claims_vs_observed.csv (claims side, RQ7).

    The observed/verdict columns are filled later by experiments/e7_claims.py.
    """
    rows = []
    for path in sorted((ROOT / "matrix" / "claims_vs_observed.d").glob("*.csv")):
        for raw in csv.DictReader(path.open(encoding="utf-8")):
            rows.append({k: (raw.get(k) or "").strip() for k in CVO_COLS})
    with (ROOT / "matrix" / "claims_vs_observed.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, CVO_COLS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    ledger = merge_ledger()
    incidents, dropped = merge_incidents()
    bib = merge_bib()
    versions = merge_versions()
    claims = merge_claims()
    print(
        f"ledger={ledger} incidents={incidents} (merged duplicates={dropped}) bib={bib} versions={versions} claims={claims}"
    )
    sys.exit(0)
