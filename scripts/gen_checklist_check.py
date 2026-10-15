"""Validate the RQ6 governance checklist and render its Markdown page.

`brief/governance-checklist.yaml` is the source. This script checks that every HG rule id exists in
`rules/`, that every AIRM, MITRE ATLAS and OWASP id (and every NIST, ISO and MAS reference) exists in
`taxonomy/mappings.yaml` or `taxonomy/harness-threats.yaml`, that each framework id in a control is
supported by one of the threat classes the control cites, that threat, root-cause and rubric ids exist,
that every `harnesswatch` command resolves to a real subcommand and options, and that
`brief/governance-checklist.md` matches the YAML.

    python scripts/gen_checklist_check.py          # validate (exit 1 on problems)
    python scripts/gen_checklist_check.py --write  # validate, then re-render the Markdown page
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
CHECKLIST_YAML = Path("brief/governance-checklist.yaml")
CHECKLIST_MD = Path("brief/governance-checklist.md")
RQ3_JSON = Path("experiments/results/rq3_incidents.json")

REQUIRED_FIELDS = (
    "id",
    "lifecycle",
    "title",
    "statement",
    "addresses",
    "rationale",
    "threats",
    "root_causes",
    "dimensions",
    "verify",
    "mappings",
    "gaps",
)

# Free-text id patterns: anything that looks like one of these must exist.
ID_PATTERNS = {
    "HG rule": re.compile(r"\bHG-[A-Z]+-\d{3}\b"),
    "airmkit": re.compile(r"\bAIRM-[0-9]+(?:\.[0-9]+)?(?:-[A-Z0-9]+)+\b"),
    "MITRE ATLAS": re.compile(r"\bAML\.T\d{4}(?:\.\d{3})?\b"),
    "OWASP LLM": re.compile(r"\bLLM\d{2}\b"),
    "OWASP Agentic": re.compile(r"\bASI\d{2}\b"),
    "OWASP MCP": re.compile(r"\bMCP\d{2}\b"),
}

FLAT_LIST_FRAMEWORKS = (
    "nist_ai_rmf",
    "owasp_llm_2025",
    "owasp_agentic",
    "owasp_mcp",
    "mitre_atlas",
)


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def class_mappings(root: Path) -> dict[str, dict[str, set[str]]]:
    """Per threat class, the set of ids per framework key, from both taxonomy files."""
    maps = {c["id"]: c for c in _load(root / "taxonomy/mappings.yaml")["classes"]}
    threats = {c["id"]: c for c in _load(root / "taxonomy/harness-threats.yaml")["classes"]}
    out: dict[str, dict[str, set[str]]] = {}
    for tid, t in threats.items():
        m = maps.get(tid, {})
        out[tid] = {
            "nist_ai_rmf": set(m.get("nist_ai_rmf", {}).get("subcategories", [])),
            "nist_ai_600_1.risks": set(m.get("nist_ai_600_1", {}).get("risks", [])),
            "nist_ai_600_1.section_numbers_unverified": set(
                m.get("nist_ai_600_1", {}).get("section_numbers_unverified", [])
            ),
            "iso_iec_42001.annex_a": set(m.get("iso_iec_42001", {}).get("annex_a", [])),
            "iso_iec_42001.clauses": set(m.get("iso_iec_42001", {}).get("clauses", [])),
            "mas_airm.paragraphs": set(m.get("mas_airm", {}).get("paragraphs", [])),
            "mas_airm.airmkit_controls": set(m.get("mas_airm", {}).get("airmkit_controls", [])),
            "owasp_llm_2025": set(t.get("owasp_llm_2025") or []),
            "owasp_agentic": set(t.get("owasp_agentic") or []),
            "owasp_mcp": set(t.get("owasp_mcp") or []),
            "mitre_atlas": set(t.get("mitre_atlas") or []),
        }
    return out


def control_mapping_items(mappings: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """(framework key, id) pairs of one control's mapping block."""
    for key in FLAT_LIST_FRAMEWORKS:
        for v in mappings.get(key) or []:
            yield key, str(v)
    for parent, children in (
        ("nist_ai_600_1", ("risks", "section_numbers_unverified")),
        ("iso_iec_42001", ("annex_a", "clauses")),
        ("mas_airm", ("paragraphs", "airmkit_controls")),
    ):
        block = mappings.get(parent) or {}
        for child in children:
            for v in block.get(child) or []:
                yield f"{parent}.{child}", str(v)


def _command_tree() -> Any:
    import typer.main

    from harnesswatch.cli import app

    return typer.main.get_command(app)


def check_command(cmd: str, tree: Any) -> list[str]:
    """Resolve `harnesswatch <sub> ...` against the CLI; report unknown subcommands or options."""
    try:
        tokens = shlex.split(cmd)
    except ValueError as exc:
        return [f"unparseable command {cmd!r}: {exc}"]
    if not tokens or tokens[0] != "harnesswatch":
        return [f"command does not start with 'harnesswatch': {cmd!r}"]
    node = tree
    rest = tokens[1:]
    while rest and hasattr(node, "commands") and rest[0] in node.commands:
        node = node.commands[rest.pop(0)]
    if hasattr(node, "commands"):
        return [f"command {cmd!r} stops at a group, not a subcommand"]
    if "--" in rest:
        rest = rest[: rest.index("--")]
    opts = {o for p in node.params for o in (*p.opts, *p.secondary_opts)}
    return [
        f"unknown option {tok.split('=')[0]!r} in {cmd!r}"
        for tok in rest
        if tok.startswith("-") and tok.split("=")[0] not in opts
    ]


def validate(root: Path = ROOT, *, check_commands: bool = True) -> list[str]:
    errors: list[str] = []
    data = _load(root / CHECKLIST_YAML)
    controls = data.get("controls") or []
    cmap = class_mappings(root)
    rules = {p.stem for p in (root / "rules").glob("HG-*.yaml")}
    root_causes = {c["id"] for c in _load(root / "taxonomy/root-causes.yaml")["classes"]}
    dimensions = {d["id"] for d in _load(root / "matrix/rubric.yaml")["dimensions"]}
    stages = set(data.get("lifecycle_stages") or {})
    kinds = set(data.get("addresses_kinds") or {})

    known: dict[str, set[str]] = {"HG rule": rules}
    union: dict[str, set[str]] = {}
    for per_class in cmap.values():
        for key, ids in per_class.items():
            union.setdefault(key, set()).update(ids)
    known["airmkit"] = union["mas_airm.airmkit_controls"]
    known["MITRE ATLAS"] = union["mitre_atlas"]
    known["OWASP LLM"] = union["owasp_llm_2025"]
    known["OWASP Agentic"] = union["owasp_agentic"]
    known["OWASP MCP"] = union["owasp_mcp"]

    # Every id-shaped token anywhere in the YAML must exist.
    for text in _strings(data):
        for label, pattern in ID_PATTERNS.items():
            for found in pattern.findall(text):
                if found not in known[label]:
                    errors.append(f"unknown {label} id {found!r} referenced in the checklist")

    tree = _command_tree() if check_commands else None
    seen: set[str] = set()
    for i, c in enumerate(controls, 1):
        cid = c.get("id", f"#{i}")
        missing = [f for f in REQUIRED_FIELDS if f not in c]
        if missing:
            errors.append(f"{cid}: missing fields {missing}")
            continue
        if cid != f"GC-{i:02d}":
            errors.append(f"{cid}: expected id GC-{i:02d} (sequential)")
        if cid in seen:
            errors.append(f"{cid}: duplicate id")
        seen.add(cid)
        if " shall " not in f" {c['statement']} ":
            errors.append(f"{cid}: statement has no 'shall'")
        if c["lifecycle"] not in stages:
            errors.append(f"{cid}: unknown lifecycle {c['lifecycle']!r}")
        errors += [
            f"{cid}: unknown 'addresses' kind {k!r}" for k in c["addresses"] if k not in kinds
        ]
        if not c["threats"]:
            errors.append(f"{cid}: cites no threat class")
        errors += [f"{cid}: unknown threat class {t}" for t in c["threats"] if t not in cmap]
        errors += [
            f"{cid}: unknown root cause {r}" for r in c["root_causes"] if r not in root_causes
        ]
        errors += [
            f"{cid}: unknown rubric dimension {d}" for d in c["dimensions"] if d not in dimensions
        ]
        verify = c["verify"]
        errors += [
            f"{cid}: unknown HG rule {r}" for r in verify.get("rules") or [] if r not in rules
        ]
        if not (verify.get("commands") or verify.get("manual")):
            errors.append(f"{cid}: no verification (command or manual check)")
        if tree is not None:
            for cmd in verify.get("commands") or []:
                errors += [f"{cid}: {e}" for e in check_command(cmd, tree)]
        cited = [cmap[t] for t in c["threats"] if t in cmap]
        for key, value in control_mapping_items(c["mappings"]):
            if key not in union:
                errors.append(f"{cid}: unknown mapping key {key}")
            elif value not in union[key]:
                errors.append(f"{cid}: {key} {value!r} does not exist in taxonomy/")
            elif not any(value in per_class[key] for per_class in cited):
                errors.append(
                    f"{cid}: {key} {value!r} is not supported by its threat classes {c['threats']}"
                )
    if not controls:
        errors.append("no controls")
    return errors


# ------------------------------------------------------------------------------- rendering


def _lookup(obj: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        obj = obj[part]
    return obj


def _fill(text: str, rq3: dict[str, Any]) -> str:
    return re.sub(r"\{\{rq3:([\w.\-]+)\}\}", lambda m: str(_lookup(rq3, m.group(1))), text)


def _join(items: Iterable[str]) -> str:
    items = list(items)
    return ", ".join(items) if items else "none mapped in taxonomy/"


def _code(items: Iterable[str]) -> str:
    return ", ".join(f"`{x}`" for x in items)


def render(root: Path = ROOT) -> str:
    data = _load(root / CHECKLIST_YAML)
    rq3 = json.loads((root / RQ3_JSON).read_text(encoding="utf-8"))
    by_class: dict[str, int] = rq3["by_taxonomy_class"]
    threats = {c["id"]: c["name"] for c in _load(root / "taxonomy/harness-threats.yaml")["classes"]}
    rcs = {c["id"]: c["name"] for c in _load(root / "taxonomy/root-causes.yaml")["classes"]}
    dims = {d["id"]: d["name"] for d in _load(root / "matrix/rubric.yaml")["dimensions"]}
    iso_titles = _load(root / "taxonomy/mappings.yaml")["frameworks"]["iso_iec_42001"][
        "annex_a_titles"
    ]
    status = data["framework_status"]
    stages = data["lifecycle_stages"]
    controls = data["controls"]

    out: list[str] = [
        f"# {data['title']}",
        "",
        f"Version {data['version']} · {data['date']} · Answers {data['research_question']}. "
        f"Generated from `{CHECKLIST_YAML.as_posix()}` by `scripts/gen_checklist_check.py --write`; "
        "edit the YAML, not this page.",
        "",
        f"> {data['status']}",
        "",
        _fill(data["preamble"], rq3).rstrip(),
        "",
        "### Kinds of issue",
        "",
        *[f"- **{k.replace('-', ' ')}**: {v}" for k, v in data["addresses_kinds"].items()],
        "",
        "### Control index",
        "",
        "| ID | Stage | Control | Addresses | Threat classes | HG rules |",
        "|---|---|---|---|---|---|",
    ]
    for c in controls:
        rules = ", ".join(c["verify"].get("rules") or []) or "manual"
        out.append(
            f"| {c['id']} | {stages[c['lifecycle']].split(' (')[0]} | {c['title']} | "
            f"{', '.join(c['addresses'])} | {', '.join(c['threats'])} | {rules} |"
        )
    out.append("")

    section = 3
    for stage_key, stage_title in stages.items():
        members = [c for c in controls if c["lifecycle"] == stage_key]
        if not members:
            continue
        out += [f"## {section}. {stage_title}", ""]
        section += 1
        for c in members:
            out += _render_control(c, threats, rcs, dims, by_class, iso_titles, status)

    out += [f"## {section}. Mapping status and gaps", ""]
    out += ["### Framework status", "", "| Framework | Status |", "|---|---|"]
    out += [f"| {v['label']} | {v['status']} |" for v in status.values()]
    out += ["", "### Gaps flagged per control", ""]
    for c in controls:
        for gap in c["gaps"]:
            out.append(f"- **{c['id']}**: {gap}")
        for note in c["mappings"].get("notes") or []:
            out.append(f"- **{c['id']}** (mapping note): {note}")
    out += [
        "",
        _fill(data["closing"], rq3).rstrip().replace("## 9.", f"## {section + 1}.", 1),
        "",
    ]
    return "\n".join(out)


def _render_control(
    c: dict[str, Any],
    threats: dict[str, str],
    rcs: dict[str, str],
    dims: dict[str, str],
    by_class: dict[str, int],
    iso_titles: dict[str, str],
    status: dict[str, dict[str, str]],
) -> list[str]:
    def incidents(t: str) -> str:
        n = by_class.get(t, 0)
        return f"{n} counted incident{'s' if n != 1 else ''}" if n else "no counted incidents"

    v = c["verify"]
    m = c["mappings"]
    lines = [
        f"### {c['id']} {c['title']}",
        "",
        f"**Control.** {c['statement']}",
        "",
        f"**Addresses.** {', '.join(k.replace('-', ' ') for k in c['addresses'])}.",
        "",
        f"**Why.** {c['rationale']}",
        "",
        "- Threat classes: "
        + "; ".join(f"{t} {threats[t]} ({incidents(t)})" for t in c["threats"]),
        "- Root causes: " + "; ".join(f"{r} {rcs[r]}" for r in c["root_causes"]),
        "- Rubric dimensions: " + "; ".join(f"{d} {dims[d]}" for d in c["dimensions"]),
        "",
        "**How to verify.**",
        "",
    ]
    if v.get("commands"):
        lines += ["```bash", *v["commands"], "```", ""]
    rules = v.get("rules") or []
    lines.append(f"- HG rules: {_code(rules) if rules else 'none; manual check'}")
    if v.get("manual"):
        lines.append(f"- Manual: {v['manual']}")
    nist600 = m["nist_ai_600_1"]
    iso = m["iso_iec_42001"]
    mas = m["mas_airm"]
    lines += [
        "",
        "**Framework mapping** (inherited from the cited threat classes).",
        "",
        "| Framework | Mapped items |",
        "|---|---|",
        f"| {status['nist_ai_rmf']['label']} | {_join(m['nist_ai_rmf'])} |",
        f"| {status['nist_ai_600_1']['label']} | {_join(nist600['risks'])}"
        + (
            f" (section numbers UNVERIFIED: {', '.join(nist600['section_numbers_unverified'])})"
            if nist600["section_numbers_unverified"]
            else ""
        )
        + " |",
        f"| {status['iso_iec_42001']['label']} (THIRD-PARTY titles) | "
        + _join(f"{a} {iso_titles.get(a, '')}".strip() for a in iso["annex_a"])
        + (f"; clauses {', '.join(iso['clauses'])}" if iso["clauses"] else "")
        + " |",
        f"| {status['owasp_llm_2025']['label']} | {_join(m['owasp_llm_2025'])} |",
        f"| {status['owasp_agentic']['label']} | {_join(m['owasp_agentic'])} |",
        f"| {status['owasp_mcp']['label']} (UNSTABLE) | {_join(m['owasp_mcp'])} |",
        f"| {status['mitre_atlas']['label']} | {_join(m['mitre_atlas'])} |",
        f"| MAS AIRM paragraphs | {_join(mas['paragraphs'])} |",
        f"| airmkit (MAS AIRM) | {_join(f'`{x}`' for x in mas['airmkit_controls'])} |",
        "",
    ]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--write", action="store_true", help="re-render brief/governance-checklist.md"
    )
    args = parser.parse_args(argv)
    errors = validate(ROOT)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    text = render(ROOT)
    md = ROOT / CHECKLIST_MD
    if args.write:
        md.write_text(text, encoding="utf-8")
        print(f"wrote {CHECKLIST_MD}")
    elif not md.exists() or md.read_text(encoding="utf-8") != text:
        print(f"{CHECKLIST_MD} is out of date; run with --write", file=sys.stderr)
        return 1
    n = len(_load(ROOT / CHECKLIST_YAML)["controls"])
    print(f"ok: {n} controls validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
