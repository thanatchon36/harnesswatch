"""E2: config-corpus prevalence study (RQ4).

Samples public GitHub files that configure coding-agent harnesses via the code search API
(through the authenticated ``gh`` CLI), rebuilds each repository's sampled files in a temporary
tree, runs ``harnesswatch audit repo`` on it and records AGGREGATES ONLY.

Guardrails (MISSION section 8, rules 3 and 5):
* repository identifiers are hashed with a random per-run salt that is never saved, and only
  used in memory to deduplicate;
* no repository name, owner, URL or file content is ever written to a committed file; the
  result payload is checked against every identifier seen in the run before it is written;
* findings are reduced to (rule id, file key); messages and evidence (which may hold redacted
  secret residue) are dropped; HG-SEC/MCP-003 style findings are only counted;
* the temporary tree under experiments/corpus/raw/ is deleted at the end.

Usage: python experiments/e2_corpus.py [--per-target 150] [--seed 20261015]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from harnesswatch.bench.stats import wilson  # noqa: E402

RAW = ROOT / "experiments" / "corpus" / "raw"
OUT_JSON = ROOT / "experiments" / "results" / "e2_corpus.json"
OUT_TEX = ROOT / "paper" / "tables" / "e2_prevalence.tex"
OUT_MD = ROOT / "paper" / "tables" / "e2_prevalence.md"

# name -> (search query, predicate on the file path)
TARGETS: dict[str, tuple[str, str]] = {
    ".claude/settings.json": ("filename:settings.json path:.claude", ".claude/settings.json"),
    ".mcp.json": ("filename:.mcp.json", ".mcp.json"),
    ".cursor/mcp.json": ("filename:mcp.json path:.cursor", ".cursor/mcp.json"),
    ".vscode/mcp.json": ("filename:mcp.json path:.vscode", ".vscode/mcp.json"),
    "opencode.json": ("filename:opencode.json", "opencode.json"),
    ".kiro/settings/mcp.json": (
        "filename:mcp.json path:.kiro/settings",
        ".kiro/settings/mcp.json",
    ),
    ".gemini/settings.json": ("filename:settings.json path:.gemini", ".gemini/settings.json"),
    ".codex/config.toml": ("filename:config.toml path:.codex", ".codex/config.toml"),
    "AGENTS.md": ("filename:AGENTS.md", "AGENTS.md"),
    "CLAUDE.md": ("filename:CLAUDE.md", "CLAUDE.md"),
    ".github/copilot-instructions.md": (
        "filename:copilot-instructions.md path:.github",
        ".github/copilot-instructions.md",
    ),
    ".windsurf/rules": ("path:.windsurf/rules", ".windsurf/rules/"),
    ".agents/mcp_config.json": (
        "filename:mcp_config.json path:.agents",
        ".agents/mcp_config.json",
    ),
    ".grok/config.toml": ("filename:config.toml path:.grok", ".grok/config.toml"),
    "workflow:claude-code-action": (
        '"claude-code-action" path:.github/workflows',
        ".github/workflows/",
    ),
    "workflow:codex exec": ('"codex exec" path:.github/workflows', ".github/workflows/"),
    "workflow:gemini -p": ('"gemini -p" path:.github/workflows', ".github/workflows/"),
}

SEARCH_SLEEP = 7.0  # code search: ~10 requests/minute
MAX_BYTES = 200_000
PAGES = 3


# ----------------------------------------------------------------------------- pure helpers
def hash_id(salt: bytes, *parts: str) -> str:
    """Salted sha256 of identifying parts; only ever used to deduplicate inside one run."""
    h = hashlib.sha256(salt)
    for p in parts:
        h.update(b"\x00" + p.encode())
    return h.hexdigest()


def path_matches(path: str, pattern: str) -> bool:
    """A search hit counts for a target only if its path really is that config file."""
    if pattern.endswith("/"):
        return path.startswith(pattern) or ("/" + pattern) in ("/" + path)
    return path == pattern


def safe_relpath(path: str) -> str | None:
    """Reject traversal / absolute paths before writing a fetched path into the temp tree."""
    p = Path(path)
    if p.is_absolute() or ".." in p.parts or not path:
        return None
    return p.as_posix()


def reduce_findings(report: dict[str, Any]) -> tuple[set[tuple[str, str]], dict[str, str]]:
    """Reduce an audit JSON report to {(rule_id, file)} and {rule_id: static title}.

    Messages, evidence and remediation text are dropped on purpose (may echo file content).
    """
    pairs: set[tuple[str, str]] = set()
    titles: dict[str, str] = {}
    for f in report.get("findings", []):
        rid = str(f.get("rule_id", ""))
        path = str((f.get("location") or {}).get("path") or "")
        if not rid:
            continue
        pairs.add((rid, path))
        titles.setdefault(rid, str(f.get("title", "")))
    return pairs, titles


def aggregate(
    repos: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """repos: [{"files": n_files_audited, "fired": {(rule, file), ...}, "titles": {...}}].

    Returns per-rule repo / file counts with Wilson CIs. Repos denominator = audited repos,
    files denominator = audited files.
    """
    n_repos = 0
    n_files = 0
    rule_repos: dict[str, int] = defaultdict(int)
    rule_files: dict[str, int] = defaultdict(int)
    titles: dict[str, str] = {}
    for r in repos:
        n_repos += 1
        n_files += int(r["files"])
        fired = r["fired"]
        for rid in {rid for rid, _ in fired}:
            rule_repos[rid] += 1
        for rid, _ in fired:
            rule_files[rid] += 1
        titles.update(r.get("titles", {}))
    rules = []
    for rid in sorted(set(rule_repos) | set(rule_files)):
        lo, hi = wilson(rule_repos[rid], n_repos)
        flo, fhi = wilson(rule_files[rid], n_files)
        rules.append(
            {
                "rule_id": rid,
                "title": titles.get(rid, ""),
                "repos": rule_repos[rid],
                "repo_rate": rule_repos[rid] / n_repos if n_repos else 0.0,
                "repo_ci95": [round(lo, 4), round(hi, 4)],
                "files": rule_files[rid],
                "file_rate": rule_files[rid] / n_files if n_files else 0.0,
                "file_ci95": [round(flo, 4), round(fhi, 4)],
            }
        )
    rules.sort(key=lambda x: (-x["repos"], x["rule_id"]))
    return {"repos_audited": n_repos, "files_audited": n_files, "rules": rules}


def scrub_check(payload: Any, identifiers: Iterable[str]) -> None:
    """Raise if any run-time identifier (owner, repo, full name, URL fragment) leaks."""
    text = json.dumps(payload).lower()
    for ident in identifiers:
        if ident and "/" in ident and ident.lower() in text:
            raise ValueError("identifier leak in output payload")
    if re.search(r"github\.com/|https?://api\.github", text):
        raise ValueError("URL leak in output payload")


def identifiers_of(full_name: str) -> set[str]:
    owner, _, repo = full_name.partition("/")
    return {full_name, owner, repo}


def render_md(res: dict[str, Any]) -> str:
    a = res["prevalence"]
    lines = [
        f"E2 prevalence ({res['query_date']}): {a['repos_audited']} repositories, "
        f"{a['files_audited']} files audited.",
        "",
        "| Rule | Title | Repos | Repo rate (95% CI) | Files |",
        "|---|---|---:|---|---:|",
    ]
    for r in a["rules"]:
        lo, hi = r["repo_ci95"]
        lines.append(
            f"| {r['rule_id']} | {r['title']} | {r['repos']} | "
            f"{100 * r['repo_rate']:.1f}% ({100 * lo:.1f}-{100 * hi:.1f}) | {r['files']} |"
        )
    return "\n".join(lines) + "\n"


def tex_escape(s: str) -> str:
    for a, b in (
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("_", r"\_"),
        ("#", r"\#"),
        ("$", r"\$"),
    ):
        s = s.replace(a, b)
    return s


def render_tex(res: dict[str, Any], top: int = 10) -> str:
    """Paper table: the `top` most prevalent rules; the rest are summarised in one row (the
    Markdown table keeps every rule)."""
    a = res["prevalence"]
    rows = []
    for r in a["rules"][:top]:
        lo, hi = r["repo_ci95"]
        rows.append(
            f"{tex_escape(r['rule_id'])} & {tex_escape(r['title'])} & {r['repos']} & "
            f"{100 * r['repo_rate']:.1f}\\,[{100 * lo:.1f}, {100 * hi:.1f}] & {r['files']} \\\\"
        )
    rest = a["rules"][top:]
    if rest:
        rows.append(
            f"\\multicolumn{{2}}{{l}}{{\\emph{{{len(rest)} further rules, each in at most "
            f"{max(r['repos'] for r in rest)} repositories (see e2\\_prevalence.md)}}}} & & & \\\\"
        )
    body = "\n".join(rows)
    return (
        "% generated by experiments/e2_corpus.py\n"
        "\\begin{tabular}{llrrr}\n\\toprule\n"
        "Rule & Title & Repos & Repo rate \\% [95\\% CI] & Files \\\\\n\\midrule\n"
        f"{body}\n\\bottomrule\n\\end{{tabular}}\n"
    )


# ----------------------------------------------------------------------------- GitHub access
class ApiUnavailable(RuntimeError):
    pass


def gh(args: list[str], *, include: bool = False) -> tuple[int, dict[str, str], str]:
    """Run ``gh api``; returns (status, lowercase headers, body). Token never touched."""
    cmd = ["gh", "api"] + (["-i"] if include else []) + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise ApiUnavailable(type(e).__name__) from e
    out = p.stdout
    status, headers = 200, {}
    if include and out.startswith("HTTP/"):
        head, _, out = out.partition("\r\n\r\n") if "\r\n\r\n" in out else out.partition("\n\n")
        lines = head.splitlines()
        m = re.match(r"HTTP/\S+\s+(\d+)", lines[0])
        status = int(m.group(1)) if m else 0
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
    elif p.returncode != 0:
        status = 0
    return status, headers, out


def wait_for_limit(headers: dict[str, str]) -> float:
    if "retry-after" in headers:
        return float(headers["retry-after"]) + 1
    if headers.get("x-ratelimit-remaining") == "0" and "x-ratelimit-reset" in headers:
        return max(1.0, float(headers["x-ratelimit-reset"]) - time.time() + 2)
    return 0.0


def search(query: str, page: int) -> list[dict[str, Any]]:
    for attempt in range(6):
        status, headers, body = gh(
            [
                "-X",
                "GET",
                "search/code",
                "-f",
                f"q={query}",
                "-f",
                "per_page=100",
                "-f",
                f"page={page}",
            ],
            include=True,
        )
        if status == 200:
            wait = wait_for_limit(headers)
            time.sleep(max(SEARCH_SLEEP, wait))
            return json.loads(body).get("items", [])
        if status in (403, 429):
            time.sleep(max(60.0, wait_for_limit(headers)))
            continue
        if status == 422:  # query rejected / page beyond the 1000-result cap
            return []
        if status in (401, 0):
            raise ApiUnavailable(f"status {status}")
        time.sleep(15 * (attempt + 1))
    raise ApiUnavailable("search kept failing")


def fetch(full_name: str, path: str) -> bytes | None:
    status, headers, body = gh(
        ["-H", "Accept: application/vnd.github.raw+json", f"repos/{full_name}/contents/{path}"],
        include=True,
    )
    if status in (403, 429):
        time.sleep(max(30.0, wait_for_limit(headers)))
        status, headers, body = gh(
            ["-H", "Accept: application/vnd.github.raw+json", f"repos/{full_name}/contents/{path}"],
            include=True,
        )
    if status != 200 or len(body) > MAX_BYTES:
        return None
    return body.encode()


def collect(target: str, per_target: int, rng: random.Random) -> list[tuple[str, str]]:
    """Return up to per_target (full_name, path) hits, one file per repo per target."""
    query, pattern = TARGETS[target]
    seen: dict[str, str] = {}
    for page in range(1, PAGES + 1):
        items = search(query, page)
        if not items:
            break
        for it in items:
            name = it["repository"]["full_name"]
            path = it["path"]
            if name not in seen and path_matches(path, pattern) and safe_relpath(path):
                seen[name] = path
        if len(items) < 100:
            break
    hits = sorted(seen.items())
    rng.shuffle(hits)
    return hits[:per_target]


def run_audit(tree: Path) -> dict[str, Any] | None:
    exe = shutil.which("harnesswatch") or str(ROOT / ".venv" / "bin" / "harnesswatch")
    try:
        p = subprocess.run(
            [exe, "audit", "repo", str(tree), "-f", "json", "--fail-on", "critical"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(ROOT),
        )
        return json.loads(p.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None


# ----------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-target", type=int, default=150)
    ap.add_argument("--seed", type=int, default=20261015)
    ap.add_argument("--targets", nargs="*", help="subset of targets (debug)")
    ap.add_argument(
        "--tables-only",
        action="store_true",
        help="re-render tables from the committed JSON (offline)",
    )
    args = ap.parse_args()
    if args.tables_only:
        res = json.loads(OUT_JSON.read_text())
        OUT_MD.write_text(render_md(res))
        OUT_TEX.write_text(render_tex(res))
        return 0

    rng = random.Random(args.seed)
    RAW.mkdir(parents=True, exist_ok=True)
    # Resume state lives only under the gitignored raw/ dir and is deleted at the end. The salt
    # is kept there (and nowhere else) so that hashes stay stable across a restart.
    state_path = RAW / "progress.json"
    state: dict[str, Any] = {}
    if state_path.exists():
        state = json.loads(state_path.read_text())
    if "salt" not in state:
        shutil.rmtree(RAW, ignore_errors=True)
        RAW.mkdir(parents=True)
        state = {
            "salt": os.urandom(16).hex(),
            "done": {},
            "files": {},
            "names": [],
            "skipped": 0,
            "per_target": args.per_target,
        }
    salt = bytes.fromhex(state["salt"])

    result: dict[str, Any] = {
        "experiment": "E2",
        "research_question": "RQ4",
        "query_date": date.today().isoformat(),
        "api": "GitHub REST code search (search/code) + contents API, via authenticated gh CLI",
        "sampling": {
            "per_target_cap": args.per_target,
            "pages_per_query": PAGES,
            "per_page": 100,
            "one_file_per_repo_per_target": True,
            "shuffle_seed": args.seed,
            "max_file_bytes": MAX_BYTES,
        },
        "queries": {t: q for t, (q, _) in TARGETS.items()},
        "status": "ok",
    }
    seen_ids: set[str] = set()
    sample_sizes: dict[str, int] = {}
    fetched_sizes: dict[str, int] = {}
    repo_hash_files: dict[str, dict[str, str]] = defaultdict(dict)  # repo hash -> path -> target
    for k, v in state["files"].items():
        repo_hash_files[k].update(v)
    seen_ids |= set(state["names"])
    for t, (a, b) in state["done"].items():
        sample_sizes[t], fetched_sizes[t] = a, b
    dedup_skipped = state["skipped"]
    try:
        targets = args.targets or list(TARGETS)
        for t in targets:
            if t in state["done"]:
                print(f"[{t}] resumed", flush=True)
                continue
            hits = collect(t, args.per_target, rng)
            sample_sizes[t] = len(hits)
            ok = 0
            for name, path in hits:
                seen_ids.add(name)
                rel = safe_relpath(path)
                rh = hash_id(salt, name)
                if rel is None or rel in repo_hash_files[rh]:
                    dedup_skipped += 1
                    continue
                data = fetch(name, path)
                if data is None:
                    continue
                dest = RAW / rh[:20] / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                repo_hash_files[rh][rel] = t
                ok += 1
            fetched_sizes[t] = ok
            state.update(
                files={k: dict(v) for k, v in repo_hash_files.items()},
                names=sorted(seen_ids),
                skipped=dedup_skipped,
            )
            state["done"][t] = [len(hits), ok]
            state_path.write_text(json.dumps(state))
            print(f"[{t}] sampled={len(hits)} fetched={ok}", flush=True)
    except ApiUnavailable as e:
        result["status"] = f"api_unavailable ({e}); partial or empty"
        print("API unavailable, stopping gracefully", flush=True)

    # audit
    dirs = sorted(d for d in RAW.iterdir() if d.is_dir())
    with ThreadPoolExecutor(4) as ex:
        reports = list(ex.map(run_audit, dirs))
    repos: list[dict[str, Any]] = []
    audit_errors = 0
    per_target_files: dict[str, int] = defaultdict(int)
    per_target_fired: dict[str, set[tuple[str, str]]] = defaultdict(set)
    path_target: dict[tuple[str, str], str] = {}
    for d, rep in zip(dirs, reports, strict=True):
        rh = next(k for k in repo_hash_files if k[:20] == d.name)
        files = repo_hash_files[rh]
        if rep is None:
            audit_errors += 1
            continue
        fired, titles = reduce_findings(rep)
        repos.append({"files": len(files), "fired": fired, "titles": titles})
        for p, t in files.items():
            per_target_files[t] += 1
            path_target[(rh, p)] = t
        for rid, p in fired:
            t = files.get(p)
            if t:
                per_target_fired[t].add((rh, rid + "|" + p))

    prevalence = aggregate(repos)
    result["per_target"] = {
        t: {
            "sampled": sample_sizes.get(t, 0),
            "fetched": fetched_sizes.get(t, 0),
            "audited_files": per_target_files.get(t, 0),
            "rule_file_findings": len({x for x in per_target_fired.get(t, set())}),
        }
        for t in (args.targets or list(TARGETS))
    }
    result["total_sampled"] = sum(sample_sizes.values())
    result["total_fetched"] = sum(fetched_sizes.values())
    result["audit_errors"] = audit_errors
    result["prevalence"] = prevalence
    result["redaction_note"] = (
        "Secret-related rules (e.g. HG-MCP-003) are reported as counts only; "
        "no matched text is retained."
    )
    result["limitations"] = [
        "Code search returns a relevance-ranked, index-limited subset (max 1,000 hits per "
        "query, we read 300); the sample is not random over GitHub and favours popular, "
        "recently indexed and well-formed files.",
        "The code-search index lags pushes and omits forks, large files and some repos, so "
        "freshness varies; results describe the index on the query date only.",
        "A repository can be sampled via several targets; its sampled files are audited "
        "together, so repo rates are over repositories with at least one sampled file.",
        "Rates are per sampled repository and are not weighted by usage; static rules flag "
        "risky configuration, not exploitation.",
        "User-level (home) config is not observable in public repos; only project-level files.",
        "Files over 200 kB and unreadable files were skipped; one file per repo per target.",
    ]
    result["dedup_skipped"] = dedup_skipped

    shutil.rmtree(RAW, ignore_errors=True)
    scrub_check(result, seen_ids)
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(result, indent=2) + "\n")
    OUT_MD.write_text(render_md(result))
    OUT_TEX.write_text(render_tex(result))
    print(f"wrote {OUT_JSON.name}: repos={prevalence['repos_audited']}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
