"""E7 analysis (offline): fill the observed side of matrix/claims_vs_observed.csv (RQ7).

Each check names a documented claim (CVO id), the probe(s) that test it, and a function that
turns the probe's observe report into (observed text, verdict). Verdicts:
- match: observed behaviour agrees with the documented claim;
- mismatch: it contradicts the claim;
- partial: it agrees in part, or only some conditions could be tested;
- not-observed: the probe ran, but the behaviour did not occur in headless mode (no verdict);
- untested: no probe exists, with a reason (no access, needs an interactive pty, terms, or model).
Hosts are re-classified from host names with the current rules/observe_hosts.yaml.

Writes matrix/claims_vs_observed.csv (in place), experiments/results/e7_claims.json and
paper/tables/e7_claims.tex|.md.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from harnesswatch.observe.analyze import classify_host
from harnesswatch.observe.runner import load_host_table

ROOT = Path(__file__).resolve().parents[1]
E7 = ROOT / "experiments" / "results" / "e7"
CSV = ROOT / "matrix" / "claims_vs_observed.csv"
TABLE = load_host_table()
DATE = "2026-10-15"

Report = dict[str, Any]
Check = Callable[[dict[str, Report]], tuple[str, str]]


def probe(name: str) -> Report | None:
    path = E7 / f"{name}.json"
    return json.loads(path.read_text()) if path.exists() else None


def vendor_hosts(result: Report) -> list[str]:
    hosts = []
    for h in result["report"]["hosts"]:
        if classify_host(h["host"], TABLE) != "local":
            hosts.append(f"{h['host']}:{h['port']}" if h["port"] else h["host"])
    return sorted(set(hosts))


def wrote(result: Report, path: str) -> bool:
    return any(f["path"] == path and f["change"] != "D" for f in result["report"]["files"])


def files_under(result: Report, prefix: str) -> list[dict[str, Any]]:
    return [
        f for f in result["report"]["files"] if f["path"].startswith(prefix) and f["type"] == "file"
    ]


def reachable(result: Report, prefix: str) -> list[str]:
    """Files under prefix that other local users could read (file o+r, known ancestors o+x)."""
    modes = {f["path"]: int(f["mode"], 8) for f in result["report"]["files"] if f["mode"]}
    out = []
    for f in files_under(result, prefix):
        mode = modes.get(f["path"])
        if mode is None or not mode & 0o004:
            continue
        parts = f["path"].split("/")
        ancestors = ["/".join(parts[:i]) for i in range(2, len(parts))]
        if all(modes.get(a, 0o755) & 0o001 for a in ancestors):
            out.append(f["path"])
    return out


# --- checks per claim id --------------------------------------------------------------------


def _hosts_claim(name: str, allowed: set[str]) -> Check:
    def run(p: dict[str, Report]) -> tuple[str, str]:
        hosts = vendor_hosts(p[name])
        extra = [h for h in hosts if h.split(":")[0] not in allowed]
        text = f"vendor hosts attempted: {', '.join(hosts) or 'none'}"
        return text, "mismatch" if extra else "match"

    return run


def _file_effect(name: str, path: str, expect: bool, what: str) -> Check:
    def run(p: dict[str, Report]) -> tuple[str, str]:
        happened = wrote(p[name], path)
        text = f"{what}: {'yes' if happened else 'no'} ({name})"
        return text, "match" if happened == expect else "mismatch"

    return run


def cc_b1_002(p: dict[str, Report]) -> tuple[str, str]:
    hosts = vendor_hosts(p["cc-baseline"])
    dd = [h for h in hosts if "datadoghq" in h]
    return (
        f"with a gateway base URL, Datadog intake contacted: {'yes' if dd else 'no'}",
        "mismatch" if dd else "match",
    )


def cc_b1_005(p: dict[str, Report]) -> tuple[str, str]:
    hosts = vendor_hosts(p["cc-baseline"])
    upd = [h for h in hosts if "npmjs" in h or "downloads.claude.ai" in h]
    if upd:
        return f"update host contacted in -p: {', '.join(upd)}", "match"
    return "no update-check host contacted during a headless (-p) session", "not-observed"


def cc_b1_008(p: dict[str, Report]) -> tuple[str, str]:
    r = p["cc-repo-env"]
    redirected = any(h["host"] == "hw-redirect.invalid" for h in r["report"]["hosts"])
    config_dir = any(f["path"].startswith("/tmp/hw-config-dir") for f in r["report"]["files"])
    text = (
        f"repo env ANTHROPIC_BASE_URL followed: {'yes' if redirected else 'no'}; "
        f"repo env CLAUDE_CONFIG_DIR applied: {'yes' if config_dir else 'no'}"
    )
    return text, "match" if redirected and not config_dir else "mismatch"


def cc_b1_012(p: dict[str, Report]) -> tuple[str, str]:
    r = p["cc-repo-mcp"]
    ran = wrote(r, "/workspace/HW_MCP_RAN")
    status = r["facts"].get("mcp_servers")
    return (
        f"repo .mcp.json stdio server started without prompt: {'yes' if ran else 'no'}; "
        f"init status {status}",
        "match" if ran else "mismatch",
    )


def cc_b1_018(p: dict[str, Report]) -> tuple[str, str]:
    creds = [
        f["path"] for f in files_under(p["cc-baseline"], "/home/agent") if "credential" in f["path"]
    ]
    return (
        f"credential files written with ANTHROPIC_AUTH_TOKEN: {', '.join(creds) or 'none'}",
        "match" if not creds else "mismatch",
    )


def cc_b1_020(p: dict[str, Report]) -> tuple[str, str]:
    mode = p["cc-baseline"]["facts"].get("permission_mode")
    return (
        f"init permissionMode with a third-party base URL: {mode}",
        "match" if mode == "auto" else "mismatch",
    )


def cc_b1_021(p: dict[str, Report]) -> tuple[str, str]:
    refused = p["cc-root-bypass"]["facts"].get("mentions_root_refusal")
    return (
        f"--dangerously-skip-permissions as uid 0 refused: {'yes' if refused else 'no'}",
        "match" if refused else "mismatch",
    )


def cc_b1_022(p: dict[str, Report]) -> tuple[str, str]:
    mode = p["cc-repo-defaultmode"]["facts"].get("permission_mode")
    return (
        f"repo permissions.defaultMode=bypassPermissions -> init permissionMode {mode}",
        "match" if mode != "bypassPermissions" else "mismatch",
    )


def cc_b1_023(p: dict[str, Report]) -> tuple[str, str]:
    r = p["cc-baseline"]
    transcripts = [
        f for f in files_under(r, "/home/agent/.claude/projects") if f["path"].endswith(".jsonl")
    ]
    modes = sorted({f["mode"] for f in transcripts})
    exposed = reachable(r, "/home/agent/.claude")
    return (
        f"transcripts written: {len(transcripts)} (modes {', '.join(modes) or '-'}); "
        f"other-user-readable files under ~/.claude: {len(exposed)}",
        "match" if transcripts else "mismatch",
    )


def grok_hosts(p: dict[str, Report]) -> tuple[str, str]:
    hosts = vendor_hosts(p["grok-baseline"])
    return (
        f"vendor hosts attempted with a custom local model and no login: {', '.join(hosts) or 'none'}",
        "match",
    )


def grok_hook(p: dict[str, Report]) -> tuple[str, str]:
    untrusted = wrote(p["grok-repo-hook-untrusted"], "/workspace/HW_HOOK_RAN")
    trusted = wrote(p["grok-repo-hook-trusted"], "/workspace/HW_HOOK_RAN")
    compat = wrote(p["grok-claude-compat-hook"], "/workspace/HW_HOOK_RAN")
    text = (
        f"repo hook ran untrusted: {'yes' if untrusted else 'no'}; with --trust: "
        f"{'yes' if trusted else 'no'}; .claude/settings.json compat hook untrusted: "
        f"{'yes' if compat else 'no'}"
    )
    return text, "match" if (not untrusted and trusted and not compat) else "mismatch"


def grok_mcp(p: dict[str, Report]) -> tuple[str, str]:
    ran = wrote(p["grok-repo-mcp-untrusted"], "/workspace/HW_MCP_RAN")
    return (
        f"project .mcp.json (compat import) server started in an untrusted folder: {'yes' if ran else 'no'}",
        "partial" if not ran else "mismatch",
    )


def grok_state(p: dict[str, Report]) -> tuple[str, str]:
    r = p["grok-baseline"]
    exposed = reachable(r, "/home/agent/.grok")
    sessions = [f for f in exposed if "/sessions/" in f]
    return (
        f"files written under ~/.grok: {len(files_under(r, '/home/agent/.grok'))}; other-user-readable: "
        f"{len(exposed)} (session files among them: {len(sessions)})",
        "match",
    )


def cop_offline(p: dict[str, Report]) -> tuple[str, str]:
    hosts = vendor_hosts(p["copilot-offline"])
    online = vendor_hosts(p["copilot-online-byok"]) if p.get("copilot-online-byok") else []
    return (
        f"COPILOT_OFFLINE=true vendor hosts: {', '.join(hosts) or 'none'}; without it (BYOK): "
        f"{', '.join(online) or 'none'}",
        "mismatch" if hosts else "match",
    )


def cop_mcp(p: dict[str, Report]) -> tuple[str, str]:
    ran = wrote(p["copilot-repo-mcp"], "/workspace/HW_MCP_RAN")
    return (
        f"repo .mcp.json server started in an untrusted folder (-p): {'yes' if ran else 'no'}",
        "match" if not ran else "mismatch",
    )


def cop_hook(p: dict[str, Report]) -> tuple[str, str]:
    ran = wrote(p["copilot-repo-hook"], "/workspace/HW_HOOK_RAN")
    return (
        f"repo .github/hooks sessionStart hook ran in -p: {'yes' if ran else 'no'}",
        "match" if ran else "not-observed",
    )


def agy_update(p: dict[str, Report]) -> tuple[str, str]:
    r = p["agy-prelogin"]
    upd = [h for h in vendor_hosts(r) if "updater" in h or "run.app" in h]
    lock = bool(files_under(r, "/home/agent/.gemini/antigravity-cli/updater"))
    ts = wrote(r, "/home/agent/.gemini/antigravity-cli/last_check.timestamp")
    return (
        f"background updater contacted: {', '.join(upd) or 'none'}; last_check.timestamp: "
        f"{'yes' if ts else 'no'}; updater lock files: {'yes' if lock else 'no'}",
        "match" if upd and ts and lock else "partial",
    )


def agy_noupdate(p: dict[str, Report]) -> tuple[str, str]:
    r = p["agy-prelogin-noupdate"]
    upd = [h for h in vendor_hosts(r) if "updater" in h or "run.app" in h]
    return (
        f"with AGY_CLI_DISABLE_AUTO_UPDATE=true, updater host contacted: {', '.join(upd) or 'none'}",
        "match" if not upd else "mismatch",
    )


def agy_telemetry(p: dict[str, Report]) -> tuple[str, str]:
    r = p["agy-prelogin"]
    tel = [h for h in vendor_hosts(r) if classify_host(h.split(":")[0], TABLE) == "telemetry"]
    return (
        f"before any login, telemetry/logging hosts attempted: {', '.join(tel) or 'none'} "
        f"(default enableTelemetry=true)",
        "match" if tel else "not-observed",
    )


def agy_auth(p: dict[str, Report]) -> tuple[str, str]:
    r = p["agy-prelogin"]
    auth = r["facts"].get("mentions_auth_required")
    return (
        f"unauthenticated headless run: exit {r['rc']}, auth-required message: {'yes' if auth else 'no'}, "
        f"duration {r['report']['duration_s']} s",
        "match" if auth and r["rc"] not in {"", "0"} else "mismatch",
    )


def agy_help(p: dict[str, Report]) -> tuple[str, str]:
    r = p["agy-help-noauth"]
    auth = r["facts"].get("mentions_auth_required")
    return (
        f"`agy -p /help` without credentials: exit {r['rc']}, auth required: {'yes' if auth else 'no'}",
        "mismatch" if auth else "match",
    )


def agy_mcp(p: dict[str, Report]) -> tuple[str, str]:
    r = p["agy-prelogin"]
    ran = wrote(r, "/workspace/HW_MCP_RAN")
    hook = wrote(r, "/workspace/HW_HOOK_RAN")
    return (
        f"before login/trust: repo .agents MCP server started: {'yes' if ran else 'no'}; "
        f"repo hook ran: {'yes' if hook else 'no'}",
        "partial",
    )


def agy_state(p: dict[str, Report]) -> tuple[str, str]:
    r = p["agy-prelogin"]
    exposed = reachable(r, "/home/agent/.gemini")
    return (
        f"pre-login files under ~/.gemini: {len(files_under(r, '/home/agent/.gemini'))}; "
        f"other-user-readable: {len(exposed)}",
        "partial",
    )


def cc_import(p: dict[str, Report]) -> tuple[str, str]:
    r = p["cc-claudemd-import-env"]
    hits = [
        f["path"]
        for f in r["report"]["files"]
        if f["canary_hit"] and not f["path"].startswith("/workspace")
    ]
    return (
        f"@.env inside a CLAUDE.md command line imported the gitignored .env into the session "
        f"transcript without a model call or prompt: {'yes' if hits else 'no'}",
        "match" if hits else "not-observed",
    )


CC_DOC_HOSTS = {
    "api.anthropic.com",
    "http-intake.logs.us5.datadoghq.com",
    "statsig.anthropic.com",
    "registry.npmjs.org",
    "downloads.claude.ai",
    "raw.githubusercontent.com",
    "storage.googleapis.com",
}

CHECKS: dict[str, tuple[list[str], Check]] = {
    "CVO-B1-001": (["cc-baseline"], _hosts_claim("cc-baseline", CC_DOC_HOSTS)),
    "CVO-B1-002": (["cc-baseline"], cc_b1_002),
    "CVO-B1-003": (["cc-nonessential"], _hosts_claim("cc-nonessential", set())),
    "CVO-B1-005": (["cc-baseline"], cc_b1_005),
    "CVO-B1-008": (["cc-repo-env"], cc_b1_008),
    "CVO-B1-010": (
        ["cc-repo-hook"],
        _file_effect(
            "cc-repo-hook",
            "/workspace/HW_HOOK_RAN",
            True,
            "repo SessionStart hook ran under -p, untrusted",
        ),
    ),
    "CVO-B1-012": (["cc-repo-mcp"], cc_b1_012),
    "CVO-B1-015": (
        ["cc-repo-hook-bare"],
        _file_effect(
            "cc-repo-hook-bare", "/workspace/HW_HOOK_RAN", False, "repo hook ran with --bare"
        ),
    ),
    "CVO-B1-018": (["cc-baseline"], cc_b1_018),
    "CVO-B1-020": (["cc-baseline"], cc_b1_020),
    "CVO-B1-021": (["cc-root-bypass"], cc_b1_021),
    "CVO-B1-022": (["cc-repo-defaultmode"], cc_b1_022),
    "CVO-B1-023": (["cc-baseline"], cc_b1_023),
    "CVO-HW-001": (["cc-claudemd-import-env"], cc_import),
    "B3-C001": (["grok-baseline"], grok_hosts),
    "B3-C009": (
        ["grok-repo-hook-untrusted", "grok-repo-hook-trusted", "grok-claude-compat-hook"],
        grok_hook,
    ),
    "B3-C011": (["grok-repo-mcp-untrusted"], grok_mcp),
    "B3-C016": (["grok-baseline"], grok_state),
    "B4-C008": (["copilot-offline", "copilot-online-byok"], cop_offline),
    "B4-C009": (["copilot-repo-mcp"], cop_mcp),
    "B4-C010": (["copilot-repo-hook"], cop_hook),
    "CVO-B2-003": (["agy-prelogin"], agy_update),
    "CVO-B2-004": (["agy-prelogin-noupdate"], agy_noupdate),
    "CVO-B2-005": (["agy-prelogin"], agy_telemetry),
    "CVO-B2-015": (["agy-prelogin"], agy_auth),
    "CVO-B2-016": (["agy-help-noauth"], agy_help),
    "CVO-B2-023": (["agy-prelogin"], agy_mcp),
    "CVO-B2-013": (["agy-prelogin"], agy_state),
}

UNTESTED_REASON = {
    "antigravity": "N/A (no access: needs a Google login; no local-model path; A19)",
    "cursor": "N/A (no access: needs a Cursor account; no local-model path)",
    "kiro": "N/A (no access: needs a Kiro login; no local-model path)",
}


def main() -> None:
    rows = list(csv.DictReader(CSV.open(encoding="utf-8")))
    probes = {p.stem: json.loads(p.read_text()) for p in E7.glob("*.json")}
    for row in rows:
        check = CHECKS.get(row["id"])
        if check and all(name in probes for name in check[0]):
            observed, verdict = check[1](probes)
            row.update(
                observed=observed,
                observed_method="harnesswatch observe: " + ", ".join(check[0]),
                observed_date=DATE,
                verdict=verdict,
            )
        elif check:
            row.update(verdict="untested", observed="probe not run yet")
        else:
            reason = UNTESTED_REASON.get(
                row["harness"],
                "untested: needs an interactive session, a vendor login, model behaviour or a probe not implemented",
            )
            row.update(verdict="untested", observed=reason, observed_method="", observed_date="")
    with CSV.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    tested = [r for r in rows if r["verdict"] not in {"untested"}]
    summary = {
        "claims": len(rows),
        "tested": len(tested),
        "verdicts": dict(Counter(r["verdict"] for r in rows)),
        "by_harness": {
            h: dict(Counter(r["verdict"] for r in rows if r["harness"] == h))
            for h in sorted({r["harness"] for r in rows})
        },
        "probes": sorted(probes),
        "rows": [
            {
                k: r[k]
                for k in ("id", "harness", "dimension", "documented_claim", "observed", "verdict")
            }
            for r in tested
        ],
    }
    out = ROOT / "experiments" / "results" / "e7_claims.json"
    out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    write_tables(tested)
    print(f"{len(tested)} of {len(rows)} claims tested: {summary['verdicts']}")


def _tex(text: str) -> str:
    text = text.replace("\\", "/").replace("{", "(").replace("}", ")")
    for a, b in (
        ("&", "\\&"),
        ("%", "\\%"),
        ("_", "\\_"),
        ("#", "\\#"),
        ("$", "\\$"),
        ("~", "\\textasciitilde{}"),
    ):
        text = text.replace(a, b)
    return text


def write_tables(rows: list[dict[str, str]]) -> None:
    out = ROOT / "paper" / "tables"
    out.mkdir(parents=True, exist_ok=True)
    md = ["| Harness | Claim | Dimension | Observed | Verdict |", "|---|---|---|---|---|"]
    tex = [
        "\\begin{tabular}{p{1.9cm}p{2.3cm}p{10.4cm}p{1.6cm}}",
        "\\toprule",
        "Harness & Dimension & Observed & Verdict \\\\",
        "\\midrule",
    ]
    for r in sorted(rows, key=lambda r: (r["harness"], r["id"])):
        md.append(
            f"| {r['harness']} | {r['id']} | {r['dimension']} | {r['observed']} | {r['verdict']} |"
        )
        tex.append(
            f"{_tex(r['harness'])} & {_tex(r['dimension'])} & {_tex(r['observed'])} & {r['verdict']} \\\\"
        )
    tex += ["\\bottomrule", "\\end{tabular}"]
    (out / "e7_claims.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out / "e7_claims.tex").write_text("\n".join(tex) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
