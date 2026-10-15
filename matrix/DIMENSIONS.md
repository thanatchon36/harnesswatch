# Control dimensions (draft v0 — finalised in Phase 2)

Used for the RQ2 control matrix (`matrix/controls.csv`) and per-harness evidence
(`matrix/evidence/<harness>.json`). Generic score scale (Phase 2 refines per dimension):

- **0** — control absent, or present only as an unsafe default with no way to change it.
- **1** — control exists but is opt-in, weak, easily bypassed, or poorly documented.
- **2** — control exists and is on by default, with documented gaps or no central enforcement.
- **3** — strong safe default, enforceable centrally (managed policy) and well documented.
- **N/A** — not applicable to this harness class, or `N/A (no access: <reason>)`.

| ID | Dimension | What to look for |
|---|---|---|
| D01 | Permission model | per-tool/per-command approval, allow/deny lists, modes, default mode, auto-approve/YOLO availability and how it is enabled (flag, config, repo file?) |
| D02 | Execution sandbox | OS-level FS/process sandbox (Seatbelt, bubblewrap, Landlock, containers, VMs), default on/off |
| D03 | Network egress control | domain allowlists for fetch/shell, network off by default in sandbox, proxying |
| D04 | Workspace & config trust | folder-trust prompt, whether repo-level config (hooks, MCP, settings, rules) is honoured before consent |
| D05 | MCP governance | approval of project MCP servers, allowlists/denylists, managed MCP policy, tool-description change detection, OAuth handling |
| D06 | Extensions/skills/plugins | marketplace vetting, signing, scope, install-time scripts, auto-update of plugins |
| D07 | Secrets & credential storage | OS keychain vs plaintext, file permissions, secret redaction in logs/transcripts, `.env` read protection |
| D08 | Headless/CI safeguards | non-interactive mode defaults, official CI action hardening (permissions, untrusted-input guidance, actor checks) |
| D09 | Persistent memory | existence, scope (project vs global), agent-writable, user review/visibility |
| D10 | Sub-agent / delegation isolation | do sub-agents inherit permissions/env, worktree/container isolation |
| D11 | Audit logging | local transcripts, structured audit logs, OpenTelemetry export, enterprise audit log |
| D12 | Telemetry & data retention | telemetry default, opt-out, training-use default, retention period, residency |
| D13 | Distribution supply chain | installer checksums/signatures, signed binaries/provenance (Sigstore/SLSA), SBOM, auto-update channel control |
| D14 | Managed/enterprise policy | admin-enforced settings file / MDM / org policy that users cannot override |
| D15 | Vulnerability disclosure | SECURITY.md, published advisories, bug bounty, CVE issuance |

## Evidence JSON (`matrix/evidence/<harness>.json`)

```json
{
  "harness": "claude-code",
  "version": "2.1.300",
  "analysed_on": "2026-10-15",
  "status": "analysed",
  "dimensions": {
    "D01": {
      "facts": [
        {"claim": "Default permission mode asks before each Bash command.",
         "source": "https://...", "label": "from-official-docs", "accessed": "2026-10-15"}
      ],
      "proposed_score": 2,
      "rationale": "one or two sentences tying the facts to the scale"
    }
  }
}
```

Labels (MISSION §6.4): `verified-by-test` · `from-official-docs` · `third-party-report` · `unverified`.
A dimension with no verifiable facts gets `"proposed_score": null` and `"rationale": "N/A (...)"`.
