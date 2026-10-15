# CLI reference

Run `harnesswatch <command> --help` for the authoritative option list.

| Command | Purpose |
|---|---|
| `harnesswatch version` | Print the version. |
| `harnesswatch inventory [REPO]` | Detect installed harnesses and harness files in REPO. `--json`, `--exec-version`. |
| `harnesswatch audit <name> [PATH]` | Static audits, read-only and offline by default. |
| `harnesswatch report INPUTS...` | Merge JSON reports into Markdown, SARIF or JSON, optionally diffing against a baseline. |
| `harnesswatch observe HARNESS -- COMMAND...` | Black-box probe in a sandbox (see [Observe](observe.md)). |

## audit

| Audit | Covers |
|---|---|
| `config` | Permission modes, allowlists, hooks, network, telemetry and credentials in harness configs. |
| `mcp` | MCP server declarations: pinning, transport and auth, inline secrets, tool poisoning. |
| `instructions` | Injection indicators in instruction, rules and skill files. |
| `secrets` | Secret residue in harness logs, transcripts and memory; loose file permissions (redacted). |
| `supply` | Installed harness packages: installer verification, known vulnerabilities, SBOM. |
| `ci` | Headless agents in CI workflows triggered by untrusted input. |
| `repo` | `config`, `mcp`, `instructions` and `ci` without reading the home directory. |
| `all` | Every audit: repository plus this machine's user-level harness state. |

Common options of the audits:

| Option | Meaning |
|---|---|
| `-f`, `--format` | `rich` (default), `json`, `markdown`, `sarif`. |
| `-o`, `--output` | Write the report to a file. |
| `--fail-on` | Exit 1 if any finding is at or above `critical`, `high` (default), `medium`, `low` or `info`. |
| `--baseline` | JSON report whose findings are suppressed. |
| `--user` / `--no-user` | Include user-level config (`config`, `mcp`, `instructions` and others, not `ci` or `repo`). |
