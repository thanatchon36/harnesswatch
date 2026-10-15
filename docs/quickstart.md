# Quickstart

## Install

```bash
pipx install harnesswatch      # or: pip install harnesswatch
harnesswatch version
```

From a checkout: `uv sync && uv run harnesswatch version`.

## Inventory

```bash
harnesswatch inventory           # installed harnesses plus harness files in the current repo
harnesswatch inventory --json
```

## Audit a repository

```bash
harnesswatch audit config .          # permission modes, hooks, network, telemetry, credentials
harnesswatch audit mcp .             # MCP server declarations
harnesswatch audit instructions .    # injection indicators in instruction and skill files
harnesswatch audit ci .              # headless agents in workflows ("pwn request")
harnesswatch audit repo .            # all four, without reading the home directory
```

Audits exit 1 when a finding is at or above `--fail-on` (default `high`). Use `--no-user` to skip
user-level (home) configuration, and `--baseline report.json` to suppress known findings.

## SARIF and code scanning

```bash
harnesswatch audit repo . -f sarif -o harnesswatch.sarif
```

Upload the file with `github/codeql-action/upload-sarif`, or use the repository's composite
action (see the README) which does this for you.

To merge several reports: `harnesswatch report a.json b.json -f sarif -o merged.sarif`.
