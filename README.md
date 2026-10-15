<p align="center"><img src="docs/assets/logo.svg" alt="harnesswatch logo" width="120"></p>

<h1 align="center">harnesswatch</h1>

[![CI](https://github.com/thanatchon36/harnesswatch/actions/workflows/ci.yml/badge.svg)](https://github.com/thanatchon36/harnesswatch/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/thanatchon36/harnesswatch/branch/main/graph/badge.svg)](https://codecov.io/gh/thanatchon36/harnesswatch)
[![PyPI](https://img.shields.io/pypi/v/harnesswatch.svg)](https://pypi.org/project/harnesswatch/)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue)](https://thanatchon36.github.io/harnesswatch/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

📄 **[Read the paper on the web](https://thanatchon36.github.io/harnesswatch/paper/)** ·
⬇️ **[Download the PDF](https://github.com/thanatchon36/harnesswatch/raw/main/paper/main.pdf)** ·
📚 **[Documentation](https://thanatchon36.github.io/harnesswatch/)** ·
📋 **[Executive brief](brief/executive-brief.pdf)**

**Security audit toolkit and research study for AI coding-agent harnesses.** The harness is the runtime
loop (Claude Code, Codex CLI, OpenCode, Cursor, Copilot CLI, Kiro, Grok Build, Antigravity, Goose, Aider and others)
that holds credentials, runs shell commands, starts MCP servers, reads repository-level configuration and runs
unattended in CI. harnesswatch audits that layer, and the accompanying paper measures it.

- **Static audits:** repository and user configs for 58 harness profiles, normalised into one schema and checked by
  25 rules (`HG-*`) for auto-approve modes, repository hooks, unpinned or unauthenticated MCP servers,
  injection indicators in instruction files, secret residue, supply chain and CI "pwn-request" patterns.
  Output is Rich, JSON, Markdown or **SARIF 2.1.0**.
- **`observe`:** a black-box behavioural probe for closed and open harnesses. It runs the harness in a sandboxed
  container and records the hosts contacted, files written with their modes, sandboxing evidence and trust prompts.
  It records metadata only and never request bodies.
- **`bench`:** an inert canary prompt-injection benchmark. It runs in disposable containers with egress blocked,
  uses synthetic secrets and sends exfiltration only to a local sink.

## Install and quickstart

```bash
pip install harnesswatch            # Python >= 3.12
harnesswatch inventory              # harnesses installed on this machine (never prints secrets)
harnesswatch audit config .         # user + repo config of every supported harness
harnesswatch audit repo . -f sarif -o harnesswatch.sarif   # repo-only audits for CI
harnesswatch audit secrets          # secret residue and permissions in harness state dirs (redacted)
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` error.
A recorded demo is in [`docs/demo.cast`](docs/demo.cast) (asciinema v2; regenerate with `python scripts/make_demo_cast.py`).

| Command | Purpose |
|---|---|
| `inventory` | Binaries, versions, install method, state dirs, credential-file modes |
| `audit config\|mcp\|instructions\|secrets\|supply\|ci\|repo\|all` | Static audits (read-only; `--online` enables OSV lookups for `supply`/`all`) |
| `report` | Merge JSON reports, `--baseline` diffing, SARIF/Markdown output |
| `observe <harness> --image IMG -- CMD` | Black-box probe in a sandbox (Docker) |
| `bench list\|run\|report` | Canary benchmark (Docker + a local model server) |

## Research: *The Harness Is the Attack Surface* (2025–2026)

The paper is in [`paper/`](paper/): a PDF in [`paper/main.pdf`](paper/main.pdf), a [web version](https://thanatchon36.github.io/harnesswatch/paper/) (built into [`docs/paper/`](docs/paper/)) and a Markdown mirror in [`paper/paper.md`](paper/paper.md).
It answers seven research questions: the threat taxonomy, a control matrix covering 58 harnesses, incidents and CVEs from
2025–2026, detection accuracy, a canary benchmark, governance, and documented claims vs observed behaviour for closed
harnesses. Every number in the paper is generated from `experiments/results/*.json`, and every harness claim carries
an evidence label (verified-by-test / from-official-docs / third-party-report).

- Executive brief (2 pages): [`brief/executive-brief.md`](brief/executive-brief.md) · PDF alongside
- Governance checklist (30 controls, each mapped to NIST AI RMF, ISO/IEC 42001, OWASP, MITRE ATLAS and MAS AI-RM, with the
  verifying `harnesswatch` command): [`brief/governance-checklist.md`](brief/governance-checklist.md)
- Evidence: [`evidence/`](evidence/) (ledger, incidents, sources), [`matrix/`](matrix/) (control matrix,
  claims vs observed), [`taxonomy/`](taxonomy/), [`VERSIONS.md`](VERSIONS.md)

Reproduce:

```bash
make all      # lint -> types -> tests (coverage gate) -> docs -> experiments (offline) -> paper -> build
make bench    # re-run the canary benchmark (Docker, pinned harness images, local Ollama model)
```

## Safety and ethics
Defensive use only. Canary payloads are inert, and every bench and observe run is sandboxed. Only synthetic secrets are used. Closed-source
harnesses are analysed black-box only: no decompilation and no leaked source. Suspected new vulnerabilities go
through coordinated disclosure. See [`SECURITY.md`](SECURITY.md) and MISSION.md §8.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only needed for upload-sarif
steps:
  - uses: actions/checkout@v4
  - uses: thanatchon36/harnesswatch@v0   # pin to a full commit SHA in production
    with:
      audits: config mcp instructions ci   # default
      fail-on: high                        # default
      sarif-output: harnesswatch.sarif
      upload-sarif: "true"
```

Inputs: `path`, `audits`, `fail-on`, `sarif-output`, `upload-sarif`, `version` (PyPI version,
default latest), `python-version`.

## pre-commit

```yaml
repos:
  - repo: https://github.com/thanatchon36/harnesswatch
    rev: v0.1.0   # pin to a tag or commit
    hooks:
      - id: harnesswatch-config
      - id: harnesswatch-mcp
      - id: harnesswatch-instructions
      - id: harnesswatch-ci
```

Each hook runs `harnesswatch audit <x> .` with `--fail-on high`, without reading your home directory.

## Documentation

`make docs` regenerates the reference pages and builds the MkDocs Material site (`site/`).

## Related projects
- [upfront](https://github.com/thanatchon36/upfront): token-cost view of MCP servers, skills and instruction files.
- rulewarden: deterministic enforcement of CLAUDE.md/AGENTS.md rules. An `HG-INJ` finding can suggest a rulewarden policy.
- airmkit: MAS AI-risk-management toolkit. The governance checklist uses its `AIRM-*` control vocabulary.

## Citation
See [`CITATION.cff`](CITATION.cff). License: Apache-2.0.
