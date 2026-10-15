# Phase 3 — Toolkit core (including the 3b `observe` delta)

Date: 2026-10-15 · Spend: $0.00

## Done
- **Package `harnesswatch`** (A01), CLI: `version`, `inventory`, `audit config|mcp|instructions|secrets|supply|ci|repo|all`,
  `report`, `observe`, `bench list|run|report`.
  - Output formats: Rich, JSON, Markdown and SARIF 2.1.0 (golden-file test).
  - Exit codes: 0 clean, 1 findings at or above `--fail-on`, 2 error. `--baseline` diffing.
- **Common schema:** `HarnessConfig` (pydantic v2). A profile-driven generic parser covers 58 harness profiles.
  - Parser fixtures for 26 harnesses: every Tier-A harness plus Claude Code, Antigravity, Grok Build, Cursor, Copilot and Kiro (`tests/test_parsers_harnesses.py`).
  - Formats: JSON, JSONC, JSON5 subset, TOML, YAML and Markdown front matter.
- **Rule pack:** 25 rules (`rules/HG-*.yaml`), each with `should_fire` and `should_not_fire` fixtures. E6 tightened 9 rules and added 22 regression fixtures.
- **`observe`** (MISSION §5.2, built first in the 3b delta because Phases 4–5 depend on it):
  - an internal Docker network, an egress proxy, and a packet-header sniffer that catches DNS even when Docker's resolver port is NATed;
  - /proc sampling for sandbox evidence, `docker diff` plus tar headers for files and modes;
  - effective other-user readability, a canary file count, and permission/trust prompt capture;
  - metadata only (A17).
  - Works on closed harnesses (Claude Code, Grok Build binary, Copilot CLI, Antigravity CLI) and open ones (Codex, OpenCode); see E7.
- **Bench package:** scenarios, adapters for 7 harnesses, scoring, Wilson CIs, a resumable grid with a budget guard, and raw transcript capture (gitignored).
- **Docs:** MkDocs Material site with reference pages generated from the rules, profiles and taxonomy; `make docs` builds it with `--strict`.
  `action.yml` (composite GitHub Action) and `.pre-commit-hooks.yaml`.
- **Engineering:**
  - 297 tests, 93% line coverage, ruff and `mypy --strict` clean; hypothesis fuzzing of the parsers.
  - CI workflows pinned by SHA, and a PyPI Trusted Publishing release workflow.
- **DoD check:** `pip install` of the built wheel in a clean `python:3.12-slim` container, then `inventory && audit config .`, takes 3.5 s on a cold first run and 0.8 s warm. That meets the < 5 s target only after the libyaml fix; before it took 8.3 s.

## Skipped / N/A
- `pre-commit install` was not run locally: pre-commit is not installed on the host. Hook definitions are shipped for users.
- gitleaks is not installed on the host. Secret-shaped fixture content is generated at test time (`{{SYNTH:kind}}`), and a regex scan before each commit found no matches.
- The GitHub Action and the docs deployment have never run on GitHub, because the public repository does not exist yet (an outward action left to the author; see RELEASE_CHECKLIST.md).

## Open questions
- Interactive trust-dialog probing needs a pty driver. It is not implemented, so those claims stay `untested`.
