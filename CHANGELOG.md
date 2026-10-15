# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-15

### Added
- `harnesswatch inventory`: installed harnesses, versions, install method, state dirs, credential-file modes.
- `harnesswatch audit config|mcp|instructions|secrets|supply|ci|repo|all`: profile-driven parsing of 58 harness
  profiles into a common `HarnessConfig` schema, and 25 `HG-*` rules, each with should-fire and should-not-fire fixtures.
- Output in Rich, JSON, Markdown and SARIF 2.1.0; `report` with `--baseline`; exit codes 0/1/2.
- `harnesswatch observe`: sandboxed black-box behavioural probe covering the egress proxy, packet-header sniffer, /proc
  sandbox evidence, files and modes, and trust prompts. It records metadata only.
- `harnesswatch bench`: inert canary prompt-injection benchmark with 7 harness adapters, Wilson CIs and a resumable grid.
- GitHub Action (`action.yml`), pre-commit hooks, and a MkDocs documentation site.
- Research artefacts: threat taxonomy (T01–T19), control matrix, incident timeline, experiments E1–E7, the paper,
  the executive brief and the governance checklist.

### Security
- Fixed the code-review findings in `reports/CODE_REVIEW.md`:
  - hostile YAML is now rejected;
  - secret redaction now covers report evidence;
  - repository scans no longer follow symlinks out of the repo;
  - a ReDoS in the secret pattern is removed;
  - observe refuses to run when an allowed host is dual-homed.
