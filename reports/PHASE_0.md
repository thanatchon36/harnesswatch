# Phase 0 — Bootstrap (2026-10-15)

## Done
- Name check: `harnessguard` taken on PyPI (v0.6.4, GitHub-Actions AI-workflow linter, created
  2026-09-13); `harnesswatch` free on PyPI and GitHub → package/import/CLI `harnesswatch` (A01).
- Scaffold per MISSION §5.6 (src layout, `rules/`, `taxonomy/`, `matrix/`, `evidence/`, `bench/`,
  `experiments/`, `paper/`, `brief/`, `docs/`, `private/` gitignored).
- Tooling: uv, hatchling, ruff, mypy --strict, pytest+cov+hypothesis, pre-commit (ruff, gitleaks,
  hygiene hooks), GitHub Actions matrix (Ubuntu/macOS × 3.12/3.13) with Codecov upload.
- LICENSE (Apache-2.0), SECURITY.md, CHANGELOG.md, ASSUMPTIONS.md (A01–A07), VERSIONS.md, PROGRESS.md.
- Core models (`Finding`, `HarnessProfile`, `HarnessConfig`, `McpServer`, `Hook`), profile loader,
  `harnesswatch inventory` prototype: PATH lookup, static version detection (native-installer path,
  npm package.json, pip dist-info) with opt-in `--exec-version`, install-method classification,
  state-dir and credential-file permission bits (never contents), repo harness-file detection,
  home-relative path display.
- Local environment detection (no secrets printed): Docker 29.9.1 with NVIDIA runtime, RTX 4070 Ti,
  no vendor API keys, Claude Code 2.1.300 (native installer), no Linux Node.js.
- Bench model server: private `hw-ollama` container (0.40.4) with `qwen3:8b` pulled.
- Phase 1 research fan-out launched (7 subagents).

## Skipped / deferred
- CI green on GitHub: the public repo does not exist yet (creating it is an outward-facing action
  left for the author — RELEASE_CHECKLIST). Local `make all` is green.
- `pre-commit install` not run on the host (gitleaks hook needs a Go toolchain bootstrap; CI runs
  the same checks). Logged for Phase 7.

## Open questions
- none blocking.

## Spend
$0.00
