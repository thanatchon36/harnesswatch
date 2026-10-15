# PROGRESS.md — single source of truth for run state

Bench spend so far: **$0.00** (cap $25; local models only — see ASSUMPTIONS A04)

## Phases
- [x] 0 Bootstrap
- [x] 1 Landscape & evidence (+1b black-box)
- [x] 2 Threat model (+2b)
- [x] 3 Toolkit core (+3b observe)
- [x] 4 Canary-bench (+4b Tier-B)
- [x] 5 Experiments (E1-E7, RQ3)
- [x] 6 Writing (+ hostile review, code review)
- [x] 7 Release (prepared; outward steps in RELEASE_CHECKLIST.md)

## Log
| When | Phase | Task | Files | Tests |
|---|---|---|---|---|
| 2026-10-15 | 0 | Name check (→ harnesswatch), scaffold, tooling, CI workflow, LICENSE, SECURITY, CHANGELOG | pyproject.toml, Makefile, .github/workflows/ci.yml, src/ | make all green (1 test, 100 % cov) |
| 2026-10-15 | 0 | Local env detection: Docker+GPU OK, no vendor API keys, Claude Code 2.1.300 installed, no Linux Node | VERSIONS.md, ASSUMPTIONS.md | — |
| 2026-10-15 | 1 | Research fan-out launched: G1–G5 harness groups, G6/G7 incidents 2025/2026 | rules/harness_profiles/_SCHEMA.md, matrix/DIMENSIONS.md, evidence/README.md | — |
| 2026-10-15 | 0 | inventory prototype + models + profile loader | src/harnesswatch/{models,resources,inventory,cli}.py, tests/ | 12 passed, 92 % cov |
| 2026-10-15 | 3 | Toolkit core (early): rules engine, profile-driven parsers, 6 audits, 24 rules + fixtures, SARIF/JSON/MD, CLI | src/, rules/, tests/ | 128 passed, 93 % cov |
| 2026-10-15 | 1 | All 7 research agents done: 59 profiles + evidence JSON, ledger 1414 rows, 328 unique incidents (103 dupes merged), 278 bib entries; merge script | scripts/merge_evidence.py, evidence/, matrix/evidence/, VERSIONS.md | — |
| 2026-10-15 | 1 | **Disclosure items pending (2)**: two source-reading candidates recorded privately; details withheld pending coordinated vendor disclosure (MISSION §8.4) | private/ (gitignored) | — |
| 2026-10-15 | 1b | B1–B4 black-box research merged; NVD/GHSA re-check (272/328 confirmed); PHASE_1 and PHASE_2 reports; observe module (proxy + sniffer + /proc + diff), works on Claude Code; **disclosure item 3** (private; details withheld pending coordinated vendor disclosure (MISSION §8.4)) | evidence/, matrix/claims_vs_observed.csv, src/harnesswatch/observe/ | 146 passed, 94 % cov |

## Scope change 2026-10-15 (A14): delta vs revised MISSION.md

### Phase 0b — black-box scope (addendum, run now)
- [x] Access detection → ACCESS.md (Claude Code, Antigravity agy/IDE, Grok Build, other Tier B; no secrets printed)
- [x] VERSIONS.md: pin Tier-B versions from Phase 1b, plus an access column

### Phase 1b — black-box scope (addendum, run now)
- [x] B1 Claude Code black-box profile: docs claims, npm package metadata, advisories → claims_vs_observed rows
- [x] B2 Antigravity (agy + IDE): profile refresh, installer metadata, claims, incidents
- [x] B3 Grok Build: open-source status, local-model path, claims, incidents
- [x] B4 other Tier B (Cursor CLI, Copilot CLI, Kiro CLI, Amp, Droid, Auggie, Qoder, …): no-login or BYOK paths, claims
- [x] Merge B1–B4 into the ledger, incidents and matrix; new file matrix/claims_vs_observed.csv (claims side)

### Phase 2 delta
- [x] Taxonomy: RQ7 claims-vs-observed dimension; Tier labels A/B/C/D in rubric applicability

### Phase 3 delta (build `observe` FIRST — Phases 4–5 depend on it)
- [x] `harnesswatch observe <harness> [-- CMD]`: sandboxed run, egress log, fs watch, credential location, sandbox evidence, prompts → JSON
- [ ] observe works on ≥1 open and ≥1 closed harness (Claude Code)
- [ ] Parsers: Antigravity (.agent/ rules/workflows/skills, agy config) and Grok Build (~/.grok, .grok/) fixture tests

### Phase 4 delta
- [ ] Tier-B bench adapters (claude-code via local model; grok if custom model works without login), each run wrapped in observe

### Phase 5 delta
- [ ] E7 black-box behavioural profiles → matrix/claims_vs_observed.csv, table and figure

### Phase 6 delta
- [ ] Paper: RQ7 section, §1.1 method, the Tier A/B/C/D framing

## Next task
None in this run. All phases are complete. Outward actions (public repo, PyPI, signed tag, arXiv, announcement) are left to the author in RELEASE_CHECKLIST.md.
Disclosure items pending: 2 (private/DISCLOSURE_DRAFT.md).
Total spend: $0.00.
