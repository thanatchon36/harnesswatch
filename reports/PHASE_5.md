# Phase 5 — Experiments E1–E7 and RQ3

Date: 2026-10-15 · Spend: **$0.00**

Each experiment has a collection step (network or Docker; run once, with the results committed) and an offline
analysis step that `make experiments` reruns from the committed JSON to regenerate every table and figure.

| Exp | Output | Headline (all figures from the results JSON) |
|---|---|---|
| E1 control matrix | `matrix/controls.csv`, `experiments/results/e1_matrix.json`, `e1_agreement.json`, scorecard, heatmap | 58 harnesses × D01–D15 = 870 cells: 664 scored, 206 N/A with reasons. Independent second rater: quadratic κ = 0.88, exact agreement 91.6%, 84 disagreements listed (not adjudicated, A24). |
| E2 corpus | `experiments/results/e2_corpus.json` | 1,010 public repos, 17 config targets, aggregate only, no repo identifiers stored. Stratified by file type (`e2_strata.json`): 51.8% of sampled agent config files declare repo MCP servers (HG-MCP-005), and 63.3% of sampled agent CI workflows grant write-scoped tokens (HG-CI-002). Pooled rates are a sampling artefact (hostile review). |
| E3 bench | `experiments/results/e3_bench.json` | See PHASE_4: 350 runs; follow 2/135 (auto) and 0/135 (default); task 84 vs 23. The secret reached the transcript in 10/10 Claude Code CLAUDE.md runs, through the documented `@`-import (E7 probe, HW-001), not through model action. |
| E4 supply chain | `experiments/results/e4_supply.json`, SBOMs | 23 packages: median 97 transitive dependencies; 10 of 18 with registry provenance; 17 curl installers, none verifying a signature; 299 OSV advisories (238 of them in one harness's pinned dependencies). |
| E5 residue | `experiments/results/e5_residue.json` | The synthetic `.env` secret ends up in harness state in 6 of 7 harnesses. It is readable by other local users in 3, given the container's 0755 home. No harness persisted the provider credential passed by env or config. N=1 per harness. |
| E6 rule accuracy | `experiments/results/e6_accuracy.json` | 376 labelled cases (113 hand-written). Held-out test split: precision 0.98 [0.95, 0.99], recall 0.98 [0.95, 0.99] (0.9825 in the JSON). DoD ≥ 0.9 met. |
| E7 claims vs observed | `matrix/claims_vs_observed.csv`, `experiments/results/e7_claims.json` | 23 probes, 117 documented claims, 28 tested: 22 match, 3 partial, 2 not observed, 1 mismatch (Antigravity `/help` needs auth despite the docs). The other claims are `untested`, with reasons. |
| RQ3 incidents | `experiments/results/rq3_incidents.json` | 323 incidents counted under A11 (99 in 2025, 224 in 2026). An earlier figure of 324 double-counted one incident; the dedup was made deterministic after the hostile review. Most common class is T03 (permission model), most common root cause RC3. For 135 of the 148 incidents with a fix date, the fix is dated on or before advisory publication. This measures disclosure practice, not time to fix. |

## Skipped / limitations
- E3 has one model (A25). E5 has N=1 per condition. E7 covers headless only, because interactive trust dialogs need a pty driver.
- E2 sampling is limited by code-search relevance and the index. The cap is 60 files per target, cut from 150 because of a session restart.
- Unverified framework clause numbers (ISO 42001, NIST 600-1) are flagged in the mappings and the checklist.

## Disclosure items pending: 2
Both are private. Item 2 (Cline workspace plugins) was closed as vendor-documented (A27). Item 3 did not reproduce in headless mode. See PHASE_1.
