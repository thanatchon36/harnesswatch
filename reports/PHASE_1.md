# Phase 1 — Landscape & evidence (including Phase 1b, black-box scope)

Date: 2026-10-15 · Spend: $0.00 (research only; no model API calls)

## Done

**1a. Original fan-out (G1–G7)**
- Seven research agents worked in parallel: G1 Anthropic/Claude, G2 OSS CLIs I, G3 OSS CLIs II,
  G4 closed IDEs/CLIs, G5 SDKs/runtimes, G6 incidents 2025, G7 incidents 2026. Notes are in `evidence/research/G*.md`.
- 58 harness profiles in `rules/harness_profiles/`, with per-harness evidence and D01–D15 facts in `matrix/evidence/*.json`.
- `scripts/merge_evidence.py` merges the fragments (`*.d/`) into the canonical files.

**1b. Black-box scope (A14, MISSION revision of 2026-10-15)**
- B1 Claude Code: 25 documented claims, an observe plan with 15 config-trust probes, and package metadata.
  The D01 score was lowered 3→1 and D13 3→2; see below.
- B2 Antigravity (`agy` and IDE): 32 claims, 11 new incidents. The profile was rewritten for the `.agents/` layout,
  and parser ownership of `~/.gemini/` was fixed.
- B3 Grok Build: hybrid tier (A18); a local-model config that needs no login; 14 incidents; 25 claims.
- B4 other Tier B: Copilot CLI has a documented BYOK path with no login (A20). Junie and trae-agent probably work
  too. There is no path for Cursor, Kiro, Amp, Auggie, Jules or Windsurf.

**Canonical evidence after the merge**

| Artefact | Count |
|---|---|
| `evidence/ledger.csv` | 1,517 rows: 1,366 from-official-docs, 80 third-party-report, 69 unverified, 2 verified-by-test |
| `evidence/incidents.csv` | 358 unique incidents (104 duplicates merged): 329 with verified=yes; 110 from 2025, 247 from 2026 |
| `evidence/sources.bib` | 384 entries with access dates |
| `matrix/claims_vs_observed.csv` | 116 documented claims for RQ7 (observed side pending E7) |
| `VERSIONS.md` | 60 harness rows plus local environment |

**Independent ID verification (A11).** `scripts/verify_incidents.py` re-queried NVD 2.0 and the GitHub advisory API for
every CVE and GHSA. Of the first 328 incidents:
- 272 confirmed;
- 52 have no CVE/GHSA ID and rely on a primary source only;
- 3 partially resolved: the GHSA confirmed it but the CVE is not on NVD yet;
- 1 had its GHSA found, but the record does not name the product.

The 31 new Phase-1b incidents are being re-checked by the same script. Only incidents that pass both checks are counted in the paper.

## Corrections to the MISSION seed list (all logged in the ledger)
- CVE-2025-59536 was published 2025-10-03 (fixed in 1.0.111). Check Point's write-up is dated 2026-02-25, and the 2026 CVE
  in that story is CVE-2026-21852.
- CamoLeak has no CVE. Codex `--full-auto` no longer exists.
- Kilo is MIT-licensed and an OpenCode fork. kimi-cli became kimi-code. Pi moved to earendil-works. goose moved to aaif-goose. Windsurf became Devin Desktop.
- Roo Code was discontinued on 2026-05-15, and Continue is unmaintained.
- Antigravity's current repo layout is `.agents/` (`.agent/` is legacy). It has no `--yolo`; the equivalent is `--dangerously-skip-permissions`.
  The CLI is 1.3.5.
- Grok Build source is public (Apache-2.0). Telemetry is off by default, not on.

## Skipped / N/A (with reason)
- **Antigravity IDE and `agy` bench:** `N/A (no access: Google login required; local model unsupported; terms)` (A19).
  A pre-login observe is planned for E7.
- **Bench for Cursor CLI, Kiro CLI, Amp, Auggie, Jules and Windsurf/Devin:** `N/A (no access: vendor account required, no local-model path)`.
- **Factory Droid and Qoder:** they have BYOK, but login is still enforced, so `N/A (no access)`.

## Disclosure items pending (3), all private and untested, nothing published
1. A Tier-A harness candidate (source reading; details private).
2. Cline CLI auto-discovers workspace plugins (source reading, G2).
3. A Tier-B harness candidate (local observation; details private). A container
   test is planned in E5/E7, and the draft will be updated with the result.

Details are in `private/DISCLOSURE_DRAFT.md` (gitignored).

## Open questions
- How should a classifier "auto" mode (Claude Code's default since 2.1.285) score on D01? It is not a human prompt, but
  it is not bypass either. The E1 second rater has to decide this, and the paper will discuss it.
- Twenty-nine incidents have `verified=no`. They stay out of RQ3 counts.


## Update after the hostile review (2026-10-15)
- Disclosure item 2 (Cline) was closed: the behaviour is vendor-documented (A27). **2 items remain pending.**
- The Grok binary-strings fact B3-004 was withdrawn (A26).
- Incident dedup is now deterministic: 357 unique rows, 323 counted.
