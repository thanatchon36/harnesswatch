# Phase 2 notes: threat model, root causes, rubric

Date: 2026-10-15. Scope: RQ1 (taxonomy, attack trees, framework mapping), the final root-cause
classes behind RQ3, and the per-dimension rubric behind RQ2. Nothing here was committed.

Deliverables: `taxonomy/harness-threats.yaml`, `taxonomy/mappings.yaml`, `taxonomy/root-causes.yaml`,
`taxonomy/incident-classification.csv` (328 rows), `taxonomy/attack-trees.md` (7 trees),
`matrix/rubric.yaml`, `matrix/rubric.md`.

## 1. What changed vs the MISSION seed

Taxonomy (details in the `changes:` list of `harness-threats.yaml`):

- T01-T16 keep their ids and meaning. No renumbering.
- Three classes were added because the incident set showed large groups with no home:
  T17 sandbox/isolation escape (19 rows), T18 agent control-plane exposure and authorization (34 rows),
  T19 conventional software defects in runtimes and SDKs (46 rows).
- T04 was narrowed to MCP protocol trust; bugs in MCP server code are classified by mechanism.
  T13 was narrowed to multi-tenant isolation and authorization. T02 was widened to git configuration,
  workspace executables and agent-writable execution-sensitive files.
- A 16-step ordered rule ("first control that failed") assigns exactly one primary class per incident.
  The drafts disagreed mainly because each agent chose between entry vector (T01) and failed control.

Root causes (`root-causes.yaml`): RC1-RC9 kept with sharper definitions; RC10 (conventional defect),
RC11 (autonomy beyond intent), RC12 (adversarial use) added; a 12-question ordered procedure replaces
free choice. RC6 takes precedence over RC2/RC3/RC4 when a protection exists but ships off.

Re-classification (`incident-classification.csv`): of 328 rows, the draft root cause was kept on 231
and changed on 97; the draft taxonomy class was kept on 200 and changed on 128 (4 draft rows were
blank/unmapped). Movement matrices are in `root-causes.yaml`. Final distribution: T03 67, T02 52,
T19 46, T18 34, T08 23, T17 19, T01 15, T04 13, T06 12, T07 10, T09 8, T13 8, T05 6, T15 4, T16 3,
T11 3, T14 2, T10 2, T12 1. Root causes: RC3 97, RC10 53, RC2 51, RC4 24, RC1 22, RC8 21, RC5 17,
RC7 15, RC6 15, RC9 8, RC12 3, RC11 2. Kinds: 286 vulnerability, 16 design-weakness, 14 supply-chain,
9 incident, 3 misuse (two rows moved to `incident`: the Claude Code source-map entry and the OpenClaw exposed-panel entry).

Rubric: D01-D15 kept; D16 (local service and control-plane exposure) proposed because T18 is
about 10% of incidents and no dimension covers it. Criteria were rewritten to be decidable from
`matrix/evidence/*.json` (fact labels, "highest score whose criteria are all met", unverified facts
ignored, third-party reports can only lower a score). I checked that the rubric reproduces the
draft claude-code D01 = 3 and D07 = 2.

Observation for RQ1: the "agent-specific" share is not the majority. By root cause, RC3 (defective
approval/allowlist/path checks) plus RC2 (config executed before consent) are about 45% of rows;
RC10 (conventional bugs) is 16%; pure injection with no other defect (RC1) is 7%. The answer to
"how does it differ from classic LLM-app risk" is therefore: the LLM is the delivery vector, but
the damage and most root causes sit in the deterministic harness layer.

## 2. Verification log (what was fetched, 2026-10-15)

| Framework | Source read | Result |
|---|---|---|
| MITRE ATLAS | `mitre-atlas/atlas-data` `dist/manifest.yaml` and `dist/ATLAS-latest.yaml` via `gh api` | Latest release 2026.09 (2026-09-15), format 6.0.0. `dist/ATLAS.yaml` is deprecated (5.6.0), not used. All 50 distinct technique ids in the YAML were checked programmatically for existence and their descriptions read (e.g. AML.T0110 AI Agent Tool Poisoning, AML.T0081 Modify AI Agent Configuration, AML.T0086 Exfiltration via AI Agent Tool Invocation, AML.T0105 Escape to Host, AML.T0132 Misconfigured or Publicly Exposed AI Services). |
| OWASP LLM Top 10 2025 | genai.owasp.org/llm-top-10/ | LLM01..LLM10 names confirmed. |
| OWASP LLM Top 10 2026 | genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ (landing page), search summaries | Edition exists (v1.0, published 2026-08-03); the page does not list entries; renumbering (Excessive Agency to LLM03, LLM08 Hidden Context Exposure) is from secondary sources only. NOT mapped. |
| OWASP Agentic Top 10 | genai.owasp.org landing page (published 2025-12-09; PDF behind the download link returned HTML, not text); OWASP GitHub repo `www-project-top-10-for-large-language-model-applications`, `initiatives/agent_security_initiative` (incident page lists all ten ASI names); giskard.ai summary | ASI01..ASI10 names confirmed from the OWASP repo and one independent summary. |
| OWASP MCP Top 10 | owasp.org/www-project-mcp-top-10/ | MCP01..MCP10 names read. Project says both "Beta Release and Pilot Testing" and "Production Project"; no version or date. Mapping kept but flagged unstable. |
| NIST AI RMF 1.0 | airc.nist.gov Playbook pages for Govern, Map, Measure, Manage | Statements read for all ids used. The Measure page was truncated after 2.11 and Map after 4.2, so MEASURE 3.x/4.x and MAP 5.x were not used. |
| NIST AI 600-1 | nist.gov publication page (date 2024-07-26); PDF downloaded but text not extractable here | Risk names used by name; numbers 2.2/2.5/2.6/2.9 corroborated only by airmkit; others unverified. |
| ISO/IEC 42001:2023 | riskprofs.com and blckalpaca.at listings (agree); certpro.com listing (different numbering, rejected) | Annex A ids/titles are at control level, secondary-sourced; standard not read (paywalled). Clause titles from memory. |
| MAS AIRM Guidelines | MAS PDF downloaded with a browser user agent; SHA-256 equals the hash in `airmkit/docs/sources/MANIFEST.md`; contents page and para 5.16 read; airmkit `clause-index.md` and `controls.yaml` read | Final, dated 7 October 2026; sections 1-6 named; effective dates per airmkit's reading of para 1.8 (not re-read by me). MAS HTML landing pages returned 404/maintenance. |
| airmkit | `gh api repos/thanatchon36/airmkit/...` | 65 `AIRM-*` control ids; every id used in `mappings.yaml` verified to exist. |

## 3. Things I could not verify

- OWASP Agentic Top 10 original PDF text (names verified from the OWASP repository instead).
- OWASP LLM Top 10 2026 per-entry list.
- NIST AI 600-1 section numbering other than the four anchors; ISO 42001 text (secondary listings only).
- Whether the MAS effective-date schedule (Sections 3-4 from 2027-10-07, 5-6 by 2028-10-07) is exactly as airmkit states; I did not re-read para 1.8.
- STRIDE letters, ASI/LLM/MCP mappings for T10, T15, T16, T18, T19 are judgement calls (flagged in `mapping_notes`). T15 has no ATLAS technique and T16, T18 no LLM entry: left empty rather than forced.

## 4. Data quality caveats on the incident set

- 99 rows carry "also reported as <id>" in `notes`; many are the same issue captured by two research groups
  (e.g. Clinejection G2-I004 and G7-I059, Antigravity G4-I033 and G7-I091). All rows were classified, and
  duplicate pairs received identical class/root cause. Counts per class include duplicates; deduplicate
  before quoting RQ3 numbers. 27 rows are `verified=no`.
- 7 rows are low confidence because the source record is sparse (G6-023, G4-I029, G2-I018, G6-064, G3-I010,
  G7-I043, G1-I001); rationale says so.
- Judgement-heavy boundaries a reviewer may want to contest: injection-written configuration is T02/RC2
  (not T01); DNS or safe-command exfiltration through a permitted command is T08/RC3; MCP SDK DNS-rebinding
  protection off by default is T18/RC6; git-config execution by harness helper operations is T02/RC2 but
  an escape from a sandboxed writer is T17/RC8.
- Kinds: the CSV keeps the five-value `kind` vocabulary. "Policy choice" (e.g. telemetry) has no value of
  its own and is recorded as `design-weakness`; the rubric (D12) says it must not be counted as a vulnerability.

## 5. Open questions and suggested follow-ups

1. Rules vs taxonomy coverage: no rule targets T12, T13, T16, T17, T18, T19; T05 and T10 have one or two
   partial rules. Candidate new rules (not written): sandbox disabled or permissive fallback (T17); harness
   service bound to a non-loopback address or with auth disabled in config (T18); unpinned or unsigned
   plugin/skill sources (T05); project-supplied extension directories (T02/T05). Existing rule `taxonomy:`
   lists were not modified.
2. D16 needs a fact-collection pass over the 58 `matrix/evidence/*.json` files before it can be scored.
3. Decide whether Phase 3+ keeps `kind` at five values or adds `policy-choice`.
4. Decide whether to remap OWASP LLM to the 2026 edition once its text is readable; the 2025 ids are
   stable in `harness-threats.yaml` but a 2026 column would be a small addition.
5. Run a second-rater check on a random 15% sample of `incident-classification.csv` using only the
   ordered rules in `harness-threats.yaml` and `root-causes.yaml`, and report Cohen's kappa; I applied
   the rules alone, so agreement has not been measured.
6. Dedupe `incidents.csv` (99 cross-referenced rows) before counting.
