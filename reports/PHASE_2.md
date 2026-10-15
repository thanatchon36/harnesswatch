# Phase 2 — Threat model (RQ1) and scorecard rubric (RQ2)

Date: 2026-10-15 · Spend: $0.00

## Done
- `taxonomy/harness-threats.yaml` has 19 classes:
  - T01–T16 keep their MISSION ids and meaning (T04 and T13 narrowed, T02 widened).
  - New: T17 sandbox/isolation escape, T18 agent control-plane exposure and authorization, T19 conventional software defects in runtimes and SDKs.
  - Each class carries STRIDE, MITRE ATLAS, OWASP LLM 2025, OWASP Agentic (ASI01–10) and OWASP MCP Top 10 (beta, flagged) ids, plus the mitigating controls (D-dimensions) and HG rules.
  - A 16-step ordered rule assigns exactly one primary class per incident.
- `taxonomy/root-causes.yaml` has RC1–RC12, assigned by a 12-question ordered procedure. New causes: RC10 conventional defect, RC11 autonomy beyond intent, RC12 adversarial use.
- `taxonomy/incident-classification.csv` re-classifies all 328 Phase-1 incidents. Changes from the agents' drafts: root cause on 97, taxonomy class on 128.
  The 30 Phase-1b incidents carry their agents' classes and get re-checked by the same procedure in E1/RQ3.
- `taxonomy/mappings.yaml` covers:
  - ATLAS 2026.09; OWASP LLM 2025; OWASP Agentic 2026 (2025-12-09); OWASP MCP Top 10 (beta);
  - NIST AI RMF 1.0 and AI 600-1; ISO/IEC 42001 Annex A;
  - the MAS AI Risk Management Guidelines (final, 2026-10-07), using airmkit `AIRM-*` ids (MISSION §13).
- `taxonomy/attack-trees.md`: 7 Mermaid attack trees (README injection → exfil, repo config → RCE, MCP poisoning,
  pwn-request CI, memory poisoning, sub-agent propagation, supply-chain installer).
- `matrix/rubric.yaml` / `rubric.md`:
  - D01–D15, each scored 0–3 with criteria decidable from `matrix/evidence/*.json` fact labels;
  - unverified facts are ignored, and third-party reports can only lower a score;
  - unweighted mean;
  - proposed D16 (local service / control-plane exposure), because T18 is about 10% of incidents.

## Phase 2b — black-box scope delta (A14)
- RQ7 adds a claims-vs-observed view rather than a new threat class. Its dimensions are telemetry_hosts, update_check,
  config_trust, hooks_trust, mcp_trust, sandbox, secret_storage, permission_default, state_dir_perms, web_fetch,
  browser, memory and subagents. They map onto existing D-dimensions (D03 config trust, D06 secrets, D08 telemetry,
  D09 updates, D02 sandbox).
- Tier labels A, A/B, B, C and D come from the profiles' `tier` field. The rubric applies the same way to every tier.
  A Tier-C cell can only use `from-official-docs` or `third-party-report` facts, so it can never be backed by a
  `verified-by-test` fact.

## Skipped / not verified
- **OWASP LLM Top 10 2026:** the entries could not be confirmed against a primary source. They are kept out of the
  mappings used by the paper; the 2025 list is used instead.
- **ISO/IEC 42001 Annex A:** the text is paywalled. Clause titles come from public summaries and are labelled `third-party-report`.
- **NIST AI 600-1:** most section numbers are unverified, so the mapping cites document-level only.
- **Attack-tree rendering:** the trees are Mermaid source; Phase 6 renders them to SVG for the paper.

## Open questions
- The Phase-1b incidents need the same ordered classification procedure; this is done in E1/RQ3 scripting.
- D16 has no evidence yet. It is scored only where the evidence JSON has facts, otherwise N/A.
