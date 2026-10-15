# E1 notes (rater 1, 2026-10-15)

Inputs: `matrix/evidence/*.json` (58 harnesses), `matrix/rubric.yaml`, rater-1 decisions in
`matrix/scores_rater1.yaml`. Outputs come from `experiments/e1_matrix.py`; every number below is in
`experiments/results/e1_matrix.json`.

## Coverage

- 58 harnesses (36 tier A/B, 22 tier C), the same set as `rules/harness_profiles/`.
- 870 D01-D15 cells: 664 scored, 206 N/A. Every N/A has a reason. "N/A (not documented ...)" means
  the evidence file has no citable fact for the dimension. A dimension whose only facts are
  `unverified` or `third-party-report` counts as not documented.
- Five tier-C entries have fewer than 8 scored dimensions and get no mean ("insufficient evidence"):
  google-adk, langgraph, manus, openai-agentkit, strands-agents.
- D16 (proposed): 10 cells, scored only where an evidence file describes a listening service in
  another dimension's facts, so every D16 citation is a cross-dimension one. D16 is excluded from all
  means.
- Rater 1 agreed with the agents' `proposed_score` on 560 of 870 cells. It scored lower on 206 and
  higher on 25. It gave N/A where the agent proposed a score on 41 cells, and scored 38 cells the
  agent had left at N/A.

## Open question: Claude Code D01 under the `auto` default

Facts (claude-code D01 #3, from-official-docs): on 2.1.300, interactive sessions start in `auto`
(from 2.1.283). `claude -p` and the Agent SDK also start in `auto` (from 2.1.285) when feature flags
are not fetched; with flags fetched they start in Manual. In `auto` a server-side classifier approves
tool calls, and the user is not asked.

Decision: **D01 = 1** (B1's correction stands).

- The score-2 criterion says "Default mode **asks** before shell commands and edits outside a safe
  set". A classifier verdict is not a question to the user, so this criterion is not met.
- The score-1 criterion lists "default mode runs shell or writes without asking". That describes
  `auto`.
- Rubric rule 3 picks the highest score whose criteria are all met. So the strong score-3 controls
  do not lift the cell: deny rules apply in every mode, `auto`/`bypassPermissions` are ignored in
  project settings, and managed `disableBypassPermissionsMode`/`disableAutoMode` exist.
- The same reading was applied to every harness whose default is a model-based approver. That covers
  Cursor (Auto-review), Qwen Code (AUTO), Hermes Agent (`smart`), Raven (`smart`), Microsoft Agent
  Framework (harness heuristic auto-approval), and the Claude Agent SDK (start mode "can be auto").
  All are D01 = 1.
- Sensitivity: if a classifier-gated default counted as "asking", Claude Code D01 would be 3 and its
  mean would go from 1.60 to 1.73. It would stay second in tier A/B, behind Codex CLI (1.79).
- Recommendation for the rubric owner: add an explicit clause for classifier/LLM-approved defaults.
  One option is "counts as asking only if the classifier's denials fall back to a user prompt and the
  classifier cannot approve writes outside the workspace". Rater 2 should be told which reading to
  use; otherwise D01 disagreements will be about the rubric, not the evidence.

## Interpretations applied consistently (candidates for rubric clarification)

1. **Repo-controlled approvals (D01).** "Approve-everything can be switched on from repository-controlled
   files" was counted even behind a trust prompt. Examples are repo hooks returning `auto_approve`
   (Antigravity, Crush), repo MCP `autoApprove ['*']` (Kiro, Roo Code), and trusted project settings
   that set a bypass mode (Qoder). Where the evidence does not show whether project config can set
   the approval mode, the cell was scored as not shown (rule 4), as for Codex CLI.
2. **D07 score 2 needs all three clauses**: keychain or 0600 file, *documented log retention*, and
   read-deny or redaction. Many harnesses with a keychain or a 0600 file stay at 1 because no
   retention is documented.
3. **D08 score 2 needs an official CI action/recipe** that documents permissions and actor checks.
   Harnesses with safe headless defaults but no official CI integration stay at 1. Harnesses whose
   headless mode auto-approves with no guidance get 0.
4. **D12 "or retention is undocumented"** applies even to opt-in telemetry (aider, goose, TrueForge
   score 1). Libraries with no vendor telemetry are N/A, per the rubric. Hosted services' content
   storage was treated as the service function, not as "mandatory collection". Training-by-default
   with an opt-out on some plans is 1.
5. **D09** covers only agent-written or replayed memory. User-authored instruction files (AGENTS.md,
   rules) do not count, and harnesses with only those are N/A (feature absent).
6. **D15 score 2 needs a documented policy.** Published GHSAs/CVEs with no documented policy or
   contact were scored 1, not 0, because the advisories show a working channel (Bedrock AgentCore,
   Claude Agent SDK, Deep Agents, ADK, LangGraph, LangGraph Platform, Vertex). Score 3 needs a bounty
   or safe harbour in the facts.
7. **D04 score 2, headless clause**: read as "either documented behaviour is acceptable at 2".
   Missing headless documentation does not block 2, but it does block 3.
8. **Tier-C ladders** were read as alternative descriptors (highest matching rung), not as nested
   criteria. A documented unsafe default or gap lowers a managed-runtime rung by one. Examples:
   Claude Managed Agents and Bedrock AgentCore D03 = 2.
9. **Third-party reports only lowered scores.** Examples: Copilot Studio D11, OpenClaw D06, Vertex D07,
   TRAE D12, Bedrock D03. Patched bypasses (CVEs with fixed versions) were recorded in the rationale
   and did not change scores (rubric rule 7).
10. **Citations**: a score must cite at least one from-official-docs or verified-by-test fact, and the
    script refuses citations of unverified facts. Facts from another dimension of the same file are
    cited as `Dxx.i`. Tier-C and docs-only harnesses never cite `verified-by-test`: those facts are
    cited as from-official-docs, because they were source or API reads (ASSUMPTIONS A09).
11. **D14 for open-source tools with no enterprise offering** is 0 only where a fact documents the
    absence of an admin layer (Crush, DeepSeek Harness, Kimi CLI). Otherwise it is N/A, not
    assumed.
12. **D14 score 3 requires "documented and verified"**, so docs-only harnesses cap at 2.

## Ranking caveats

- The rubric guardrail allows ranking claims only where the order holds under equal,
  exposure-weighted and security-core weightings. Codex CLI is in the A/B top 3 under all three.
  Aider and Continue are in the A/B bottom 3 under all three (`top_in_all_weightings` /
  `bottom_in_all_weightings` in the JSON). The other top/bottom positions are not stable.
- Ties are broken alphabetically. Claude Managed Agents and Copilot Studio tie at 1.67 in tier C.
- Means with 8-10 scored dimensions (for example Replit Agent and TRAE with n=8) are fragile.

## Inter-rater check

`matrix/scores_rater2.yaml` was not read. When it exists (same schema), `e1_matrix.py` writes
`experiments/results/e1_agreement.json`. That file holds quadratic-weighted Cohen's kappa on cells
both raters scored, exact and within-one agreement, N/A-vs-score mismatches, and a disagreement list.
