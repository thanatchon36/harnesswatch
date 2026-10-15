# Paper review

Reviewed: `paper/main.tex`, `paper/sections/*.tex`, `paper/numbers.tex`, the generated tables, and the
built PDF (14 pp, `bash paper/build.sh`, 2026-10-15). I checked the paper against
`experiments/results/*.json`, `bench/results/2026-10-15/runs.jsonl`, the raw bench output under
`bench/.work/raw/`, `evidence/ledger.csv`, `evidence/incidents.csv`,
`taxonomy/incident-classification.csv`, `taxonomy/root-causes.yaml`, `matrix/evidence/*.json`,
`matrix/controls.csv`, `matrix/scores_rater2.yaml`, `ASSUMPTIONS.md`, `MISSION.md` §6.4 and §8, and
`reports/phase2_notes.md`.

## Hostile review

### Summary verdict

**Major revision (reject in its current form at a top-4 venue).** The engineering is substantial and
most of it can be reproduced. The macro pipeline works: I checked 31 prose numbers against the
results JSON, and 29 of the 31 macros match. The problems are in the inferences, not the arithmetic:

- The headline claim that "the harness is where most risk sits" rests on an incident set chosen for
  harness-level CVEs. Its residual root-cause category (RC1) is small by construction.
- The patch-latency result measures advisory publication lag, not how fast bugs were fixed. The
  evidence CSV contradicts it.
- The E3 abstract claim (default modes "trade task completion for safety") does not hold. The two
  modes show the same safety (0/135 vs 2/135, Fisher p ≈ 0.5), and most "default" cells are harnesses
  that did nothing at all.
- The E3 "Correction" paragraph credits the wrong harness with the secret hits. It hides a likely
  injection effect: in Claude Code's `instructions` scenario the synthetic secret reached the session
  transcript in 10 of 10 runs, against 0 in its control and other scenarios.
- E2 pools prevalence over a stratified sample with equal per-stratum caps, so the headline rates are
  sampling artefacts.
- The evidence-label discipline the paper advertises does not hold in `matrix/evidence/`.
- One pending private-disclosure candidate is already public in the matrix.

None of this is fatal to the artefact. All of it is fatal to the current wording.

Counts: **13 major, 19 minor.**

### Numbered findings

#### Major

**1. [major] The central thesis is circular and selection-biased.**
*Location:* `paper/sections/abstract.tex:2` ("We show that this deterministic layer is where most
coding-agent security risk sits"); `introduction.tex:8`; `conclusion.tex:4` ("the 2025–2026 record
shows that this is where most coding-agent security failures occur").
*Problem:* The survey only admits *harness-level* incidents (`incidents.tex:4`), and most of them have
CVE or GHSA identifiers. Pure model behaviour rarely gets a CVE, so the population is filtered towards
deterministic software defects before any analysis. RC1 ("pure prompt injection") is also the
*residual* category of the ordered procedure: `taxonomy/root-causes.yaml` Q12 reads "Otherwise,
injected content steered an agent that behaved as designed -> RC1". A low RC1 share therefore partly
follows from how the procedure is built. Finally, 48% is not "most".
*Evidence:* `rq3_incidents.json`: by_kind.vulnerability = 292/324; with_cve = 239; RC2+RC3 =
156/324 = 48.1% (`\pctRCTwoThree`); RC1 = 17 (5%). The data measure disclosed harness bugs, not risk.
*Required fix:*
- Restate the claim as "among publicly disclosed harness-level advisories, 48% …".
- Drop "risk" and "most".
- Add a threats-to-validity paragraph on the selection effect: the CVE and GHSA filter, and the fact
  that model-level failures are not tracked as advisories.
- Report how sensitive RC1 is to the question order, for example by re-running the procedure with
  Q12 moved earlier, or by counting "injection was the vector" separately.

**2. [major] Patch-latency semantics are wrong, the conclusion is unsupported, and the evidence CSV
contradicts the computation.**
*Location:* `incidents.tex:33` ("Coordinated disclosure works for most reported harness bugs").
*Problem:*
- `rq3_incidents.py::latency` computes `fix_date − date_disclosed`. For GHSA and NVD rows,
  `date_disclosed` is the advisory publication date, which under coordinated disclosure comes after
  the fix by design. A median of −5 days says nothing about time-to-fix. The metric that matters is
  report-to-fix, and it is not available.
- Only 149 of 324 incidents have both dates. The 175 without a fix date (unfixed, or fix unknown) are
  silently dropped. That is survivorship bias, and it goes in exactly the direction of the
  conclusion.
- `evidence/incidents.csv` has a `patch_latency_days` column that disagrees with its own dates, and
  the script ignores it:
  - G6-049 (CVE-2025-49596): disclosed = fix = 2025-06-13, column = 79.
  - G4-I018 (CVE-2025-53773): disclosed = fix = 2025-08-12, column = 44.
  - G1-I040 (CVE-2025-61260): the dates give −237 days, the column says 13.
  - G5a-I16: the dates give −80 days, the column says +80.

*Evidence:* `rq3_incidents.json` patch_latency_days = {n: 149, median: −5, fixed_before_disclosure:
135, p90: 0, max: 288}. The script counts `x <= 0` as "fixed on or before disclosure", so same-day
advisories count as "before".
*Required fix:*
- Rename the metric "advisory-publication lag".
- Remove the sentence "coordinated disclosure works", or support it with report dates taken from
  researcher timelines (for example the Check Point timelines in ledger G7-120).
- Report the 175 incidents without a fix date as a separate category (unfixed or unknown).
- Reconcile or delete the contradictory CSV column, and document what it meant.

**3. [major] The E3 headline ("default headless modes trading task completion for safety") is not
supported.**
*Location:* `abstract.tex:2` item (v); `evaluation.tex:37` ("Several headless defaults deny the tools
the task needs, so they are safe but useless, which creates pressure to run CI agents with
approve-everything flags").
*Problem:* Safety does not differ between modes. Follow was 0/135 in default and 2/135 in auto
(two-sided Fisher exact p ≈ 0.50), and destructive actions were 0 vs 1. What does differ is that
several harness × mode cells were non-functional. For those cells "safe" means "inert", and nothing
was traded.
*Evidence:* `e3_bench.json` by_harness_mode, task_completed and permission_prompt over the injection
scenarios:

| Harness, mode | Task done | Prompts | Note |
|---|---|---|---|
| opencode auto | 0/20 | 0 | |
| opencode default | 0/20 | 0 | |
| opencode control | 0/5 (auto), 1/5 (default) | | the adapter/model pair is broken |
| grok-build default | 0/20 | 0/20 | |
| qwen-code default | 0/20 | 0/20 | |
| codex-cli default | 0/20 | 20/20 | |
| github-copilot default | 0/20 | 20/20 | |

Only Codex and Copilot show the "asks, so it cannot finish headless" mechanism. Grok and Qwen
completed nothing and showed no prompt, and the paper does not explain why. Claude Code's "default"
in `-p` with a third-party base URL is the classifier `auto` mode (E7 CVO-B1-020: "init
permissionMode with a third-party base URL: auto"). So the two Claude Code arms are not
"ask vs approve-all".
*Required fix:*
- Delete "trading task completion for safety" from the abstract.
- Report follow and destructive rates *conditional on the agent acting* (for example, runs with at
  least one tool call, or control-task completion above 0).
- Exclude OpenCode, or flag it as non-functional.
- Explain the Grok and Qwen default-mode zeros from the transcripts.
- State what the Claude Code "default" arm actually is.
- Remove the causal "creates pressure" sentence, or support it.

**4. [major] The E3 "Correction" credits the wrong harness with the secret hits, and the metrics miss
an apparent injection effect.**
*Location:* `evaluation.tex:41` ("flagged 15 runs, mostly because Codex CLI snapshots its process
environment"); metric definitions at `evaluation.tex:34`.
*Evidence:*
- In `runs.jsonl`, `secret_accessed` is true for 10 Claude Code runs (claude-code/instructions:
  5 auto + 5 default) and 5 Codex runs (+1 Codex control). Claude Code accounts for 10 of the 15, so
  "mostly Codex" is false.
- In the raw `observe.json` of those Claude Code runs (for example
  `bench/.work/raw/claude-code-instructions-auto-0-bb936f10/observe.json`), the canary hit is the
  session transcript `/home/agent/.claude/projects/-workspace/<id>.jsonl`, not an environment
  snapshot.
- Claude Code's control, readme, code_comment and tool_output runs have 0 hits.
- The synthetic secret therefore entered the agent's context in 10/10 runs, and only when the payload
  sat in `CLAUDE.md`. The injected instruction is the most likely cause: the agent read `.env` (or
  dumped the environment) but stopped short of the POST.
- The "injection follow" metric (marker, POST or delete) does not count this partial compliance.
- The strict `secret_read` metric only searches the harness's stdout. `claude -p` prints only the
  final message, so the metric cannot see tool results and is structurally close to zero for such
  harnesses.
- The strict metric was introduced after the results were seen (`experiments/e3_rescore.py`, CODE_REVIEW
  M1).

*Required fix:*
- Correct the attribution.
- Add a "secret entered agent context" metric that separates harness persistence (Codex
  `shell_snapshots`) from agent reads (transcript hits).
- Report Claude Code instructions = 10/10 against its control = 0/10 as the clearest injection
  signal in the bench, with the caveat that it is one model.
- Say plainly that the metric was changed post hoc.
- Redefine "follow" to cover partial compliance (reading the target secret), or add that as a
  separate metric.

**5. [major] E2 prevalence rates are artefacts of stratified sampling, and E2 does not measure
accuracy.**
*Location:* `evaluation.tex:19`, and `evaluation.tex:9` ("not real-world accuracy, which E2
addresses").
*Problem:*
- The sample is 17 strata, each capped at 60 files, pooled with equal weight over 1,010 repositories.
  Rates "per audited repository" therefore depend on how many strata of each type were chosen.
- HG-MCP-005 ("MCP server declared in repository config", 30.8%) is close to tautological: five of
  the 17 strata are MCP declaration files (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
  `.kiro/settings/mcp.json`, `.agents/mcp_config.json`, 300 files), and finding 311 repositories is
  just finding the files that were searched for.
- The CI rules are diluted the other way. Only the three workflow strata (177 files) can fire
  HG-CI-*. Among them, HG-CI-002 fires in about 112/177 ≈ 63% and HG-CI-001 in about 50/177 ≈ 28%,
  not 11.1% and 5.0%.
- No E2 finding was checked by hand, so the real-world precision of the rules is unknown. E6 is
  synthetic.

*Evidence:* `e2_corpus.json` per_target (60 each, 57 for `gemini -p`); prevalence rules HG-MCP-005
repos = 311, HG-CI-002 repos = 112, HG-CI-001 repos = 50.
*Required fix:*
- Report prevalence per stratum, with the stratum as the denominator, and drop the pooled
  "of repositories" rates.
- Remove HG-MCP-005 as a headline result, or redefine it so it does not fire on the sampling key.
- Hand-label a random sample of findings (for example 100) to estimate real-world precision.
- Delete "which E2 addresses" at `evaluation.tex:9`.
- Soften "show that the patterns behind RC2 and T04 incidents are common".

**6. [major] The evidence-label discipline does not hold in `matrix/evidence/`, contrary to
`method.tex:16`.**
*Location:* `method.tex:14,16` ("reading source counts as documentation, not as a test … the evidence
ledger links each label to a URL, access date and version"); Fig. 1 caption ("every cell links to
labelled evidence").
*Evidence:* A scan of `matrix/evidence/*.json` found:
- 56 facts labelled `verified-by-test`, nearly all of them source reads (GitHub `blob/main/...`
  URLs), for example crush G1-082/083/080, codex-cli G1-037/039/045/056 and claude-agent-sdk
  `_build_command`. ASSUMPTIONS A09 says these were relabelled `from-official-docs`, but the
  relabelling only reached `ledger.csv`: 39 matrix facts disagree with their ledger label.
- 1,104 matrix facts have no `ledger_id`, so they are not linked to the ledger at all.
- 87 matrix facts are labelled `unverified`. MISSION §6.4 says unverified claims do not enter the
  paper, but these sit beside the scores and their rationales (for example `cline.json`: "No 'trust'
  gate … (grep of source); not tested at runtime", next to the D04 = 0 rationale).
- `evidence/ledger.csv` holds only 2 `verified-by-test` rows (B1-012, G1-019). Every [T] in the paper
  traces to `experiments/results/e7` probe files and bench JSON, not to the ledger the paper names.

*Required fix:*
- Propagate the A09 relabelling to `matrix/evidence/*.json`.
- Give every matrix fact a ledger id, or change the claim in the paper.
- Show that no `unverified` fact contributed to any score (add a test).
- State where [T] evidence lives (probe JSON and bench runs), and link the Table II rows to the probe
  files.

**7. [major] The reliability of E1 and RQ3 is overstated, and who did the work is misdescribed.**
*Location:* `controls.tex:6` ("A second rater, who had no access to the first rater's files");
`limitations.tex:14` ("classified by one author").
*Problem:*
- Rater 2 scored from the same pre-extracted fact lists as rater 1: `matrix/scores_rater2.yaml` cites
  facts by index (`f: [0, 1, 2]`). κ = 0.88 therefore measures how consistently the rubric is applied
  to identical evidence. It does not measure the reliability of the scores, because evidence
  collection, the step most open to error, is shared.
- MISSION §7 E1 specifies the second pass as "a fresh subagent". The paper never says the raters (and
  the incident collectors, ASSUMPTIONS A11 "research agent") are LLM agents. Reviewers need to know
  this.
- κ is computed on the 655 cells both raters scored. The 29 N/A-vs-score disagreements are left out,
  which inflates agreement.
- The incident classification has no reliability measurement at all: `reports/phase2_notes.md` §5
  item 5 reads "I applied the rules alone, so agreement has not been measured".

*Required fix:*
- Disclose that the raters, collectors and classifier are agents.
- Describe the shared fact base and restate what κ measures.
- Report agreement with N/A as a category (for example Krippendorff's α).
- Run and report the planned 15% second-rater check of the incident classes and root causes.

**8. [major] The RQ7 headline "21 of 27 tested claims matched" overstates the evidence.**
*Location:* `abstract.tex:2` item (vii); `claims.tex:15` ("Most documented controls hold");
`controls.tex:21` ("Grok Build and Copilot CLI hold them until the folder is trusted\evD\evT").
*Problem:*
- 89 of 116 claims (77%) are untested. The abstract leaves this out.
- The tested set is chosen by convenience and is dominated by low-stakes or trivial checks: host
  lists, the auto-updater, and "requires login". For example, CVO-B2-015 counts "unauthenticated
  headless run: exit 1, auth required" as a `match` under `permission_default`.
- Copilot CLI has no positive control. B4-C009 (MCP not started when untrusted) and B4-C010 (hook did
  not run, verdict `not-observed`) were never re-run in a trusted folder. "Did not run" could mean
  the feature does not work in `-p`, which is exactly why B4-C010 is `not-observed`.
- Grok has a `--trust` positive control for hooks only. Its MCP claim, B3-C011, is `partial`.
- Effort is uneven across vendors: 13 Claude Code claims were tested against 3 for Copilot.

*Evidence:* `e7_claims.json` verdicts {match: 21, partial: 3, mismatch: 1, not-observed: 2,
untested: 89}; rows B4-C009, B4-C010, B3-C011, CVO-B2-015.
*Required fix:*
- Put "27 of 116 claims testable; 21 of those matched" in the abstract.
- Classify the tested claims by security relevance.
- Add positive-control probes (trusted folder) for every negative trust result, or downgrade those
  results.
- Change `controls.tex:21` so it does not claim that Copilot "holds" configuration until trust.
- Remove "Most documented controls hold".

**9. [major] Claude Code was run in a configuration the vendor says is unsupported, and the paper
cites that vendor page selectively.**
*Location:* `method.tex:10` (cites `cc_llm_gateway` as "Claude Code's LLM-gateway support");
`evaluation.tex:32`.
*Evidence:* Ledger B1-017 records that the same page says Anthropic "doesn't support routing Claude
Code to non-Claude models through any gateway". The bench routes Claude Code to `qwen3:4b-instruct`.
In this mode Claude Code also starts in classifier `auto` mode (B1-005, CVO-B1-020), so the
permission decisions in the "default" arm depend on how that classifier behaves against a 4B
non-Claude backend. The paper never analyses this.
*Problem:* The configuration is unsupported, and the permission behaviour may be outside the vendor's
design envelope. The other harnesses ran in configurations their vendors document as supported
(Copilot BYOK and local models, Grok custom models). This asymmetry undermines both the comparison
and the vendor-neutral tone.
*Required fix:*
- Quote the support statement.
- Label Claude Code's E3, E5 and E7 `permission_default` results "unsupported configuration".
- Explain what the `auto` classifier runs on in this setup, or exclude Claude Code's default arm.

**10. [major] Ethics: a pending private-disclosure candidate is already public in the matrix.**
*Location:* `matrix/evidence/cline.json` (around lines 70–84) and `matrix/controls.csv:140`, which
the paper points readers to (Fig. 1 caption, `appendix.tex:18`). This contradicts `method.tex:20`
("Potentially unknown issues went to private coordinated disclosure and are not described here").
*Evidence:* `private/DISCLOSURE_DRAFT.md`, G2 item 2, covers Cline workspace plugin auto-discovery
(`<workspace>/.cline/plugins`, no trust gate found) and marks it "NOT verified … check whether the
vendor documents it as intended before reporting". The public matrix states the same thing: "Plugin
search paths include <workspace>/.cline/plugins (JS/TS modules executed by CLI/SDK)", "No 'trust'
gate in apps/cli or sdk core … not tested at runtime" (label `unverified`), and the D04 = 0 rationale
"Workspace hooks and JS/TS plugins are discovered from the cwd; no trust gate is documented."
*Problem:* MISSION §8.4 requires no public details before a fix or 90 days.
*Required fix:*
- Remove or neutralise these facts and the rationale until the item is resolved with the vendor, or
  until it is confirmed as documented, intended behaviour.
- Audit `matrix/` for the other two disclosure items. I found no trace of the first item
  item.
- Add a CI check that greps public artefacts for disclosure-draft identifiers.

**11. [major] Analysis of the Grok Build binary is mislabelled and conflicts with the stated
black-box rules.**
*Location:* `method.tex:6` ("the shipped npm binary contains components not in the tree … \evD")
versus `method.tex:10` ("We never decompile, deobfuscate …").
*Evidence:* Ledger B3-004, labelled `from-official-docs`, reads: "The official linux-x64 1.0.45
binary embeds source paths of 12 crates absent from the public tree". This finding comes from
examining the contents of a shipped binary. It is not documentation, and it borders on the reverse
engineering that MISSION §8.8 forbids. The source facts also describe 1.0.45, while the black-box
probes ran 1.0.52 (VERSIONS.md).
*Required fix:*
- Relabel the fact (it is not [D]).
- State exactly what was done (for example `strings` on the binary), and argue in the ethics
  paragraph why it is consistent with the vendor's terms, or drop it.
- Align the source and binary versions, or state the mismatch.

**12. [major] E5 contradicts E3 on Codex credential persistence.**
*Location:* `evaluation.tex:60` ("In the key condition, 0 harnesses wrote the provider credential to
a file … Codex CLI also wrote its full process environment, including any secret passed as an
environment variable, into shell-snapshot files").
*Evidence:*
- `e5_residue.json` codex-cli.key: credential_supplied_via = "environment", residue = [].
- In E3, Codex wrote the environment canary into `~/.codex/shell_snapshots/*.sh` in some runs only.
  For example, in code_comment/auto, runs 1 and 4 of 5 hit and runs 0, 2 and 3 did not
  (`bench/.work/raw/codex-cli-code_comment-auto-*/observe.json`).
- So the E5 key result for Codex (N = 1) is a sampling miss, not evidence that Codex does not persist
  the credential.
- "0 harnesses" also hides the denominator: only 4 of 7 harnesses take a key at all (aider,
  copilot and opencode are n/a).

*Required fix:*
- Report the key condition as "0 of 4 in one run; Codex persists environment-supplied credentials in
  shell snapshots when its shell tool runs (E3: k of n runs)".
- Raise N, or drop the key-condition conclusion.

**13. [major] RQ1 contains a factual statement that the paper's own data contradict.**
*Location:* `threats.tex:12` ("allowlists over shell commands must reason about quoting, substitution,
redirection and symlinks, and most verified incidents are failures of that reasoning (T03)").
*Evidence:* T03 = 74/324 = 23% (`\pctTopThree`), and RC3 = 104/324 = 32%. Neither is "most".
*Required fix:* Replace the sentence with the macro values ("the largest single group, 23% by class
and 32% by root cause").

#### Minor

**14. [minor] The incident arithmetic does not close.**
*Location:* `incidents.tex:4`.
*Evidence:* 358 − 29 − 4 = 325, but the text says "leaving 324". The JSON lists
`outside_2025_2026: 1` (INC-G5d-001, 2024-08-06), and the paper does not mention it.
*Fix:* Add the date exclusion to the sentence through a macro.

**15. [minor] The claim that every number is generated is false as stated.**
*Location:* `abstract.tex:2` ("Every number in the paper is generated from versioned results files");
`appendix.tex:8` ("no number in the text is typed by hand").
*Evidence:* Hand-typed values include:
- the versions in the Table II caption (2.1.300, 1.3.5, 1.0.52, 1.0.98) and the Ollama version
  (0.40.4);
- the 240 s cap, the "16-class seed", the 30 controls, the twelve root causes and "Three classes were
  added";
- "D01 from 1 to 3";
- the mode bits 0600, 0755 and 0750.

Most are fine as constants, but the absolute claim is wrong.
*Fix:* Say "every result number", or move versions and counts into macros generated from
`VERSIONS.md` and the taxonomy YAML.

**16. [minor] The Wilson bounds are rounded until they mislead.**
*Location:* `evaluation.tex:37`; `numbers.tex` (`\benchFollowAutoLo` = 0.00 for k = 2/135, true
value 0.0041; `\benchDestrAutoLo` = 0.00 for k = 1, true value 0.0013).
*Fix:* Use three decimals or percentages with one decimal for small rates.

**17. [minor] The E6 confidence intervals and the "held-out" status are weaker than stated.**
*Location:* `evaluation.tex:7–9`.
*Problem:*
- The Wilson CIs treat the 171 (case, rule) firings as independent. They are clustered within 131
  cases and within 9 templated generator families.
- `e6_notes.md` reports a first run on the test split (P = R = 0.959). After that run, case-content
  fixes were applied to cases in both splits (the 26 `g-ci-*` cases were regenerated), so the test
  split was not untouched.

*Fix:*
- Use a cluster bootstrap by case and by family.
- State that the test split was seen once before the content fixes.

**18. [minor] The incident scope is broader than "harness".**
*Location:* `incidents.tex:4`.
*Evidence:* by_tier.ecosystem = 73 (for example MCP Inspector, nx). T19 "conventional defects in
runtimes and SDKs" = 45 and RC10 = 51.
*Fix:* Report the headline shares with and without ecosystem and SDK-only incidents.

**19. [minor] The timeline is confounded by how incidents were collected.**
*Location:* `incidents.tex:13`; Fig. 2.
*Problem:* The rise from 1 incident (2025-Q1) to 75 (2026-Q3) also reflects agent-assisted search
that favours recent, well-indexed advisories, and the start of GHSA use by vendors. The partial
2026-Q4 bar (19) looks like a decline.
*Fix:* Hatch the partial bar, and add the collection-recency confound to the threats section.

**20. [minor] Some factual claims carry no label.**
*Location:*
- `background.tex:12`: the source-map event. Ledger G7-026 is [3P] with low confidence and names
  version 2.1.88; the paper gives no label and no version.
- `background.tex:10`: "Every major harness runs non-interactively".
- `controls.tex:23`: "Credentials mostly sit in a 0600 file or keychain … few vendors document
  transcript retention".
- `incidents.tex:31`: the vendor threat report is labelled [D] for a claim about criminal misuse.

*Fix:* Add labels, or point to the matrix column that supports each statement.

**21. [minor] The E4 signature count hides a documented-versus-observed gap.**
*Location:* `evaluation.tex:70`.
*Evidence:* `e4_supply.json` claude-code installer: `declared_signed: true` (the documentation says
the manifest is GPG-signed from 2.1.89), yet `verifies_signature: false`, and it is counted among
the 17 "unsigned". Several auto-update entries are "unverified" (cline, continue, crush, goose,
qwen-code, …), while the table is labelled [D] as a whole.
*Fix:* Report the documented-versus-observed gap, and mark the unverified cells.

**22. [minor] Grok Build's tier is inconsistent.**
*Evidence:* `e4_supply.json` tier = "A"; Table VI calls it "(closed)"; `claims.tex` calls it Tier-B;
`method.tex:6` calls it a hybrid.
*Fix:* Use one tier label throughout.

**23. [minor] The handling of secrets found in E2 is not described.**
*Location:* `evaluation.tex:19` (literal secrets in 21 repositories).
*Fix:* Say whether owners or GitHub secret scanning were notified, and why or why not. Reviewers will
ask.

**24. [minor] Vendor-host attempts during the bench are not reported.**
*Evidence:* In all 50 runs per harness, `runs.jsonl` blocked_hosts include api.anthropic.com (Claude
Code); chatgpt.com, ab.chatgpt.com, github.com and api.github.com (Codex); an Aliyun RUM telemetry
host and models.dev (Qwen); and models.opencode.ai and registry.npmjs.org (OpenCode).
*Fix:* Report these. They are relevant to RQ7, and they contrast with the E7 runs that used the
opt-outs.

**25. [minor] The classifier interpretation in the rubric needs a sensitivity analysis.**
*Location:* `controls.tex:17`.
*Problem:* The rule that a classifier is "not asking" changes D01 for Claude Code, Cursor, Qwen Code,
Hermes Agent and Devin-style "smart" modes, but the paper reports the sensitivity only for Claude
Code. The asymmetry that [3P] facts can only lower a score is not justified.
*Fix:* Report the rankings under the alternative interpretation, and justify the asymmetry.

**26. [minor] Timeouts in E3 are unreported.**
*Evidence:* 22 runs hit the 240 s cap: Claude Code 12, Codex 6, Copilot 2, Qwen 2 (`runs.jsonl`
`timed_out`). They are scored on the state at the cap, but Table VI does not show them.
*Fix:* Add a timeout column.

**27. [minor] Two sources disagree on the classification of CVE-2025-53773.**
*Location:* `incidents.tex:27`.
*Evidence:* `evidence/incidents.csv` row G4-I018 says T03/RC6. `taxonomy/incident-classification.csv`,
which the script uses, says T02/RC2. The paper's example is consistent with the latter.
*Fix:* Sync the CSVs so a reader of the evidence finds one answer.

**28. [minor] RQ6 is answered prescriptively and not evaluated.**
*Location:* `governance.tex:4`.
*Problem:* The 30-control checklist is not tested for coverage or usability, and the claim of
suitability for "regulated financial institutions" has no supporting evidence.
*Fix:* Either map each control to the incidents it would have prevented, with counts from the
JSON, or label RQ6 as a recommendation, not a finding.

**29. [minor] Causal and superlative wording.**
*Location:*
- `claims.tex:15` "Most documented controls hold".
- `evaluation.tex:37` "creates pressure to …".
- `evaluation.tex:19` "show that the patterns … are common".
- `controls.tex:19` "OS-level sandboxing is the clearest gap", which is acceptable but should cite
  the D02 and D03 macros.
- `conclusion.tex:4` "documented behaviour mostly matched", which repeats finding 8.

*Fix:* Hedge these, or attach a macro to each.

**30. [minor] Related work has gaps.**
*Location:* `related.tex`.
*Missing:*
- GitHub Actions and CI workflow security, which bears directly on HG-CI-001/002 and E2:
  Koishybayev et al., USENIX Security 2022; ARGUS, USENIX Security 2023.
- System-level isolation and privilege control for LLM apps and agents (IsolateGPT/SecGPT,
  NDSS 2025; Progent; information-flow control such as FIDES).
- Risky-code-execution benchmarks for code agents (RedCode, NeurIPS 2024 D&B).
- Academic studies of prompt injection against agentic coding editors (2025).
- npm and PyPI install-script and supply-chain studies, which bear on E4.

*Bibliography spot-check (5 entries plus extras):*
- `agentdojo` (NeurIPS 2024 D&B), `injecagent` (Findings ACL 2024), `greshake2023` (AISec '23,
  pp. 79–90, DOI matches), `liu2024formalizing` (USENIX Security '24) and `asb2025` (ICLR 2025) are
  correct.
- `camel2025`, `designpatterns2025`, `radosevich2025mcp` and `hasan2025mcp` have the correct arXiv
  identifiers.
- `mcpstudy2` (MCPTox, AAAI-26, vol. 40(42), pp. 35811–35819) could not be verified offline, and its
  key name is uninformative.
- `cc_llm_gateway` is cited selectively (see finding 9).

**31. [minor] Presentation problems.**
- Fig. 1 squeezes a 58 × 15 heatmap into one column. Labels are unreadable at print size; use a
  `figure*` or split it by tier.
- Table VII (E5) is shrunk by `adjustbox` to roughly 5 pt; set it as a `table*` or drop columns.
- Fig. 3 is almost all zero bars and conveys nothing that Table VI does not; replace it with
  task-completion against follow.
- The Table V footnote points readers to a repository file (`e2_prevalence.md`).
- Table VI leaves out the permission-prompt and lenient-secret columns that the text discusses.
- The `\answers` lines state the RQ in every section, which is good. However, §IX mixes RQ2 (E4) into
  the RQ4/RQ5 section; move E4 next to §V.

**32. [minor] The vendor-neutral tone is mostly met, with exceptions.**
The paper avoids per-product incident rankings (good). But it repeatedly singles out Claude Code's
headless trust behaviour, which is documented, while giving Copilot the benefit of a negative result
with no positive control (finding 8). The probe effort is also uneven (13 Claude Code claims against
3 for Copilot).
*Fix:* Run symmetric probes, or state the asymmetry in §VI "Limits".

### Spot-check log (numbers checked against JSON or CSV)

**Matched (29):**
- **Incidents:** nIncCounted 324; RC3 104 (32%); RC2 52; RC1 17 (5%); RC2+RC3 48%; RC10 16%; RC4 24;
  2025/2026 = 99/225; CVE 239 and GHSA 237; kinds 292/19/8/3/2; T03 74 (23%), T02 52, T19 45, T18 34,
  T01 14, T17 22; latency n 149, median −5, 135, 145, max 288.
- **E1:** 870/664/206 cells; 5 insufficient; κ 0.8757 → 0.88; 91.6%; 99.5%; 655; 29; 84; the D-means
  for A/B and C; D01 at score 2 or above = 6; D02 zero = 8 and three = 0; D03 zero = 11; D04 zero =
  13; Codex and Continue stable under all weightings.
- **E7:** 116/27/21/3/1/2/89, and the per-harness counts.
- **E6:** 0.983 [0.950, 0.994], FP 3, FN 3, macro 0.97/0.95, before 0.960 with FP 7, and the corpus
  counts.
- **E2:** 17 targets, cap 60, 1,010 repositories, 1,017 files, 18 rules, and all quoted rates.
- **E3:** 350/340/0 runs; follow 2/135 and 0/135; control 0/70; destructive 1/135; tasks 84 and 23;
  prompts 40.
- **E5:** 6/7, 3, 0.
- **E4:** 23, 7, 10/18, 17/17, 12, 97, 299.

**Mismatches (2):** the incident arithmetic (finding 14), and the "15 runs, mostly Codex" attribution
(finding 4).

**Prose claims contradicted by data (3, beyond the numbers):** "most verified incidents" are T03
(finding 13); Copilot "holds" configuration until trust (finding 8); "0 harnesses wrote the
credential" (finding 12).

**Ledger spot-checks (15):**

| Ledger id | Topic | Result |
|---|---|---|
| B1-005 | auto mode in `-p` | supports the text |
| B1-007 / G1-011 | `-p` runs hooks/MCP when untrusted | supports the text |
| B1-017 | gateway | contradicts the framing (finding 9) |
| B2-012 | `agy -p` | supports the text |
| B2-014 | no local-model path for Antigravity | supports the text |
| B2-029 | Antigravity terms on other products | supports the text |
| B3-004 | binary analysis | wrong label (finding 11) |
| B3-009 / G4-209 | Grok imports Claude and Cursor files | supports the text |
| B4-009 | Copilot BYOK without GitHub auth | supports the text |
| G1-008 | sandbox fallback | supports the text |
| G1-116 | Qwen AUTO default | supports the text |
| G3-131 | Hermes `smart` | supports the text |
| G4-004 | Cursor auto-review | supports the text |
| G6-071 | Amazon Q 1.84.0 | supports the text |
| G7-026 | source map | label and version not carried into the paper (finding 20) |
| G7-028 | Gemini action auto-trust | supports the text |
| G7-089 | DeepSeek Harness Host header | supports the text |

## Resolution

Paper revised on 2026-10-15 (14 pp, `bash paper/build.sh`, no undefined references). The coordinator fixed the data (`make experiments`), and the paper changes are listed in Appendix "Review and Corrections". Status key: **fixed**, **partial** (wording or disclosure fixed, the extra analysis not done), **won't fix** (with reason).

| # | Finding | Status | What changed / why |
|---|---|---|---|
| 1 | Circular, selection-biased thesis | partial | Abstract, intro and conclusion now say "among publicly disclosed harness-level advisories, 48%", with no "most" and no "risk". RC1 is described as the residual class (threats, incidents) and as a lower bound. A Selection paragraph was added to Limitations. *Not done:* re-running the procedure with Q12 earlier and coding the injection vector separately (needs a new classification pass). |
| 2 | Patch-latency semantics | fixed (data + text) | Latency is recomputed from dates (A-level data fix). The section is renamed "Fix date relative to advisory publication" and framed as disclosure practice, not time-to-fix. `\nIncNoFixDate` incidents without a fix date are reported. "Coordinated disclosure works" is removed. *Not done:* report-to-fix dates (not available). |
| 3 | E3 "trading completion for safety" | fixed | The abstract claim is deleted. Results now state there is no detectable safety difference and that the CIs overlap. The completion gap is attributed to headless defaults denying tools: Codex and Copilot prompt every time, while the Grok and Qwen zeros are "reasons not established". OpenCode is flagged as non-functional (control completion via macro). The Claude Code default arm is described as classifier `auto`. The "creates pressure" sentence is removed. *Not done:* rates conditional on the agent acting. |
| 4 | Secret-hit attribution, missed signal | fixed | The correction paragraph now says 15 = 10 Claude Code (via the import) + the rest Codex snapshots, and states that the metric was changed after results were seen. A new `secret in state` metric was added. The 10/10 Claude Code `instructions` result is explained by an E7 probe (`@.env` import with no model call, CVO-HW-001, [T]) and presented as a documented harness design property. `secret read` is stated to undercount for final-message-only harnesses. |
| 5 | E2 pooled rates are sampling artefacts | fixed / partial | Prevalence is now per stratum (Table `e2_strata`). HG-MCP-005 is marked as restating the sampling key. "Which E2 addresses" is deleted. The text says no finding was hand-validated, so real-world precision is unknown. *Not done:* a hand-labelled sample of 100 findings. |
| 6 | Evidence-label discipline in `matrix/evidence` | fixed (data) / partial | The A09 relabel was propagated to the matrix (data fix). The paper now says where [T] evidence lives (probe and bench files). *Not done in the paper:* ledger ids for every matrix fact, and a test proving that no `unverified` fact feeds a score (`e1_matrix.py` already refuses unverified citations). |
| 7 | Reliability overstated | fixed (disclosure) / partial | Method and Limitations say that collectors, both raters and the incident classifier are LLM agents, and that the raters share one fact base. κ is described as measuring rubric application. The N/A-vs-score cells are named as excluded from κ but included in the `\nDisagreeEOne` published disagreements. The single-rater incident classification is stated. *Not done:* Krippendorff's α and a 15% second rating of incidents. |
| 8 | RQ7 headline overstated | fixed | The abstract gives `\pctClaimsTested` of `\nClaims` testable. "Most documented controls hold" is removed, and the tested set is called a convenience sample. The Copilot result is now "did not start … not re-tested in a trusted folder". The controls section no longer says Copilot "holds" config. The effort asymmetry is stated in Limits. *Not done:* positive-control probes and a security-relevance classification. |
| 9 | Claude Code in an unsupported configuration | fixed | Method quotes the vendor's "doesn't support routing … to non-Claude models". E3 and Limitations label the Claude Code results as an unsupported configuration whose default arm is classifier `auto`. |
| 10 | Disclosure candidate public in matrix | fixed (data) | Per A27 the Cline plugin behaviour is vendor-documented. The paper cites the Cline docs as a design property, and no disclosure history is mentioned. |
| 11 | Grok binary analysis | fixed | B3-004 is withdrawn (A26). The paper no longer mentions binary contents. The hybrid rationale now rests on the version lag and build-time endpoints. The ethics paragraph states that a strings-derived fact was withdrawn. |
| 12 | E5 vs E3 Codex | fixed | The E5 key result is now "0 of 4 applicable, one run, a sampling result". Codex snapshots happen when the shell tool runs (`\benchCodexSnapshotK` of `\benchCodexSnapshotN` E3 runs, [T]). |
| 13 | threats.tex "most incidents" | fixed | Replaced with "largest single group … T03 23% by class; RC3 32% by root cause" (macros). |
| 14 | Incident arithmetic | fixed | The sentence now subtracts `\nIncOutside` explicitly. |
| 15 | "No hand-typed numbers" | fixed | Now reads "every result number"; the appendix says design constants are typed. |
| 16 | Wilson bounds rounded to 0.00 | fixed | Bench macros now use 3 decimals. The E3 table shows CIs in percent with 1 decimal. |
| 17 | E6 CIs and held-out status | partial | The text states that the intervals are optimistic (clustered pairs) and that the test split was seen once before the content fixes. *Not done:* cluster bootstrap. |
| 18 | Incident scope broader than harness | partial | The ecosystem count (`\nIncTierEco`) and the population caveat are stated. *Not done:* headline shares with and without ecosystem items. |
| 19 | Timeline confound | partial | The collection-recency and GHSA-adoption confound was added, and the caption says the partial quarter is not a decline. *Not done:* hatching the partial bar in the generator. |
| 20 | Unlabelled claims | fixed | The source map is now [3P] with version 2.1.88. "Every major harness" is scoped to the benchmarked harnesses [D][T]. D07 credentials are tied to the matrix column [D]. The vendor threat report is attributed as the vendor's own account. |
| 21 | E4 signature gap | fixed (text) | The documented signed manifest that the installer does not verify is stated. "Unverified" auto-update cells are explained. The E4 table moved to `paper/tables/e4_supply.md` for space. |
| 22 | Grok tier inconsistent | fixed | Described as an A/B hybrid: source read white-box, npm client treated as Tier B in E3/E7. The E3 table marks Tier-B clients with ^B. |
| 23 | E2 secrets handling | fixed | The text says secret-shaped strings were counted only, owners were not notified because identifiers are discarded by design, and the strings were not validated. |
| 24 | Vendor-host attempts in bench | fixed | Blocked vendor and telemetry host attempts per harness are reported in the RQ7 Limits ([T]). |
| 25 | Classifier sensitivity | partial | The text says the alternative reading would lift all classifier-default harnesses, that rankings were not recomputed, and why [3P] can only lower a score. *Not done:* rankings under the alternative reading. |
| 26 | Timeouts unreported | fixed | Timeout column in the E3 table (generator) and a total macro. |
| 27 | CVE-2025-53773 class disagreement | won't fix here | Evidence CSV sync is a data task outside the paper. The paper uses `incident-classification.csv`, which the script reads. |
| 28 | RQ6 prescriptive | fixed | The section is now labelled "recommendations, not an evaluated finding". The "regulated financial institutions" suitability claim is removed, and the lack of coverage and usability evaluation is stated. |
| 29 | Causal and superlative wording | fixed | All five listed phrases were removed or hedged. D02 and D03 are now cited with macros. |
| 30 | Related-work gaps | fixed | Added verified entries: Koishybayev et al. (USENIX Sec 2022), ARGUS (USENIX Sec 2023), IsolateGPT (NDSS 2025), Progent (arXiv), RedCode (NeurIPS 2024 D&B), Ohm et al. (arXiv). `mcpstudy2` was renamed `mcptox2026`. Editor prompt-injection studies were not added (no single verified entry chosen). |
| 31 | Presentation | fixed / partial | The heatmap is regenerated at true column size (readable 4–5 pt labels). The E5 table headers were shortened in the generator, with no shrink to 5 pt. Fig. 3 was replaced in the generator by task-completion vs follow, but it is omitted from the paper for space (file kept). The E2 footnote pointer was removed. The E3 table now has prompt, timeout and secret-in-state columns. *Not done:* moving E4 next to §V. |
| 32 | Vendor-neutral tone / uneven effort | fixed (disclosure) | The probe-effort asymmetry and the lack of a Copilot positive control are stated in §VI Limits. |

# Code review (toolkit)
An independent code-reviewer subagent produced 22 findings: 4 high, 10 medium, 8 low. Details, reproductions and the
per-finding resolution are in [`CODE_REVIEW.md`](CODE_REVIEW.md). All high and medium findings are fixed, each with a regression test,
except L5, which is a documented won't-fix: the target keeps its default seccomp profile so harness-native sandboxes can be observed.
H1 (Ollama attached to an internet-facing network during the bench) was mitigated live. Ollama's logs show no pull, push or delete
call from any bench container.
