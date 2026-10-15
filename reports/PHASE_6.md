# Phase 6 — Writing (paper, executive brief, governance checklist) and review

Date: 2026-10-15 · Spend: $0.00

## Done
- **Paper:** *The Harness Is the Attack Surface: A Security Analysis of AI Coding-Agent Harnesses (2025–2026)*
  (`paper/main.tex`, 14 pages, IEEEtran).
  - Built by `paper/build.sh` with a pinned Tectonic 0.16.9 (sha256-checked); `paper/paper.md` is the Markdown mirror.
  - Covers RQ1–RQ7. Every section states its RQ.
  - Every result number is a macro from `paper/numbers.tex`, generated from `experiments/results/*.json` by `experiments/paper_numbers.py`. Tables and figures are script-generated.
  - Evidence labels are [T]/[D]/[3P]; unverified claims are excluded.
  - Related work has 46 verified entries.
- **Executive brief:** 2 pages, `brief/executive-brief.md` and PDF, rendered from a template whose numbers come from the same macros (`scripts/render_brief.py`).
- **Governance checklist:** 30 controls, `brief/governance-checklist.md` and `.yaml`. Each control maps to NIST AI RMF, ISO/IEC 42001, OWASP, ATLAS and MAS AIRM. A validator checks that every referenced id exists.
- **Hostile review** by a fresh reviewer subagent: 13 major and 19 minor findings. Resolution: 21 fixed, 10 partial (wording fixed, extra analyses noted as future work), 1 won't-fix (`reports/REVIEW.md`). Data corrections:
  - incident dedup made deterministic (324 → 323);
  - patch latency reframed and recomputed from dates;
  - E2 prevalence stratified by file type;
  - E3 transcript-aware secret metric, which revealed Claude Code's documented CLAUDE.md `@`-import pulling `.env` into context (new E7 probe; HW-001 [T]);
  - A09 relabelling in the matrix evidence;
  - withdrawn binary-strings fact (A26);
  - Cline item reclassified as vendor-documented (A27).
- **Code review** by a fresh subagent: 22 findings (`reports/CODE_REVIEW.md`), all fixed or documented, including H1 (Ollama dual-homed during the bench), which was mitigated live, with logs showing no abuse.

## Open / partial (as recorded in REVIEW.md)
- A second rater for incident classification; Krippendorff's α; a hand-labelled E2 sample; positive-control trust probes; cluster bootstrap for E6.

## Update (2026-10-15): prose revision
- The paper was re-edited for a formal academic register at the author's request (A29): tighter sentences, no colloquialisms, consistent British spelling. Section sources went from 8,257 to 8,403 words; the PDF stays at 14 pages (microtype protrusion; heatmap at 0.9 and timeline at 0.85 column width).
- Author block: name only; the project URL is now the last sentence of the abstract.
- Checked by script: every `numbers.tex` macro, `\cite` key, `\ref`/`\label` and evidence-label count is unchanged (one duplicated rubric-rule sentence in Appendix E now cross-references Section V). `make all` passes; the Markdown mirror and the web reader were regenerated.
