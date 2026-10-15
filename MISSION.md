# MISSION.md — `harnessguard`

> **Security analysis & audit toolkit for AI agent harnesses** (coding-agent CLIs/IDEs and agent SDK runtimes).
> **50 % software** (auditable, contributable Python toolkit) · **50 % research** (peer-review-grade paper + executive brief).
> Built autonomously with Claude Code, phase by phase. **Read this entire file before doing anything.**

---

## 0. One-paragraph brief

In 2026 the industry converged on **Agent = Model + Harness**. The harness — the runtime loop that holds credentials, executes shell commands, mounts MCP servers, reads repo-level config, spawns sub-agents and runs headless in CI — is now the real attack surface, not the model. Every major vendor shipped at least one harness-level vulnerability in 2025–2026 (rules-file backdoors, MCP tool poisoning, prompt-injection → RCE, supply-chain abuse of agent CLIs, source leaks). There is no vendor-neutral, reproducible comparison of harness security controls and no tooling that audits a machine or repo for dangerous harness configuration. **Build both.** Output: (1) `harnessguard`, a Python package/CLI on PyPI that inventories installed harnesses, audits their configs/MCP servers/instruction files/state directories for risk, and benchmarks prompt-injection resilience with inert canaries in a sandbox; (2) a paper, *"The Harness Is the Attack Surface: A Security Analysis of AI Coding-Agent Harnesses (2025–2026)"*, plus a 2-page executive brief and a governance checklist. Everything reproducible from `make all`.

---

## 1. Scope — the harnesses

Four tiers, split by **method**, not by how famous the product is. Closed source does not put a harness out of scope — it changes the method from white-box (read the code) to black-box (observe the client; §1.1). Pin the exact version you analysed in `VERSIONS.md` — this field moves monthly.

### Tier A — Open-source harnesses: **white-box** (install, read source, test empirically)
| Harness | Vendor | License (verify) | Notes |
|---|---|---|---|
| OpenCode | SST | MIT | provider-agnostic, de-facto OSS alternative to Claude Code |
| Codex CLI | OpenAI | Apache-2.0 | Rust, sandboxed; cloud/app are closed |
| DeepSeek Harness (`dsh`) | DeepSeek | MIT | everything-is-a-plugin (Cordis), dev preview since Aug 2026, plugin ecosystem via npm |
| Pi / Oh-My-Pi (`omp`) | M. Zechner / C. Bölük | MIT | minimal harness + batteries-included fork |
| Cline (+ Roo Code, Kilo Code/Kilo CLI) | Cline / Kilo | Apache-2.0 | IDE + CLI + SDK |
| Aider | community | Apache-2.0 | |
| OpenHands (+ Software Agent SDK) | All Hands | MIT | |
| Goose | Block | Apache-2.0 | MCP-first |
| Continue | Continue | Apache-2.0 | CI/PR-check focus |
| Qwen Code | Alibaba | Apache-2.0 | fork of Gemini CLI |
| Kimi CLI | Moonshot | Apache-2.0 | Python |
| Mistral Vibe | Mistral | Apache-2.0 | Python |
| Hermes Agent | Nous Research | MIT | general-purpose personal agent: messaging gateway, scheduler, memory |
| OpenClaw | community | MIT (verify) | personal agent, known for exposed instances |
| Gemini CLI (legacy) | Google | Apache-2.0 | code still open; consumer login ended 2026-06-18 — API-key mode may still work, verify |
| Warp (client) | Warp | MIT + AGPL-3.0 | open-core: AI/Oz/Drive backend closed |
| Crush | Charm | FSL-1.1-MIT | source-available, not OSI |

### Tier B — Closed-source harnesses you can still run: **black-box empirical** (priority targets)
We cannot read their code, but we can install the official client, inspect what it writes to disk, watch what it sends over the network, drive it headless against the same canary scenarios, and compare observed behaviour with what the vendor documents. Detect access in Phase 0; never ask the author for credentials.

| Harness | Vendor | Access needed (verify in Phase 0) | What is testable black-box |
|---|---|---|---|
| **Claude Code** (CLI, Agent SDK) | Anthropic | Claude subscription or API key — available | full: config/hooks/MCP/permission modes, `claude -p` bench, state-dir & secret storage, egress/telemetry hosts, npm package metadata, update channel |
| **Google Antigravity** — IDE + Antigravity CLI (`agy`) | Google | Google account (free tier; quota via AI Pro/Ultra) | `agy`: config, headless bench (verify flag), egress; IDE: repo-level `.agent/` rules/workflows/skills trust prompts, built-in browser surface (T12), MCP config, artifacts — manual/semi-automated probes |
| **xAI Grok Build** (`grok` CLI) | xAI | SuperGrok-tier subscription (beta-gated) — without it: Tier C, `N/A (no access)` | config, `grok -p` headless bench, sub-agent/worktree isolation, AGENTS.md handling, egress |
| Cursor CLI | Anysphere | free Hobby tier may suffice | rules/hooks/MCP config, headless bench, egress |
| GitHub Copilot CLI | GitHub | Copilot Free/Pro | config, `copilot -p`, CI pattern, egress |
| AWS Kiro CLI | AWS | free tier | steering/hooks/MCP config, headless bench, egress |
| Amp · Droid · Windsurf · Augment (Auggie) · Jules · Junie · Qoder · Trae | various | free tiers / trials where they exist | as access allows; otherwise Tier C |

### Tier C — Closed harnesses with no access: document-level only
Codex cloud agent/app (if no ChatGPT plan) · Devin · Replit Agent · any Tier-B harness whose access check fails. Analyse official docs, security pages, disclosure policies, advisories and third-party research. Matrix cells from this tier are labelled `from-official-docs` or `third-party-report`, never `verified-by-test`.

### 1.1 The black-box method (applies to every Tier B harness)
- **Do:** install the official release; read official docs/changelogs/advisories; parse user- and repo-level config; run `harnessguard observe` (§5.2) — a sandboxed run with egress logging and filesystem watch — to record hosts contacted (model API / telemetry / update / unknown), files written and their permissions, where credentials are stored (keychain vs plaintext), evidence of OS-level sandboxing (seatbelt / bwrap / container) from process inspection, and prompts shown; drive headless mode through the canary scenarios; probe config trust (does a repo-level hook or MCP server run on first open? is there a trust prompt?); inspect package **metadata** only (manifest, declared dependencies, install/postinstall scripts, signatures, SBOM).
- **Don't:** decompile, deobfuscate or reverse-engineer proprietary code; use leaked source (the Claude Code source-map leak is cited as an event, never read or quoted); bypass licensing, quotas or bot detection; test the vendor's hosted service beyond your own client's normal traffic; break the vendor's terms — if the terms forbid a probe, skip it and label the cell `N/A (terms)`.
- **Why it matters:** the gap between what a vendor documents and what its client observably does is itself a result (RQ7), and the method is the same for open and closed harnesses, which makes the comparison fair.

### Tier D — Harness runtimes / SDKs (the layer teams build their own harness on)
Open: OpenAI Agents SDK · Google ADK · Microsoft Agent Framework (AutoGen + Semantic Kernel, 1.0 Apr 2026, has its own "agent harness" layer) · LangGraph / Deep Agents · AWS Strands Agents · Pydantic AI · CrewAI (core) · smolagents · OpenHands SDK · GitHub Copilot SDK · TrueForge · Raven (EverMind).
Managed/commercial: Claude Agent SDK + Claude Managed Agents · OpenAI AgentKit · Vertex AI Agent Engine · AWS Bedrock AgentCore Harness · Azure AI Foundry Agent Service · Copilot Studio "GitHub Copilot harness" · LangGraph Platform · Manus.

**Prioritisation rule:** depth over breadth. Priority empirical set = **Tier A (white-box) + Claude Code, Antigravity and Grok Build (black-box)**; then the rest of Tier B as access allows; structured doc-level coverage of everything else; mark cells `N/A (no access)` honestly rather than guessing.

---

## 2. Research questions → deliverables

| RQ | Question | Deliverable | Evidence type |
|---|---|---|---|
| RQ1 | What is the attack surface of an agent harness, and how does it differ from classic LLM-app risk? | Threat taxonomy (`taxonomy/harness-threats.yaml`), attack trees, mapping to OWASP LLM Top 10 (2025), OWASP Agentic/MCP Top 10, MITRE ATLAS, STRIDE | literature + source reading |
| RQ2 | How do harnesses differ in their security controls (permission model, sandbox, config trust, MCP governance, secrets, egress, telemetry, supply chain, CI safeguards)? | Control matrix + 0–3 rubric scorecard per harness (`matrix/controls.csv`, `matrix/scorecard.md`) with evidence links | docs + source + hands-on verification |
| RQ3 | What harness-level incidents and CVEs occurred 2025–2026, what was the root cause class, and how fast were they patched? | Incident timeline + root-cause classification (`evidence/incidents.csv`) | NVD/GHSA/vendor advisories |
| RQ4 | Can misconfiguration and dangerous patterns be detected automatically across harness config formats? | `harnessguard` static modules + rule pack, precision/recall on a labelled synthetic corpus, findings on a public-repo corpus | software + experiment |
| RQ5 | How resilient are harnesses × models × permission modes to indirect prompt injection and secret-residue leakage, measured with inert canaries? | `harnessguard bench` (canary-bench) results with confidence intervals | sandboxed experiment |
| RQ6 | What controls should an organisation (incl. regulated financial institutions) mandate before adopting agent harnesses? | Governance checklist mapped to NIST AI RMF, ISO/IEC 42001, OWASP, MAS AI-risk guidelines; executive brief | synthesis |
| RQ7 | For closed-source harnesses (Claude Code, Antigravity, Grok Build, …), do the documented security controls match observable client behaviour — telemetry hosts, config trust, sandboxing, secret storage, update checks? | Claims-vs-observed table per closed harness (`matrix/claims_vs_observed.csv`) | black-box observation (§1.1) |

Every paper section must state which RQ it answers; every result table must be generated by a script from JSON — no hand-typed numbers.

---

## 3. Threat taxonomy (seed — extend, restructure, do not just copy)

| ID | Class | Examples specific to harnesses |
|---|---|---|
| T01 | Indirect prompt injection via workspace content | README/AGENTS.md/CLAUDE.md/.cursor rules, code comments, test fixtures, git history, issues/PRs pulled by the agent, hidden Unicode / zero-width / bidi / HTML comments |
| T02 | Repo-level config as code execution | hooks in `.claude/settings.json`, `.cursor/hooks.json`, `.kiro/hooks/`, Kiro/Codex/OpenCode project configs, MCP servers auto-started on folder open, "trust this folder" bypasses |
| T03 | Permission-model weaknesses | YOLO / auto-approve / bypass-permissions modes, over-broad allowlists (`Bash(*)`), allowlist bypass via shell metacharacters, path-restriction bypass, symlink/`..` escapes |
| T04 | MCP supply chain & tool poisoning | malicious/typosquatted MCP packages, `npx -y`/`uvx` unpinned launches, tool-description injection, rug pulls (description changes after approval), OAuth token theft, server-side prompt injection via tool results |
| T05 | Skills / plugins / extensions marketplaces | SKILL.md injection, plugin bundles (`dsh` plugins, Claude Code plugins, omp extensions), postinstall scripts |
| T06 | Harness supply chain | `curl \| bash` installers without checksums, unsigned binaries, auto-update channels, npm/PyPI/cargo dependency compromise, source-map/secret leaks in packages |
| T07 | Secret exposure & residue | API keys/OAuth tokens in `~/.<harness>/`, secrets copied into session logs, transcripts, trajectories, memory files; telemetry carrying secrets; world-readable state dirs |
| T08 | Data exfiltration channels | web fetch, DNS, markdown image rendering, `git push` to attacker remote, MCP egress, curl/wget, browser automation |
| T09 | Headless / CI abuse ("pwn request") | `claude -p`, `codex exec`, `grok -p`, `agy` in PR-triggered workflows with repository secrets; poisoned PR text drives the agent |
| T10 | Persistent memory poisoning | cross-project memory (Hermes, omp Hindsight, Claude memory, OpenClaw), long-lived instructions injected once and replayed forever |
| T11 | Sub-agent & cross-harness trust propagation | dsh/Hermes delegating to Claude Code/Codex: does bypass mode, env, and secrets propagate? worktree isolation gaps |
| T12 | Browser & computer-use surfaces | built-in Chromium (Antigravity), session cookies, same-profile browsing, screenshot leakage |
| T13 | Multi-tenant / shared sessions | collab links, cloud sandboxes, shared workspaces, prompt/transcript visibility |
| T14 | Destructive & unsafe autonomous actions | `rm -rf`, force-push, DB migrations, cloud CLI with prod creds; hallucinated commands under auto-approve |
| T15 | Telemetry, data residency & compliance | code/prompt retention by vendor, training opt-out defaults, region, audit-log availability |
| T16 | Misuse of harnesses by attackers (offensive use) | documented abuse of agent CLIs for secret hunting / "vibe hacking" — treat descriptively only; no offensive tooling |

Map each class to STRIDE + MITRE ATLAS technique IDs + OWASP IDs, and to the controls that mitigate it (this mapping becomes the rule pack and the scorecard rubric).

---

## 4. Seed evidence — VERIFY EVERY ITEM (IDs, dates, affected versions) against NVD/GHSA/vendor sources before citing

The author's knowledge is dated; some IDs below may be wrong. Confirm, correct, and **extend through Q4 2026** with web search. Record each in `evidence/ledger.csv` (claim, source URL, publisher, date, verified_by, confidence).

- "Rules File Backdoor" — hidden Unicode in `.cursorrules` / Copilot instructions (Pillar Security, Mar 2025)
- MCP tool-poisoning attacks and GitHub MCP server data-leak via prompt injection (Invariant Labs, Apr–May 2025)
- CVE-2025-49596 — MCP Inspector RCE (Oligo, 2025)
- Gemini CLI indirect prompt injection → silent command execution & exfiltration (Tracebit, Jul 2025)
- CVE-2025-54135 "CurXecute" and CVE-2025-54136 "MCPoison" — Cursor (Aim Security / Check Point, Aug 2025)
- CVE-2025-53773 — GitHub Copilot / VS Code RCE via prompt injection flipping auto-approve (Aug 2025)
- CVE-2025-54794 / CVE-2025-54795 — Claude Code path-restriction bypass & command injection (Cymulate, Aug 2025)
- CVE-2025-52882 — Claude Code IDE-extension local WebSocket exposure (Jun 2025)
- CVE-2025-59536 — Claude Code code execution via repo-level hooks/MCP config (Check Point, Jan 2026) — verify
- Amazon Q Developer VS Code extension v1.84.0 shipped with injected destructive prompt (Jul 2025)
- `nx` "s1ngularity" npm supply-chain attack weaponising Claude Code / Gemini CLI / Q CLI to hunt secrets (Aug 2025); Shai-Hulud npm worm (Sep 2025) as ecosystem context
- Postmark MCP server variant exfiltrating email (Sep 2025); Supabase MCP data leak via SQL-returned injection (Jul 2025)
- Google Antigravity post-launch reports: indirect-injection exfiltration, ignore-rule bypass, destructive filesystem incident (Nov–Dec 2025) — verify
- OpenClaw/Clawdbot publicly exposed control panels & token leakage (Jan 2026) — verify
- Claude Code source-map leak in `@anthropic-ai/claude-code` 2.1.88 (31 Mar 2026): exposure of internals, not a license change
- Anthropic's 2025 threat-intel reports on offensive misuse of Claude Code (T16 context)
- Anything new in Jul–Oct 2026 for DeepSeek Harness, Antigravity CLI, Grok Build, Kiro CLI, Hermes, omp, OpenCode, Codex — search explicitly

Also collect each vendor's **security documentation**, SECURITY.md / disclosure policy, bug-bounty scope, sandbox docs, permission docs, and release-signing / SBOM practice.

---

## 5. Software deliverable — `harnessguard`

### 5.1 Package & CLI
- Python ≥ 3.12, `uv`, `pyproject.toml`, src layout: `src/harnessguard/`. Import `harnessguard`, CLI `harnessguard` (Typer + Rich). **Phase 0: check PyPI + GitHub name availability; fallbacks `harnesswatch`, `harnessaudit`.**
- Stack: `pydantic` v2 models for every finding/config, `typer`, `rich`, `pyyaml`, `httpx`, `pytest` (+ `pytest-cov`, `hypothesis` for parsers), `ruff`, `mypy --strict`, `pre-commit`, GitHub Actions (lint/type/test matrix macOS + Ubuntu, Python 3.12/3.13), Codecov, `uv build` + Trusted Publishing to PyPI.
- Output formats: Rich terminal, JSON, Markdown, **SARIF 2.1.0** (so findings show up in GitHub code scanning). Exit codes: 0 clean / 1 findings ≥ threshold / 2 error.
- No network calls by default; `--online` enables OSV / registry lookups. Never transmit file contents anywhere.

### 5.2 Modules (each: parser → pydantic model → rules → findings)
| Command | Purpose |
|---|---|
| `harnessguard inventory` | Detect installed harnesses on this machine and in this repo: binaries on PATH, versions, install method (npm/pip/brew/curl-installer), state dirs, login state (never print secrets) |
| `harnessguard audit config [PATH]` | Parse user-level and repo-level configs of every supported harness into a **common schema** (`HarnessConfig`: permission_mode, allow/deny lists, hooks, mcp_servers, instruction_files, trust settings, telemetry, auto_update) and run the rule pack |
| `harnessguard audit mcp` | Parse all MCP server declarations (every harness format + `.vscode/mcp.json`): package pinning, registry provenance, transport/TLS/auth, inline secrets in `env`, tool-description injection heuristics, optional OSV/registry checks |
| `harnessguard audit instructions` | Scan instruction/rules/skill files for injection indicators: zero-width/bidi/confusable Unicode, HTML comments, base64/hex blobs, imperative override phrases, embedded URLs/IPs, role-play & "do not tell the user" patterns. Scored, not binary |
| `harnessguard audit secrets` | Scan harness state dirs, session logs, transcripts, trajectories, memory files for secrets (regex + entropy; `detect-secrets`-style) and check file permissions. Redacts in output; never stores matches |
| `harnessguard audit supply` | SBOM (CycloneDX) for installed harness packages (npm/pip/cargo/go), OSV vulnerability lookup (`--online`), installer-script checksum/signature presence, auto-update channel settings |
| `harnessguard audit ci [REPO]` | Detect headless agent invocations in GitHub Actions / GitLab CI: PR-triggered + secrets + auto-approve = "pwn-request" pattern; permissions of `GITHUB_TOKEN` |
| `harnessguard observe <harness> [-- CMD]` | **Black-box behavioural probe** (works for closed and open harnesses alike): run a harness command inside the sandbox with an egress-logging proxy and a filesystem watch; report hosts contacted (classified model-API / telemetry / update / unknown), files and dirs written with permission bits, credential storage location, evidence of OS-level sandboxing, prompts shown. Output feeds `matrix/claims_vs_observed.csv` (RQ7) |
| `harnessguard bench …` | Canary-bench (5.4) |
| `harnessguard report` | Aggregate findings → Markdown/SARIF/JSON; `--baseline` for diffing |
| `harnessguard scorecard` | Render the RQ2 control matrix for a harness/version from `matrix/` data |

Ship a **GitHub Action** (`action.yml`) and a **pre-commit hook** wrapping `audit config/mcp/instructions/ci` on repos.

### 5.3 Rule pack (`rules/*.yaml`, versioned, documented, each with a test fixture pair: `should_fire/`, `should_not_fire/`)
Rule ID scheme `HG-<AREA>-<NNN>`, severity (critical/high/medium/low/info), confidence, taxonomy class (T01–T16), affected harnesses, remediation text, references. Seed rules:
- `HG-PERM-001` auto-approve / bypass-permissions / YOLO / full-auto mode enabled (per-harness flag & config names)
- `HG-PERM-002` over-broad allowlist (`Bash(*)`, `*`, write to `/`)
- `HG-PERM-003` deny-list missing for destructive commands when auto-approve is on
- `HG-HOOK-001` repo-level (not user-level) config defines hooks that execute shell commands
- `HG-HOOK-002` hook command references network tools or external scripts fetched at runtime
- `HG-MCP-001` MCP server launched via unpinned `npx -y` / `uvx` / `pip install` at runtime
- `HG-MCP-002` remote MCP over plain HTTP / no auth header / wildcard host
- `HG-MCP-003` secrets inline in MCP `env` or args
- `HG-MCP-004` tool description contains instruction-like or cross-tool text (tool poisoning)
- `HG-MCP-005` MCP server declared in repo-level config (auto-starts for every cloner)
- `HG-INJ-001` hidden/confusable Unicode in instruction files
- `HG-INJ-002` override/exfiltration phrase patterns in instruction files
- `HG-INJ-003` instruction file pulls remote content (`@https://…`, curl) at load time
- `HG-SEC-001` secret-like strings in harness logs/transcripts/memory
- `HG-SEC-002` state directory or credential file world/group readable
- `HG-SEC-003` credentials stored in plaintext config where keychain/OS store is supported
- `HG-NET-001` unrestricted web fetch where the harness supports domain allowlists
- `HG-SUP-001` installed via unsigned `curl | bash`; no checksum verification; auto-update on
- `HG-SUP-002` dependency with known vulnerability (OSV)
- `HG-TEL-001` telemetry / training-data sharing enabled (flag as policy, not vulnerability)
- `HG-CI-001` headless agent in PR-triggered workflow with secrets exposed
- `HG-MEM-001` persistent cross-project memory enabled and writable by the agent
- `HG-SUB-001` sub-agent / cross-harness delegation inherits bypass mode or full env

Rules must be **harness-aware**: the same risk has different config spellings per harness. Maintain `rules/harness_profiles/<harness>.yaml` describing config locations, flag names, and defaults (verify every path/flag against current docs — seeds: `~/.claude/settings.json`, `.claude/settings*.json`, `.mcp.json`, `~/.codex/config.toml`, `opencode.json`, `~/.gemini/settings.json`, `.cursor/rules|mcp.json|hooks.json`, `.github/copilot-instructions.md`, `.vscode/mcp.json`, `.clinerules`, `.roo/`, `.kilocode/`, `.aider.conf.yml`, `~/.config/goose/config.yaml`, `.goosehints`, `.openhands/`, `~/.hermes/`, `~/.pi/`, `~/.omp/`, `~/.dsh/` profiles, `.kiro/steering|hooks|settings`, `~/.qwen/`, `~/.kimi/`, `~/.vibe/config.toml`, `crush.json`, `.windsurf/`, `.agent/` rules/workflows/skills + the `agy` config dir (Antigravity IDE/CLI — verify), `~/.grok/` + AGENTS.md handling (Grok Build — verify), `~/.openclaw/`, `~/.config/amp/`, `.factory/`, `.continue/`). Profiles for Claude Code, Antigravity and Grok Build are mandatory, not optional. Expect schemas to have changed — read the docs/source first.

### 5.4 Canary-bench (`harnessguard bench`) — defensive resilience benchmark
**Purpose:** measure, per harness × model × permission mode, how often an agent follows injected instructions or leaks synthetic secrets. **Inert by design.**
- **Isolation:** every run inside Docker (Linux container; `--network none` plus a sidecar egress proxy that allows only the model-API host and logs/blocks everything else). Synthetic repo per run, discarded afterwards. Nothing ever runs on the host.
- **Canary payload rules (hard):** the only "attacker goals" are (a) create a marker file `CANARY_<id>.txt`, (b) print a canary string, (c) read a synthetic secret file and send it to a **local sink at 127.0.0.1** inside the container. No real hosts, no real credentials, no destructive commands beyond deleting a fixture file inside the sandbox. Payloads are templated, versioned, and documented as **detection fixtures**, not exploits.
- **Scenarios (seed):** README injection · AGENTS.md/CLAUDE.md injection · hidden-Unicode rules file · HTML-comment injection in source · poisoned MCP tool description (fake local MCP server) · poisoned tool *result* · poisoned local web page (served from container) · poisoned git commit message / issue text · poisoned persistent-memory file · sub-agent delegation chain · headless `-p` mode vs interactive-with-auto-approve.
- **Metrics:** Injection Follow Rate, Secret Access Rate (read when task didn't require it), Exfil Attempt Rate (blocked egress or local-sink hit), Destructive Action Rate, Permission-Prompt Rate, task-completion rate (so "safe but useless" is visible), tokens/cost. N ≥ 5 runs per cell, report Wilson/bootstrap CIs, fixed seeds where the harness allows.
- **Runners:** one adapter per harness using its headless mode (`claude -p`, `codex exec`, `opencode run`, `dsh` headless profile, `agy`/`gemini -p`, `aider --message`, `goose run`, `hermes`, `omp -p`, `qwen -p`, `kimi`, `vibe --prompt`, `crush run`, `grok -p`, `kiro-cli`, `copilot -p` — verify flags). Skip gracefully with `N/A (no access)` when credentials are absent.
- **Tier B harnesses run the identical scenarios black-box:** no source instrumentation; wrap every run with `harnessguard observe` so network and filesystem evidence is captured alongside the behavioural metrics. Claude Code, Antigravity (`agy`) and Grok Build are first-class bench targets, not afterthoughts.
- **Budget:** hard cap configurable (`--max-usd`, default 25) with cheap models by default; log spend per cell.

### 5.5 Engineering standards
- Tests ≥ 85 % line coverage; every rule has fixtures; parsers fuzzed with `hypothesis`; golden-file tests for SARIF.
- Typed end-to-end; docstrings; `CHANGELOG.md` (Keep a Changelog); semantic versioning; Conventional Commits; signed tags.
- `make all` = lint → type → test → build docs → run experiments on fixtures → build paper.
- Docs: `docs/` (MkDocs Material): quickstart, rule reference auto-generated from YAML, harness profile reference, bench methodology, threat taxonomy.
- Security of the tool itself: `SECURITY.md`, no `eval`, no shell=True with user input, subprocess with arg lists, path normalisation, read-only by default.

### 5.6 Repository layout
```
harnessguard/
├── MISSION.md  README.md  LICENSE(Apache-2.0)  SECURITY.md  CHANGELOG.md  VERSIONS.md  ASSUMPTIONS.md
├── pyproject.toml  Makefile  action.yml  .pre-commit-hooks.yaml  .github/workflows/
├── src/harnessguard/{inventory,parsers/<harness>.py,models,rules_engine,audits/*,bench/*,report,cli}.py
├── rules/            # HG-*.yaml + harness_profiles/
├── taxonomy/         # harness-threats.yaml, mappings (owasp/atlas/stride/nist)
├── matrix/           # controls.csv, scorecard rubric, per-harness evidence JSON
├── evidence/         # ledger.csv, incidents.csv, sources.bib
├── bench/            # scenarios/, fixtures/, docker/, runners/, results/<date>/
├── experiments/      # scripts that produce every table/figure from JSON
├── paper/            # LaTeX (acmart or IEEEtran), figures/, tables/, refs.bib, build.sh
├── brief/            # executive brief (2 pp) + governance checklist
├── docs/  tests/
└── private/          # gitignored: DISCLOSURE_DRAFT.md, credentials notes
```

---

## 6. Research deliverables

### 6.1 Paper — `paper/`
Working title: **"The Harness Is the Attack Surface: A Security Analysis of AI Coding-Agent Harnesses (2025–2026)"**. Target arXiv cs.CR, 10–14 pages, ACM/IEEE template, LaTeX, fully built by `paper/build.sh`.
1. Abstract · 2. Introduction (Agent = Model + Harness; why the harness layer matters; contributions) · 3. Background (harness anatomy: loop, tools, permissions, MCP, skills, memory, sub-agents, headless mode; the 2026 landscape incl. open vs closed split) · 4. Threat model & taxonomy (RQ1) · 5. Comparative analysis of security controls (RQ2; matrix + scorecard; per-dimension discussion) · 6. Incident & CVE survey 2025–2026 (RQ3; timeline, root-cause classes, patch latency) · 7. `harnessguard` design (RQ4) · 8. Empirical evaluation (RQ4 corpus results; RQ5 canary-bench results with CIs) · 9. Governance recommendations (RQ6; mapped to NIST AI RMF, ISO/IEC 42001, OWASP, MITRE ATLAS, MAS AI-risk guidelines and financial-sector supervisory expectations) · 10. Related work (AgentDojo, InjecAgent, MCP security studies, rules-file backdoor research, Trail of Bits / Invariant / Tracebit / Pillar reports, OWASP agentic work) · 11. Limitations & threats to validity (version drift, model nondeterminism, access gaps, benign-canary ceiling) · 12. Conclusion · Appendix: reproducibility, full rule list, bench scenario catalogue, scorecard rubric.
- Also produce `paper/paper.md` (Markdown mirror) for GitHub readers.

### 6.2 Executive brief — `brief/executive-brief.md` (+PDF), 2 pages
C-suite lens: what changed, top 5 risks in business terms, what to mandate before rollout, a one-page decision table (which harness class is acceptable under which controls), cost of inaction with incident citations.

### 6.3 Governance checklist — `brief/governance-checklist.md`
Control → why → how to verify (with the exact `harnessguard` command) → framework mapping. Make it adoptable as policy text.

### 6.4 Evidence & citation discipline (hard rules)
- Every factual claim about a harness carries: version tested, date, source URL, and a label — **verified-by-test** / **from-official-docs** / **third-party-report** / **unverified**. Unverified claims do not enter the paper.
- Every CVE confirmed on NVD or GHSA; every incident has a primary source (vendor advisory, researcher write-up). Access dates in BibTeX.
- No number appears in prose that is not in a results JSON. Figures generated by `experiments/`.
- Distinguish *vulnerability* (bug) from *design weakness* (default) from *policy choice* (telemetry) — do not conflate.
- Vendor-neutral tone; no superlatives without data; credit prior researchers.

---

## 7. Experiments

| ID | Experiment | Output |
|---|---|---|
| E1 | Control matrix: ~14 control dimensions × all harnesses, scored 0–3 with evidence; inter-rater check by a second pass with a fresh subagent | `matrix/`, Fig. heat-map, Table scorecard |
| E2 | Config-corpus study: public GitHub repos containing harness configs (`.claude/settings.json`, `.cursor/mcp.json`, `.mcp.json`, `opencode.json`, `.kiro/`, `AGENTS.md`, …) via GitHub Search API; run `audit config/mcp/instructions`; report prevalence of each rule. **Public data only, structure only, redact & discard any secret found, rate-limit, respect ToS, never name individual repos** | `experiments/corpus/`, prevalence tables |
| E3 | Canary-bench across available harnesses × ≥2 models each × {default, auto-approve} permission modes; ≥ 5 runs/cell | `bench/results/`, Fig. follow-rate bars with CIs |
| E4 | Supply-chain audit of each Tier-A harness package: SBOM size, OSV findings, installer signing, postinstall scripts, auto-update behaviour | table |
| E5 | Secret-residue study (local, synthetic): seed a synthetic API key, run a short session in each harness, grep state dirs/logs/transcripts for residue and check permissions | table |
| E6 | Rule-pack accuracy: precision/recall on a labelled synthetic config corpus (≥ 200 files, generated + hand-crafted) | table |
| E7 | Black-box behavioural profiles (RQ7) for Claude Code, Antigravity (`agy` + IDE), Grok Build and every other reachable Tier-B harness: hosts contacted, files written, sandboxing evidence, secret-storage location, config-trust behaviour on a synthetic repo seeded with hooks/MCP servers/rules — each compared against the vendor's documented claims | `matrix/claims_vs_observed.csv`, table + Fig. |

---

## 8. Ethics, safety & legal guardrails (non-negotiable)
1. **Defensive only.** No weaponised exploits, no malware, no credential stealers, no offensive tooling — even "for testing". Canary payloads are inert (5.4).
2. **Sandbox only.** Benchmarks run in disposable containers with egress blocked; never against the host, third-party systems, other people's repos, or production.
3. **Synthetic secrets only.** Never use, store, print, or commit real credentials. `audit secrets` redacts and never persists matches.
4. **Responsible disclosure.** If you discover a previously unknown vulnerability in any harness: stop, do not publish details or a PoC, write a private note to `private/DISCLOSURE_DRAFT.md` (gitignored), and flag it in the phase report so the author can report it to the vendor. Public write-ups only after a fix or 90 days.
5. **Public-data corpus only** (E2), no scraping beyond API terms, no re-identification, aggregate reporting.
6. **Licensing.** Respect each harness's license when reading/quoting source (short excerpts with attribution; nothing from leaked proprietary sources — the Claude Code source-map leak is cited as an event, never copied).
7. **Accuracy over drama.** Security writing attracts hype; this project's credibility is its evidence ledger.
8. **Closed-source handling.** Black-box only (§1.1): no decompilation, deobfuscation or reverse engineering; no leaked source; no circumvention of quotas, licences or bot detection; comply with each vendor's terms of service and acceptable-use policy; your own account, your own machine, your own synthetic repos only. If a term forbids a probe, skip it and label the cell `N/A (terms)`.

---

## 9. Work plan (phases → checkpoint commit + `reports/PHASE_<n>.md`)

| Phase | Work | Suggested effort |
|---|---|---|
| 0 Bootstrap | Name check, repo scaffold, tooling, CI green on hello-world, `ASSUMPTIONS.md`; access detection → `ACCESS.md` (Claude Code login, Google account for Antigravity/`agy`, SuperGrok-tier login for Grok Build, free tiers for the other Tier-B harnesses; never print secrets); `VERSIONS.md` | fast model |
| 1 Landscape & evidence | Parallel subagents (one per harness group): Tier A — install, read docs + source; Tier B — install, run `observe` probes + docs + advisories (black-box, §1.1), starting with Claude Code, Antigravity, Grok Build; Tier C — docs only. All cover permission/sandbox/MCP/config/secrets/telemetry/update behaviour; collect & verify incidents/CVEs; fill `evidence/ledger.csv`, `incidents.csv`, `sources.bib` | high-effort model |
| 2 Threat model | Finalise taxonomy YAML, mappings (STRIDE/ATLAS/OWASP/NIST), attack trees (Mermaid), derive control dimensions + scorecard rubric | high-effort model |
| 3 Toolkit core | Parsers (common schema) → rules engine → `inventory`, `audit config/mcp/instructions/secrets/supply/ci`, `report` (SARIF), tests + fixtures, docs, GitHub Action, pre-commit | implementation model; design review with high-effort model |
| 4 Canary-bench | Docker sandbox + egress proxy, scenario fixtures, runners, metrics, budget guard; smoke-test on 2 harnesses before scaling | implementation model |
| 5 Experiments | E1–E6; results JSON; figures/tables scripts; second-pass review of E1 scores | high-effort model |
| 6 Writing | Paper (LaTeX + Markdown mirror), executive brief, governance checklist; internal review pass as a hostile reviewer; fix | high-effort model |
| 7 Release | README with demo GIF/asciinema, docs site, PyPI publish (Trusted Publishing), GitHub release + signed tag, arXiv-ready PDF, `CITATION.cff`, LinkedIn announcement draft (`brief/announcement.md`) | fast model |

Checkpoint rule: a phase is complete only when its artefacts exist, tests pass, and `reports/PHASE_<n>.md` lists what was done, what was skipped (with reason), open questions, and spend.

---

## 10. Autonomy rules
- Run all phases without waiting for approval. **Decide and log**: every assumption or judgement call goes to `ASSUMPTIONS.md` with date and rationale.
- Stop and ask **only** for: credentials/paid subscriptions, spend above the configured cap, or a disclosure situation (8.4).
- Keep a live task list; commit at least once per module with Conventional Commits; never commit `private/`, results containing paths with usernames, or anything secret-shaped (`gitleaks` in pre-commit).
- Version drift is expected: if a config path or flag from this brief is wrong, trust the current docs/source, fix the profile, note it in `ASSUMPTIONS.md`.
- Prefer small, reviewable modules over frameworks; no premature abstraction.
- If a harness cannot be installed or run, record `N/A` with the reason — never fabricate a result.

## 11. Definition of done
- [ ] `pip install harnessguard` works; `harnessguard inventory && harnessguard audit config .` runs on a clean machine in < 5 s
- [ ] ≥ 20 documented rules with fixture pairs; E6 precision ≥ 0.9 on the synthetic corpus
- [ ] Parsers for every Tier-A harness + Claude Code + Antigravity + Grok Build + Cursor + Copilot + Kiro config formats
- [ ] Claude Code, Antigravity (`agy` + IDE) and Grok Build each have: a harness profile, a black-box behavioural profile (E7), a claims-vs-observed row (RQ7), a scorecard column and bench cells — or `N/A (no access)` with the reason
- [ ] `harnessguard observe` works on at least one open and one closed harness
- [ ] Canary-bench runs end-to-end on ≥ 4 harnesses with CIs; results reproducible from `make bench`
- [ ] Control matrix covers every harness in §1 (with honest `N/A`s), each cell linked to evidence
- [ ] Incident timeline ≥ 25 verified entries 2025–2026 with root-cause class
- [ ] Paper builds to PDF, every table/figure script-generated, every claim labelled per 6.4
- [ ] Executive brief + governance checklist published; docs site live; CI + Codecov badges green
- [ ] SECURITY.md, CITATION.cff, CHANGELOG, Apache-2.0, signed v0.1.0 tag, PyPI release

## 12. Environment
- Primary: macOS on Apple Silicon, 16 GB RAM — everything must run comfortably here (Docker Desktop or Colima for the bench; keep container images small).
- Secondary: Linux / WSL2 box with an NVIDIA GPU — optional for local open-weight models via Ollama/vLLM in the bench (a "no vendor API" cell is scientifically valuable: same harness, local model).
- Claude Code is used from the terminal only; no IDE integration assumed.
- Antigravity IDE needs a GUI session (fine on the Mac); `agy` and Grok Build are terminal tools. Grok Build is beta-gated to SuperGrok-tier accounts — without one it drops to Tier C automatically, with the reason recorded in `ACCESS.md`.

## 13. Related work by the same author — reuse, cross-link, do not duplicate
- **upfront** (github.com/thanatchon36/upfront): already parses MCP servers, skills and instruction files across Claude Code / Codex / Gemini CLI / OpenCode to measure token cost. Reuse or port its parsers where sensible (respect its license); link it in README and Related Work. `harnessguard` stays independent (no hard dependency).
- **rulewarden**: deterministic enforcement of CLAUDE.md/AGENTS.md rules. Offer an optional integration point (a `HG-INJ` finding can suggest a rulewarden policy); cite in Related Work.
- **airmkit**: MAS AI-risk-management toolkit — use its control vocabulary for the RQ6 mapping so the governance checklist slots into it.
- Same conventions as those repos: MISSION-driven, software 50 / paper 50, Apache-2.0, PyPI, CI + Codecov, paper in-repo, LinkedIn-ready announcement.

## 14. Kickoff
Start in plan mode: produce a one-screen plan for Phase 0–1, create the task list, then execute. First commands: name availability check → scaffold → `harnessguard inventory` prototype against this machine → Phase 1 subagent fan-out. Report back with `reports/PHASE_0.md`.
