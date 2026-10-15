# Control rubric (final, Phase 2)

Machine-readable source: `matrix/rubric.yaml`. This page is generated from it.

## Scope and changes vs the draft

- D01-D15 unchanged in id and scope; wording of criteria made observable.
- Added: D16 Local service and control-plane exposure (proposed, optional): 34 incidents in taxonomy class T18 (about 10% of the set) concern unauthenticated local/network services, and no D01-D15 dimension covers them. It is excluded from the headline mean until evidence facts exist.
- Merge considered: D12 (policy) vs D11 kept separate: one is customer visibility, the other vendor-side collection.

## Scoring rules (apply to every dimension)

1. Use only facts in matrix/evidence/<harness>.json for the dimension. Facts labelled unverified are ignored.
2. A criterion counts as met only if supported by at least one fact labelled from-official-docs or verified-by-test. third-party-report facts may lower a score (a documented bypass of a claimed control) but cannot raise it.
3. Choose the highest score whose criteria are all met; each higher score includes the lower score's criteria.
4. If a criterion cannot be decided from the facts, score as if it is not met and record "not documented"; do not assume.
5. No facts at all for a dimension that applies -> proposed_score null with rationale "N/A (no access / not documented)", excluded from means, and counted in the coverage figure.
6. Every score cites the fact ids (ledger_id) that satisfy the highest criterion and the one that blocks the next.
7. Open vulnerabilities and incident history do NOT change the score (they are reported separately in RQ3); only documented controls do. Exception: a documented, patched bypass of a criterion is recorded in the rationale.

Generic scale:

- **0** - Control absent, or only an unsafe default that cannot be changed.
- **1** - Exists but opt-in, weak, easily bypassed or poorly documented.
- **2** - On by default but with documented gaps or no central enforcement.
- **3** - Strong safe default, centrally enforceable and documented.
- **N/A** - N/A, feature absent or no access.

## Tiers

- **Tier A/B.** Products you run: score the shipped product with default settings, as documented for the pinned version.
- **Tier C.** Runtimes/SDKs: score what the runtime itself provides and what its reference agent loop does by default; behaviour that the application developer must build (their own approvals, sandbox) scores as not provided (0 or 1 per the dimension) but is flagged "application responsibility". Compare tier C only with tier C; do not mix with A/B in one ranking. Dimensions that require a user-facing product (D04, D06, D09, D14 for open-source libraries) are N/A or documented per the tier_c notes.

## Weighting guidance

Report the unweighted mean of scored D01-D15 dimensions (N/A excluded), always together with the per-dimension heat map and the minimum.

Why:
- No empirical basis exists for dimension weights: incident counts measure what attackers and researchers examined, not residual risk.
- Weights are organisation-specific (a bank weights D11/D14 higher than a hobbyist); publishing one weighting would hide that choice.
- An unweighted mean is reproducible by readers who change nothing, and sensitivity can be shown openly.

Guardrails:
- Compute the mean only if at least 8 of 15 dimensions are scored; otherwise report "insufficient evidence".
- Report the number of scored dimensions next to every mean.
- Provide a sensitivity table with (a) equal weights, (b) weights proportional to incident_exposure below, (c) security-core subset D01-D05, D07, D08, D13, D14; ranking claims are made only where the ordering is unchanged under all three.
- Do not average tier C with tier A/B.

## Dimensions

"Exposure" = number of incidents (of 328) in the taxonomy classes the dimension addresses; classes overlap across dimensions so the figures are not additive; informational, for the sensitivity weighting only.

### D01 Permission model

*Question:* Does the harness ask before risky tool actions, and can the approve-everything path be restricted?  
*Addresses:* T03, T14, T01, T09 (exposure 92)

*Facts to extract:* Default mode and what it asks for (shell, file writes, network); Allow/deny rule syntax and precedence (does deny apply in every mode?); How approve-everything / YOLO / bypass is enabled (flag, user config, repo file) and whether it can be disabled by policy; Whether agent can edit its own permission settings.

| Score | Criteria |
|---|---|
| 0 | No per-action approval exists, or the only mode runs every tool call unattended with no way to restrict it. |
| 1 | Approval exists but any of: default mode runs shell or writes without asking; only coarse on/off; allow rules are documented as prefix/pattern matches with no deny precedence; approve-everything can be switched on from repository-controlled files or by the agent. |
| 2 | Default mode asks before shell commands and edits outside a safe set; user-level allow/deny rules exist; approve-everything requires a user-level flag or setting and cannot be enabled from repository files. |
| 3 | All of score 2 AND deny rules apply in every mode AND approve-everything cannot be enabled from repo or agent-writable files AND an administrator can disable it centrally (managed setting). |
| N/A | Never N/A for tier A/B. A harness with no tools that act on the system is out of scope, not N/A. |

*Tier C:* Score the permission primitives the runtime provides and the default of its reference agent loop. Interrupt/approval hooks that exist but are off by default = 1; on by default in the built-in loop = 2; 3 only if a platform policy can enforce them (managed runtimes). No approval primitive at all = 0.

### D02 Execution sandbox

*Question:* Is agent-executed code confined by an OS/container/VM boundary, and is that on by default?  
*Addresses:* T17, T03, T14, T11 (exposure 91)

*Facts to extract:* Sandbox technology (Seatbelt, bubblewrap, Landlock, container, VM) and platforms covered; Default on/off; Filesystem write scope and network scope under the sandbox; Whether the agent, repo files or a flag can weaken or disable it; fallback when the runtime is missing.

| Score | Criteria |
|---|---|
| 0 | No sandbox or isolation option; commands run with the user's full privileges. |
| 1 | A sandbox/container option exists but is opt-in, or covers only some tools, or silently falls back to unsandboxed execution, or is documented as not security-relevant. |
| 2 | Sandbox is on by default for shell execution on at least the main supported platform, with filesystem writes limited to the workspace. |
| 3 | All of score 2 AND filesystem and network are both confined by default AND neither the agent nor repo-controlled files can weaken it AND it can be enforced centrally; escape hatches need explicit user approval. |
| N/A | N/A only where the product has no code-execution or shell tool at all (documented). |

*Tier C:* Sandbox as a component: optional code-interpreter/container backend = 1; default isolation for built-in code execution = 2; provider-managed isolated runtime (microVM/container per session) with egress control = 3.

### D03 Network egress control

*Question:* Can outbound traffic from agent tools be limited to approved destinations?  
*Addresses:* T08, T17, T12, T09 (exposure 51)

*Facts to extract:* Domain allowlist/denylist for fetch and search tools and its default contents; Network policy for shell and sandbox (off, allowlist, proxy); Handling of DNS and pre-approved hosts; Browser tool network filter.

| Score | Criteria |
|---|---|
| 0 | No egress controls and network is unrestricted for every tool with no option. |
| 1 | Opt-in controls only, or controls cover the fetch tool but not shell/sandbox traffic; default allowlist contains hosts that accept arbitrary uploads. |
| 2 | Fetch/search tools ask or are domain-restricted by default and a sandbox network allowlist exists (possibly off by default); documented gaps remain (DNS, preapproved hosts). |
| 3 | All of score 2 AND default-deny network for sandboxed execution with a proxy-enforced allowlist AND allowlist is centrally manageable. |
| N/A | N/A only where no tool can reach the network (documented). |

*Tier C:* Library: egress hooks or URL validators provided = 1; built-in fetch tools with SSRF protection by default = 2; managed runtime with VPC/egress policy = 3.

### D04 Workspace and config trust

*Question:* Is repository-supplied configuration (hooks, MCP, settings, rules, plugins) ignored until the user consents?  
*Addresses:* T02, T01, T05 (exposure 73)

*Facts to extract:* Trust prompt existence and what it gates (hooks, MCP, env, settings, plugins, git helper operations); Behaviour in headless mode; Whether repo-level config can raise privileges; Persistence of trust decisions.

| Score | Criteria |
|---|---|
| 0 | Repository config is honoured silently and there is no trust concept. |
| 1 | A trust or approval step exists but misses at least one executable config class documented by the vendor, or can be skipped by a flag in interactive use, or is off by default. |
| 2 | A folder-trust or equivalent gate on by default covers hooks, MCP servers and project settings; headless mode is documented to skip it or to require a flag. |
| 3 | All of score 2 AND the gate covers every repo-controlled executable class including env/plugins/git helper operations AND headless requires an explicit flag AND admins can pre-approve or deny folders centrally. |
| N/A | N/A where the product reads no repository-level configuration (e.g. library that loads only caller-supplied objects). |

*Tier C:* Usually N/A for libraries. Score only if the runtime auto-loads workspace files (instructions, plugins, MCP definitions).

### D05 MCP governance

*Question:* How are MCP servers and tools approved, restricted and monitored for change?  
*Addresses:* T04, T02, T05 (exposure 71)

*Facts to extract:* Approval of project-scoped servers; Per-tool permissions and auto-approve behaviour; Managed allow/deny lists; Re-approval or change detection on tool definitions; OAuth token storage and server-identity checks.

| Score | Criteria |
|---|---|
| 0 | Project MCP servers start automatically and there are no allow/deny controls. |
| 1 | Servers need user setup, but any of: project-defined servers auto-approved, tool auto-approval is blanket, no managed policy, no change detection. |
| 2 | Project-scoped servers require approval by default and per-tool permissions exist; AND one of: managed allow/deny list, or definition-change detection. |
| 3 | Approval by default AND managed allow/deny lists AND change detection or pinning AND documented OAuth handling (tokens stored securely, scopes shown). |
| N/A | N/A if the harness has no MCP or equivalent tool-protocol support. |

*Tier C:* Libraries with an MCP client: approval hook for tool calls = 1; approval default-on plus header/auth handling documented = 2; platform allowlist for tools = 3.

### D06 Extensions, skills and plugins

*Question:* Is there vetting, scoping, pinning and policy control for installable extensions?  
*Addresses:* T05, T04, T06 (exposure 31)

*Facts to extract:* Marketplace and review/signing process; Pinning of versions/SHA; Install-time scripts and auto-update; Scope (user, project, org) and admin allowlist.

| Score | Criteria |
|---|---|
| 0 | Unrestricted installation of code from arbitrary sources that runs automatically, with no review. |
| 1 | Extension mechanism exists but without documented vetting or signing, or auto-updates by default, or project-supplied plugins load without prompt. |
| 2 | Installation needs explicit user action and sources can be scoped or pinned; some vetting or scanning documented. |
| 3 | Signed or verified publishing AND pinning AND admin allowlist/managed control AND no install-time script execution by default. |
| N/A | N/A if the harness has no extension, plugin or skill mechanism. |

*Tier C:* Skills/plugins loaded by the runtime from application code: treat application code as trusted; score only built-in marketplaces or registries.

### D07 Secrets and credential storage

*Question:* Are credentials and secrets stored, redacted and protected from the agent?  
*Addresses:* T07, T08, T13 (exposure 41)

*Facts to extract:* Where credentials are stored (OS keychain, file and mode); Redaction in transcripts, logs and telemetry; Protection of .env and secret files from agent reads; Token lifetime and scope; secrets in config files.

| Score | Criteria |
|---|---|
| 0 | Credentials stored world-readable or secrets written to logs with no control. |
| 1 | Plaintext credential file with mode unspecified or 0600 only; no documented redaction; no secret-file read protection. |
| 2 | OS keychain or verified 0600 file; documented log retention; some read-deny defaults or redaction. |
| 3 | Keychain by default AND redaction of secrets in transcripts/telemetry AND secret-file read protection by default AND short-lived or scoped tokens. |
| N/A | N/A only where the harness holds no credentials of its own (documented). |

*Tier C:* SDK: reads keys from environment/arguments = 1; secret-manager or managed identity integration documented = 2; managed identity with scoped tokens and redacted traces = 3.

### D08 Headless and CI safeguards

*Question:* Are non-interactive modes and official CI integrations safe by default against untrusted input?  
*Addresses:* T09, T01, T14 (exposure 25)

*Facts to extract:* Headless defaults (approvals, tools allowed); Official CI action or recipe: token permissions, actor/trigger restrictions; Documentation on untrusted input; Restrictions on repo config in CI.

| Score | Criteria |
|---|---|
| 0 | Headless mode runs with approvals disabled by default and no guidance. |
| 1 | Headless mode exists but defaults are permissive, or the official action has no trigger/actor restrictions or untrusted-input guidance. |
| 2 | Headless requires explicit tool/permission flags and the official action documents minimal permissions and actor checks. |
| 3 | All of score 2 AND the official action restricts who can trigger it by default AND uses read-only/minimal token by default AND documents prompt-injection handling and blocks PR-head config. |
| N/A | N/A if no non-interactive mode and no CI integration exists. |

*Tier C:* Runtimes: non-interactive is the normal mode, so score whether tool allowlists and human-in-the-loop interrupts are enforceable for unattended runs.

### D09 Persistent memory

*Question:* Is persistent memory scoped, visible, user-editable and controllable?  
*Addresses:* T10, T01 (exposure 17)

*Facts to extract:* Existence, scope (project/global/shared via VCS); Who writes (agent or user), notice on write; Visibility and editability; Disable/managed controls and content scanning.

| Score | Criteria |
|---|---|
| 0 | Agent-writable memory loaded into every session, shared or global, with no user visibility. |
| 1 | Memory exists, global or auto-written, viewable but with no confirmation or off-switch documented. |
| 2 | Memory is project-scoped plain files the user can inspect and edit, with a documented off switch. |
| 3 | Off by default or each write confirmed AND scoped AND content provenance/scanning AND centrally disableable. |
| N/A | N/A (feature absent) when the harness has no persistent agent memory; excluded from the mean and not rewarded. |

*Tier C:* Checkpoint stores and thread state count as memory only if replayed as model context across sessions; otherwise N/A.

### D10 Sub-agent and delegation isolation

*Question:* Do sub-agents and delegated harnesses inherit more authority than intended?  
*Addresses:* T11, T17, T03 (exposure 89)

*Facts to extract:* Permission and env inheritance; Per-agent tool restrictions; Isolation (worktree, container); Whether bypass mode propagates.

| Score | Criteria |
|---|---|
| 0 | Sub-agents receive full parent authority including bypass mode and environment with no restriction possible. |
| 1 | Sub-agents inherit permissions/environment; restriction is manual or undocumented. |
| 2 | Sub-agents inherit but per-agent tool restrictions exist and bypass mode does not silently propagate; optional worktree isolation. |
| 3 | Least-privilege defaults AND isolated worktree/sandbox per sub-agent AND no escalation path AND audit of delegated actions. |
| N/A | N/A if there is no sub-agent, task or delegation feature. |

*Tier C:* Multi-agent frameworks: score handoff/permission scoping between agents.

### D11 Audit logging

*Question:* Can an organisation reconstruct what the agent did?  
*Addresses:* T15, T16, T07 (exposure 17)

*Facts to extract:* Local transcripts and format; Structured tool-call logs; OpenTelemetry/central export; Enterprise audit log of admin and tool actions.

| Score | Criteria |
|---|---|
| 0 | No durable record of actions. |
| 1 | Local unstructured transcripts only. |
| 2 | Structured local logs of tool calls AND opt-in telemetry export (e.g. OpenTelemetry). |
| 3 | Structured logs AND central export or enterprise audit log covering tool actions and admin changes AND enforceable by policy. |
| N/A | Never N/A. |

*Tier C:* Tracing hooks included in the runtime = 2 if on by default or one setting away; requires third-party instrumentation = 1.

### D12 Telemetry and data retention

*Question:* Is vendor-side data collection controllable and documented? (Policy choice; not a vulnerability.)  
*Addresses:* T15, T07 (exposure 14)

*Facts to extract:* Telemetry default and opt-out; Prompt/code retention period; Training-use default; Residency and zero-retention options.

| Score | Criteria |
|---|---|
| 0 | Collection is mandatory with no opt-out, or content is used for training by default with no opt-out. |
| 1 | Opt-out exists but telemetry including prompts/code is on by default, or retention is undocumented. |
| 2 | Content-free telemetry by default or opt-out documented and honoured; retention documented; training use not default for the relevant plan. |
| 3 | No content telemetry by default AND documented bounded retention AND training opt-in only AND region/zero-retention option AND admin enforcement. |
| N/A | N/A if the software has no vendor service (fully local, no telemetry code) -- state which. |

*Tier C:* Hosted runtimes: score retention/training/residency terms of the managed service; self-hosted libraries with no telemetry are N/A.

*Note:* Scored separately from security vulnerabilities; never counted as an incident.

### D13 Distribution supply chain

*Question:* Can users verify what they install and control updates?  
*Addresses:* T06, T05, T04 (exposure 31)

*Facts to extract:* Install method and integrity (checksums, signatures); Provenance (Sigstore/SLSA), SBOM; Auto-update channel and pinning; Registry account protections.

| Score | Criteria |
|---|---|
| 0 | Unsigned installer or package with no integrity check and forced auto-update. |
| 1 | Registry install only (no provenance/signature) or curl-pipe-shell without checksum; auto-update default with no control. |
| 2 | Signed releases or checksums OR published provenance; update channel can be pinned or disabled. |
| 3 | Signed binaries AND provenance AND SBOM AND controllable update channel (pin/admin) AND hardened publishing (trusted publishing/2FA) documented. |
| N/A | Never N/A. |

*Tier C:* Libraries: PyPI/npm publication with trusted publishing or provenance = 2; signed + SBOM = 3.

### D14 Managed and enterprise policy

*Question:* Can an organisation enforce settings that users and repositories cannot override?  
*Addresses:* T03, T04, T05, T13, T15 (exposure 98)

*Facts to extract:* Managed settings file / MDM / admin console; Which settings are enforceable (permissions, MCP, plugins, telemetry, sandbox); Precedence over user/project settings.

| Score | Criteria |
|---|---|
| 0 | No administrator-enforced settings of any kind. |
| 1 | Org features exist but only as defaults users can override, or cover a small subset. |
| 2 | Admin-enforced settings for several security controls with documented precedence, but gaps (e.g. not covering MCP or plugins). |
| 3 | Managed policy with precedence over user and project settings covering permissions, MCP, plugins, sandbox and telemetry; documented and verified. |
| N/A | Not N/A: absence of central enforcement is a real gap and scores 0 for open-source tools with no enterprise offering. |

*Tier C:* Platform-managed runtimes: cloud IAM/policy enforcement counts as managed policy.

### D15 Vulnerability disclosure

*Question:* Does the vendor publish a security policy and advisories?  
*Addresses:* T19, T06 (exposure 58)

*Facts to extract:* SECURITY.md or security page; Published advisories (GHSA/CVE/CNA); Bug bounty or safe harbour; Security contact.

| Score | Criteria |
|---|---|
| 0 | No security contact or policy found. |
| 1 | Contact or policy exists but no advisories published. |
| 2 | Policy plus published advisories (GHSA/CVE) for fixed issues. |
| 3 | Policy AND consistent advisory/CVE issuance AND bounty or safe harbour AND advisory feed. |
| N/A | Never N/A. |

*Tier C:* Same criteria; for hosted runtimes use the vendor-wide programme page.

### D16 Local service and control-plane exposure (PROPOSED)

*Question:* Do local or network services of the harness require authentication and validate Origin/Host?  
*Addresses:* T18 (exposure 34)

*Facts to extract:* Servers the harness starts (HTTP/WebSocket/gateway) and bind address; Authentication, Origin and Host validation; Scope/authorization model for clients; Pairing flows.

| Score | Criteria |
|---|---|
| 0 | Control service reachable with no authentication, or exposed to the network by default. |
| 1 | Authentication exists but is optional, off by default, or lacks Origin/Host validation. |
| 2 | Authentication by default on all services bound to loopback; Origin/Host validation documented. |
| 3 | All of score 2 AND per-install secret or non-network transport AND scope-limited clients AND advisory history shows no repeated class of this flaw. |
| N/A | N/A where the harness starts no listening service. |

*Tier C:* Server-style runtimes (agent servers, platform APIs): authentication and tenant scoping on the API.

*Note:* Not in the draft D01-D15; no existing matrix/evidence/*.json carries D16 facts. Score null until facts are collected; exclude from the headline mean.

