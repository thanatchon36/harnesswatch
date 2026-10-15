# Governance checklist for AI coding-agent harnesses

Version 1.0 · 2026-10-15 · Answers RQ6. Generated from `brief/governance-checklist.yaml` by `scripts/gen_checklist_check.py --write`; edit the YAML, not this page.

> Interpretive synthesis by the harnesswatch authors. Framework mappings are the authors' crosswalk, not an endorsement by any framework owner, and not legal or regulatory advice.

## 1. Purpose

This checklist sets the minimum controls an organisation shall have in place before and while it uses
AI coding-agent harnesses: the runtime (CLI, IDE agent, CI action or agent SDK) that holds credentials,
runs shell commands, mounts MCP servers and reads repository configuration on the model's behalf. It is
written so that sections 3 to 7 can be adopted as policy text. "Shall" marks a requirement; a control
that a harness cannot technically meet requires a documented risk acceptance by the accountable owner.

## 2. Scope and how to read it

- **In scope:** coding-agent harnesses on developer endpoints, in dev containers and in CI; agent SDKs and
  runtimes used to build internal agents; MCP servers, skills, plugins and instruction files used with
  them; the suppliers of all of these.
- **Out of scope:** model selection and model-level evaluation, except where a harness control depends on it.
- **Regulated financial institutions.** Each control maps to the MAS Guidelines on AI Risk Management
  through the airmkit control vocabulary (AIRM-* ids). Per paragraph 1.8 as indexed in airmkit, MAS expects
  Sections 3-4 from 2027-10-07 and Sections 5-6 by 2028-10-07. The guidelines apply to AI agents.
  Mappings to NIST AI RMF, ISO/IEC 42001, OWASP and MITRE ATLAS support institutions under other regimes.
- **What a control addresses.** Each control says whether it manages a *vulnerability* (a defect the vendor
  fixes), a *design weakness* (an unsafe default or missing safeguard) or a *policy choice* (for example
  telemetry). These are managed differently and are not conflated.
- **Verification.** Where a `harnesswatch` command and HG rule exist they are given; otherwise the check is
  manual. A passing `harnesswatch` audit shows that the listed rules did not fire. It is not evidence that the
  control is met.
- **Mappings** are inherited from the threat classes each control cites, using `taxonomy/mappings.yaml`
  and `taxonomy/harness-threats.yaml`. Flags such as UNVERIFIED and THIRD-PARTY are carried over (see
  section 8). No framework identifier appears here that is not in those files.

### Context from the incident survey

`experiments/results/rq3_incidents.json` counts 323 harness incidents disclosed in 2025-2026
(verified primary source and an independent ID check). By kind: 292
vulnerabilities, 19 design weaknesses, 8 supply-chain
compromises, 3 cases of misuse and 1 operational incidents. Of
148 incidents with both dates known, 135
were fixed on or before public disclosure. Per-control incident counts below come from
the same file (`by_taxonomy_class`). Incident counts reflect what researchers examined, not residual
risk, and are not used to weight controls.

### Kinds of issue

- **vulnerability**: A defect the vendor fixes in code, usually with a CVE or GHSA. Managed by patching (GC-29).
- **design weakness**: Behaviour that works as specified or by default but is unsafe (permissive default, missing safeguard). Managed by configuration, compensating controls or choosing another product.
- **policy choice**: A decision with no right answer independent of the organisation (telemetry, retention, residency, acceptable autonomy). Managed by deciding explicitly and checking configuration matches.

### Control index

| ID | Stage | Control | Addresses | Threat classes | HG rules |
|---|---|---|---|---|---|
| GC-01 | Before adoption | Harness inventory and approval register | policy-choice, design-weakness | T05, T11, T16 | manual |
| GC-02 | Before adoption | Security evaluation before approval | design-weakness, vulnerability | T03, T17, T19 | HG-SUP-002 |
| GC-03 | Before adoption | Verify vendor claims against observed behaviour (closed-source harnesses) | policy-choice, design-weakness | T15, T02, T17 | manual |
| GC-04 | Before adoption | Pre-adoption prompt-injection resilience test with inert canaries | design-weakness | T01, T08 | manual |
| GC-05 | Before adoption | Telemetry, data residency and retention as a documented policy decision | policy-choice | T15 | HG-TEL-001 |
| GC-06 | Configuration baseline | Managed permission mode and bypass lock | design-weakness | T03, T14 | HG-PERM-001 |
| GC-07 | Configuration baseline | Narrow tool allowlists and deny rules | design-weakness | T03, T14, T07 | HG-PERM-002, HG-PERM-003 |
| GC-08 | Configuration baseline | Repository configuration is untrusted until reviewed (hooks, settings, env) | vulnerability, design-weakness | T02 | HG-HOOK-001, HG-HOOK-002, HG-SEC-003 |
| GC-09 | Configuration baseline | No auto-approval of repository-declared MCP servers | design-weakness | T04, T02 | HG-MCP-005, HG-MCP-006 |
| GC-10 | Configuration baseline | MCP server pinning, provenance and change review | design-weakness, vulnerability | T04, T06 | HG-MCP-001, HG-MCP-004 |
| GC-11 | Configuration baseline | MCP transport security and authentication | design-weakness | T04, T07 | HG-MCP-002, HG-MCP-003 |
| GC-12 | Configuration baseline | Instruction-file review | design-weakness | T01, T05 | HG-INJ-001, HG-INJ-002, HG-INJ-003 |
| GC-13 | Configuration baseline | Skills, plugins and extensions from approved sources only | design-weakness | T05, T06 | HG-INJ-001, HG-INJ-002 |
| GC-14 | Configuration baseline | Credentials outside harness configuration files | design-weakness | T07 | HG-SEC-003, HG-MCP-003 |
| GC-15 | Configuration baseline | Secrets in state directories, file modes and transcript retention | design-weakness | T07, T15 | HG-SEC-001, HG-SEC-002 |
| GC-16 | Configuration baseline | Execution sandbox for agent tools, including browser and computer use | design-weakness, vulnerability | T17, T12, T14 | manual |
| GC-17 | Configuration baseline | Network egress allowlist | design-weakness | T08, T12 | HG-NET-001 |
| GC-18 | Configuration baseline | Persistent memory | design-weakness | T10 | HG-MEM-001 |
| GC-19 | Configuration baseline | Sub-agent and delegation restrictions | design-weakness | T11, T03 | HG-SUB-001 |
| GC-20 | Configuration baseline | Local agent services and control endpoints | vulnerability, design-weakness | T18 | manual |
| GC-21 | Runtime and CI | Headless agents in CI: no untrusted triggers (pwn-request pattern) | design-weakness | T09, T01 | HG-CI-001 |
| GC-22 | Runtime and CI | Least-privilege GITHUB_TOKEN and agent identities | design-weakness | T09, T14 | HG-CI-002 |
| GC-23 | Runtime and CI | Harness-configuration gate on every change | design-weakness, vulnerability | T02, T04, T01 | HG-PERM-001, HG-PERM-002, HG-HOOK-001, HG-HOOK-002, HG-MCP-001, HG-MCP-005, HG-MCP-006, HG-INJ-001, HG-INJ-002, HG-INJ-003, HG-CI-001, HG-CI-002 |
| GC-24 | Runtime and CI | Human approval and stop control for irreversible actions | design-weakness | T14 | HG-PERM-003, HG-CI-002 |
| GC-25 | Monitoring and incident response | Agent activity logging and audit trail | policy-choice, design-weakness | T15, T11, T09 | manual |
| GC-26 | Monitoring and incident response | Continuous configuration posture monitoring | design-weakness, vulnerability | T03, T07, T06 | HG-PERM-001, HG-PERM-002, HG-PERM-003, HG-SEC-001, HG-SEC-002, HG-SEC-003, HG-SUP-001, HG-SUP-002, HG-MCP-001, HG-MCP-003 |
| GC-27 | Monitoring and incident response | Harness-specific incident response | vulnerability, design-weakness, policy-choice | T16, T07, T14 | HG-SEC-001, HG-SEC-002 |
| GC-28 | Supplier management | Verified installers and a controlled update channel | design-weakness | T06 | HG-SUP-001 |
| GC-29 | Supplier management | SBOM, advisories and patch deadlines | vulnerability | T06, T19 | HG-SUP-002 |
| GC-30 | Supplier management | Supplier terms: transparency, change notice and disclosure | policy-choice | T15, T06 | manual |

## 3. Before adoption (procurement and evaluation)

### GC-01 Harness inventory and approval register

**Control.** The organisation shall maintain a register of every agent harness, IDE agent, agent SDK, MCP server, skill and plugin approved for use, recording for each the owner, version, permission mode, tools and MCP servers it can reach, sub-agents it can start, and the data classes it may process. Harnesses not on the register shall not be used with organisational code, data or credentials.

**Addresses.** policy choice, design weakness.

**Why.** Unregistered harnesses and extensions are a shadow-AI surface: they hold developer credentials and run shell commands outside any review. The register is also where the per-agent attributes (tools, guardrails, delegation) that later controls depend on are recorded.

- Threat classes: T05 Skills, plugins, extensions and marketplaces (2 counted incidents); T11 Sub-agent and cross-harness trust propagation (2 counted incidents); T16 Offensive misuse of harnesses by attackers (3 counted incidents)
- Root causes: RC5 Package, extension or update-channel compromise or integrity failure; RC12 Adversarial use of a legitimate capability (no product defect)
- Rubric dimensions: D14 Managed and enterprise policy; D06 Extensions, skills and plugins; D10 Sub-agent and delegation isolation

**How to verify.**

```bash
harnesswatch inventory --json .
harnesswatch audit supply --sbom harness-sbom.cdx.json -f json -o supply.json
```

- HG rules: none; manual check
- Manual: Run the inventory on a sample of developer endpoints, build agents and dev containers and reconcile the detected harnesses, state directories and repository harness files with the register. Any detected harness or MCP server absent from the register is a finding.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, GOVERN 3.2, MAP 3.5, MANAGE 2.4, MANAGE 4.3, MANAGE 2.3, GOVERN 4.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Human-AI Configuration, Information Security (section numbers UNVERIFIED: 2.12, 2.7, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.10.3 Suppliers, A.4.4 Tooling resources, A.10.2 Allocation of responsibilities, A.6.1.3 Processes for responsible design and development, A.6.2.6 AI system operation and monitoring, A.8.4 Communication of incidents, A.9.2 Processes for responsible use of AI systems, A.3.3 Reporting of concerns; clauses 8.3, 10.2 |
| OWASP Top 10 for LLM Applications 2025 | LLM03, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04, ASI03, ASI07, ASI08, ASI10 |
| OWASP MCP Top 10 (UNSTABLE) | MCP04 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0010.005, AML.T0115.002, AML.T0011.001, AML.T0111, AML.T0118, AML.T0118.001, AML.T0053, AML.T0124, AML.T0116, AML.T0117 |
| MAS AIRM paragraphs | 5.11, 5.16, 4.8, 5.23, 4.4 |
| airmkit (MAS AIRM) | `AIRM-5.16-THIRD-PARTY-COMPONENTS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-4.4-FN22-SHADOW-AI`, `AIRM-4.8-FN25-AGENT-ATTRIBUTES`, `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.23-AGENT-TRACE-MONITORING`, `AIRM-5.23-INCIDENT-MANAGEMENT` |

### GC-02 Security evaluation before approval

**Control.** Before a harness is approved, the organisation shall assess it against the control dimensions D01-D16 of the harnesswatch rubric (permission model, sandbox, egress, config trust, MCP governance, extensions, secrets, headless/CI, memory, delegation, audit logging, telemetry, distribution, managed policy, vulnerability disclosure, local service exposure), record the evidence and its label for each score, and document accepted residual risk. A harness without administrator-enforceable settings (D14) or without a published security policy and advisories (D15) shall require a documented risk acceptance.

**Addresses.** design weakness, vulnerability.

**Why.** Harnesses differ in which controls exist, which are on by default and which an administrator can enforce. A missing safeguard or permissive default (RC6) is a design weakness that will not be fixed by patching; it has to be found at procurement. For runtimes and SDKs (tier C) approvals, sandboxing and logging are often the application's responsibility and must be built by the adopter.

- Threat classes: T03 Permission-model weaknesses and approval bypass (74 counted incidents); T17 Execution sandbox and isolation escape (22 counted incidents); T19 Conventional software defects in agent runtimes and SDKs (45 counted incidents)
- Root causes: RC6 Insecure default, missing safeguard or over-privileged mode by design; RC8 Isolation boundary escape or weak isolation fallback; RC10 Conventional implementation defect not gating an agent capability
- Rubric dimensions: D01 Permission model; D02 Execution sandbox; D14 Managed and enterprise policy; D15 Vulnerability disclosure; D16 Local service and control-plane exposure (PROPOSED)

**How to verify.**

```bash
harnesswatch audit supply --online -f json -o supply.json
```

- HG rules: `HG-SUP-002`
- Manual: Score the harness with matrix/rubric.md using only facts labelled from-official-docs or verified-by-test; record N/A where there is no access. Confirm the vendor publishes a security contact and advisories. Keep the scored evidence with the approval record.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | GOVERN 3.2, MAP 3.5, MEASURE 2.6, MANAGE 2.4, MEASURE 2.7, MANAGE 1.3, MANAGE 4.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Human-AI Configuration, Information Security (section numbers UNVERIFIED: 2.7, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems, A.9.3 Objectives for responsible use of AI systems, A.9.4 Intended use of the AI system, A.6.1.3 Processes for responsible design and development, A.4.5 System and computing resources, A.6.2.4 AI system verification and validation, A.6.2.7 AI system technical documentation; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM06, LLM05, LLM10 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI02, ASI03, ASI05 |
| OWASP MCP Top 10 (UNSTABLE) | MCP02, MCP05 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0053, AML.T0050, AML.T0102, AML.T0105, AML.T0097, AML.T0049, AML.T0029 |
| MAS AIRM paragraphs | 5.9, 5.16, 5.22, 6.3, 5.14, 5.25 |
| airmkit (MAS AIRM) | `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.16-ACCESS-CONTROL`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.9-DESIGN-FOR-OVERSIGHT`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-6.3-INFRASTRUCTURE`, `AIRM-5.14-TESTING-APPROACHES`, `AIRM-5.25-CHANGE-CONTROL` |

### GC-03 Verify vendor claims against observed behaviour (closed-source harnesses)

**Control.** For any closed-source harness, the organisation shall verify, before approval and after each major version, that the vendor's documented network destinations, configuration-trust behaviour, sandboxing and credential storage match what the client does when run in an isolated environment with synthetic data. Undocumented destinations or behaviours shall be raised with the supplier and resolved or risk-accepted before production use.

**Addresses.** policy choice, design weakness.

**Why.** Without source access, documentation is the only basis for the control assessment. A black-box observation (hosts contacted, files written and their modes, whether repository configuration executes before trust is granted) checks the documentation. Differences are usually documentation gaps or policy choices, not vulnerabilities, and should be labelled as such.

- Threat classes: T15 Telemetry, data residency, retention and audit gaps (1 counted incident); T02 Repository and workspace configuration as code execution (52 counted incidents); T17 Execution sandbox and isolation escape (22 counted incidents)
- Root causes: RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself; RC2 Workspace, repository or agent-written content executed or honoured before or without consent; RC8 Isolation boundary escape or weak isolation fallback
- Rubric dimensions: D12 Telemetry and data retention; D04 Workspace and config trust; D02 Execution sandbox; D07 Secrets and credential storage

**How to verify.**

```bash
harnesswatch observe <harness-id> --image <image-with-harness> --repo <synthetic-repo> -o observe-<harness-id>.json -- <harness command>
```

- HG rules: none; manual check
- Manual: Compare the hosts, file modes and pre-trust execution recorded in the observe report with the vendor's documented claims, one row per claim (format of matrix/claims_vs_observed.csv: claim, source, observed, method, verdict). Use only synthetic credentials and data; observe records metadata only and does not intercept TLS.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.10, MEASURE 2.8, GOVERN 1.1, MANAGE 4.3, MEASURE 2.7, MANAGE 1.3, MAP 4.2, MEASURE 2.6 |
| NIST AI 600-1 (Generative AI Profile) risks | Data Privacy, Intellectual Property, Information Security (section numbers UNVERIFIED: 2.4, 2.10, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.4.3 Data resources, A.7.3 Acquisition of data, A.8.2 System documentation and information for users, A.6.2.8 AI system recording of event logs, A.6.1.3 Processes for responsible design and development, A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems, A.4.5 System and computing resources; clauses 7.5, 9.1, 6.1.2, 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM02, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI05, ASI02 |
| OWASP MCP Top 10 (UNSTABLE) | MCP08, MCP09 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0081, AML.T0050, AML.T0053, AML.T0105, AML.T0097 |
| MAS AIRM paragraphs | 5.4, 5.11, 5.23, 5.16, 5.22, 6.3 |
| airmkit (MAS AIRM) | `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.4-DATA-CLASSIFICATION`, `AIRM-5.11-THIRD-PARTY-TRANSPARENCY`, `AIRM-5.23-GENAI-LOGGING`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-6.3-INFRASTRUCTURE` |

### GC-04 Pre-adoption prompt-injection resilience test with inert canaries

**Control.** Before approval, and when the harness, model or permission mode changes materially, the organisation shall test the harness in its intended permission mode against indirect prompt injection placed in repository content and tool output, using inert canaries in a disposable environment, and shall record the result with its confidence interval and number of runs.

**Addresses.** design weakness.

**Why.** Instruction-following on attacker-written text is a property of the model and harness together, not a defect that a patch removes. A measured baseline shows how much the permission mode and egress controls have to carry. Results apply only to the tested harness, model, mode and version.

- Threat classes: T01 Indirect prompt injection via workspace and retrieved content (14 counted incidents); T08 Data exfiltration channels (23 counted incidents)
- Root causes: RC1 Untrusted content treated as instructions (no distinct control failure); RC9 Output-rendering or automatic-fetch feature acts as an exfiltration channel
- Rubric dimensions: D01 Permission model; D03 Network egress control

**How to verify.**

```bash
harnesswatch bench list
harnesswatch bench run --out bench-results/<date> --harness <adapter-id> --mode default --mode auto -n 5
harnesswatch bench report bench-results/<date>
```

- HG rules: none; manual check
- Manual: Review summary.json for per-cell canary rates with Wilson 95% confidence intervals; do not report cells with fewer than 3 runs. Harnesses without a bench adapter need one written or a manual test with the same scenarios.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MEASURE 2.6, MANAGE 1.3, MANAGE 2.3, MEASURE 2.10 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Data Privacy (section numbers UNVERIFIED: 2.9, 2.4) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.1.3 Processes for responsible design and development, A.6.2.4 AI system verification and validation, A.6.2.6 AI system operation and monitoring, A.4.3 Data resources, A.9.2 Processes for responsible use of AI systems; clauses 6.1.2, 8.2, 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM01, LLM02, LLM05 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI01, ASI02 |
| OWASP MCP Top 10 (UNSTABLE) | MCP06, MCP10 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0051.001, AML.T0093, AML.T0068, AML.T0094, AML.T0086, AML.T0077, AML.T0025, AML.T0057 |
| MAS AIRM paragraphs | 5.15, 5.16, 5.22, 5.4 |
| airmkit (MAS AIRM) | `AIRM-5.15-GUARDRAIL-EFFECTIVENESS`, `AIRM-5.15-GENAI-FAILURE-MODES`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-5.4-DATA-SECURITY`, `AIRM-5.4-DATA-PRIVACY` |

### GC-05 Telemetry, data residency and retention as a documented policy decision

**Control.** For each approved harness and model endpoint, the organisation shall decide and document which data classes may be sent to which vendor or endpoint, where it is processed and stored, how long it is retained, and whether usage telemetry, prompt logging and vendor data sharing are enabled. The decision shall be enforced through managed settings or network controls where the harness supports it.

**Addresses.** policy choice.

**Why.** Telemetry and vendor-side retention are policy choices of the vendor, not vulnerabilities. Whether they are acceptable depends on the organisation's data classification, outsourcing and residency obligations, so the organisation has to make the choice explicitly and check that configuration matches it.

- Threat classes: T15 Telemetry, data residency, retention and audit gaps (1 counted incident)
- Root causes: RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself
- Rubric dimensions: D12 Telemetry and data retention; D14 Managed and enterprise policy

**How to verify.**

```bash
harnesswatch audit config . -f json -o config.json
```

- HG rules: `HG-TEL-001`
- Manual: Review the vendor's data-use, retention and region terms against the data-classification policy. HG-TEL-001 is informational: it reports telemetry or prompt logging explicitly enabled in configuration, not whether the organisation's decision is met.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.10, MEASURE 2.8, GOVERN 1.1, MANAGE 4.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Data Privacy, Intellectual Property (section numbers UNVERIFIED: 2.4, 2.10) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.4.3 Data resources, A.7.3 Acquisition of data, A.8.2 System documentation and information for users, A.6.2.8 AI system recording of event logs; clauses 7.5, 9.1 |
| OWASP Top 10 for LLM Applications 2025 | LLM02 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | none mapped in taxonomy/ |
| OWASP MCP Top 10 (UNSTABLE) | MCP08 |
| MITRE ATLAS techniques (release 2026.09) | none mapped in taxonomy/ |
| MAS AIRM paragraphs | 5.4, 5.11, 5.23 |
| airmkit (MAS AIRM) | `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.4-DATA-CLASSIFICATION`, `AIRM-5.11-THIRD-PARTY-TRANSPARENCY`, `AIRM-5.23-GENAI-LOGGING` |

## 4. Configuration baseline

### GC-06 Managed permission mode and bypass lock

**Control.** Where the harness supports administrator-managed settings, the organisation shall deploy them to every managed endpoint so that the default permission mode asks before shell commands, file writes outside the workspace and network tools, and so that approve-everything modes (bypass, YOLO, full-auto, never-ask) cannot be enabled by users or repositories. Bypass modes are permitted only in disposable environments that hold no organisational credentials.

**Addresses.** design weakness.

**Why.** In approve-everything mode every successful injection reaches the shell directly. Settings that users or a committed repository file can change do not constitute a control; managed settings with precedence over user and project scope do. Examples: Claude Code permissions.disableBypassPermissionsMode, Gemini CLI security.disableYoloMode, Codex requirements.toml.

- Threat classes: T03 Permission-model weaknesses and approval bypass (74 counted incidents); T14 Destructive and unsafe autonomous actions (no counted incidents)
- Root causes: RC6 Insecure default, missing safeguard or over-privileged mode by design; RC11 Autonomous action exceeding user intent without enforced guardrail
- Rubric dimensions: D01 Permission model; D14 Managed and enterprise policy

**How to verify.**

```bash
harnesswatch audit config . --user -f json -o config.json
```

- HG rules: `HG-PERM-001`
- Manual: Confirm the managed settings file (e.g. /etc/claude-code/managed-settings.json) is present, root-owned and not user-writable, and contains the bypass lock. Then try to start the harness in bypass mode as an ordinary user and confirm it refuses.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | GOVERN 3.2, MAP 3.5, MEASURE 2.6, MANAGE 2.4, MANAGE 2.3, MANAGE 1.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Human-AI Configuration, Information Security (section numbers UNVERIFIED: 2.7, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems, A.9.3 Objectives for responsible use of AI systems, A.9.4 Intended use of the AI system, A.5.4 Assessing impacts on individuals or groups, A.6.2.6 AI system operation and monitoring; clauses 8.3, 6.1.4, 8.4 |
| OWASP Top 10 for LLM Applications 2025 | LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI02, ASI03, ASI08 |
| OWASP MCP Top 10 (UNSTABLE) | MCP02 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0053, AML.T0050, AML.T0102, AML.T0101, AML.T0048.000 |
| MAS AIRM paragraphs | 5.9, 5.16, 5.2, 5.3 |
| airmkit (MAS AIRM) | `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.16-ACCESS-CONTROL`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.9-DESIGN-FOR-OVERSIGHT`, `AIRM-5.3-KILL-SWITCH`, `AIRM-5.3-CONTINGENCY-PLAN`, `AIRM-5.2-FN28-PILOT-GUARDRAILS` |

### GC-07 Narrow tool allowlists and deny rules

**Control.** Tool allowlists shall name specific commands with fixed arguments; whole-tool or wildcard entries for shells, interpreters, network tools, package managers or git with arbitrary arguments shall not be allowed without a prompt. Where any auto-approval is in force, deny rules shall cover recursive deletion, history-rewriting pushes and reads of credential files.

**Addresses.** design weakness.

**Why.** An allowlist entry such as Bash(*) or Bash(git *) is equivalent to auto-approve for that tool (git subcommands can run arbitrary programs). Deny rules are the last guard when auto-approval is on, but they are bypassable and do not replace a sandbox.

- Threat classes: T03 Permission-model weaknesses and approval bypass (74 counted incidents); T14 Destructive and unsafe autonomous actions (no counted incidents); T07 Secret exposure and residue (12 counted incidents)
- Root causes: RC6 Insecure default, missing safeguard or over-privileged mode by design; RC3 Validation, parsing or authorization logic flaw in a check that gates an agent capability; RC11 Autonomous action exceeding user intent without enforced guardrail
- Rubric dimensions: D01 Permission model

**How to verify.**

```bash
harnesswatch audit config . --user -f json -o config.json
```

- HG rules: `HG-PERM-002`, `HG-PERM-003`

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | GOVERN 3.2, MAP 3.5, MEASURE 2.6, MANAGE 2.4, MANAGE 2.3, MANAGE 1.3, MEASURE 2.10, MEASURE 2.7, GOVERN 1.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Human-AI Configuration, Information Security, Data Privacy (section numbers UNVERIFIED: 2.7, 2.9, 2.4) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems, A.9.3 Objectives for responsible use of AI systems, A.9.4 Intended use of the AI system, A.5.4 Assessing impacts on individuals or groups, A.6.2.6 AI system operation and monitoring, A.4.3 Data resources, A.4.5 System and computing resources, A.6.2.8 AI system recording of event logs; clauses 8.3, 6.1.4, 8.4 |
| OWASP Top 10 for LLM Applications 2025 | LLM06, LLM02 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI02, ASI03, ASI08 |
| OWASP MCP Top 10 (UNSTABLE) | MCP02, MCP01 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0053, AML.T0050, AML.T0102, AML.T0101, AML.T0048.000, AML.T0055, AML.T0083, AML.T0037, AML.T0098 |
| MAS AIRM paragraphs | 5.9, 5.16, 5.2, 5.3, 5.4 |
| airmkit (MAS AIRM) | `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.16-ACCESS-CONTROL`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.9-DESIGN-FOR-OVERSIGHT`, `AIRM-5.3-KILL-SWITCH`, `AIRM-5.3-CONTINGENCY-PLAN`, `AIRM-5.2-FN28-PILOT-GUARDRAILS`, `AIRM-5.4-DATA-SECURITY`, `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.16-SECURITY-CONTROLS` |

### GC-08 Repository configuration is untrusted until reviewed (hooks, settings, env)

**Control.** Harness configuration committed to a repository (hooks, project settings, environment blocks, sandbox or permission overrides) shall be treated as executable code: it shall not take effect before the user grants workspace trust, shall be changed only through reviewed pull requests with designated code owners, and shall not set model endpoints, credentials or network settings. Hooks shall be defined in user-level or managed settings, or restricted to managed hooks where the harness supports it.

**Addresses.** vulnerability, design weakness.

**Why.** Opening a repository is enough to run its hooks or start its configured processes in harnesses that honour project configuration before, or without, a trust prompt; several 2025-2026 CVEs were pre-trust execution of exactly this surface. Headless modes often do not prompt at all. A project environment block that redirects the model endpoint sends prompts and code to a third party.

- Threat classes: T02 Repository and workspace configuration as code execution (52 counted incidents)
- Root causes: RC2 Workspace, repository or agent-written content executed or honoured before or without consent
- Rubric dimensions: D04 Workspace and config trust; D14 Managed and enterprise policy

**How to verify.**

```bash
harnesswatch audit config . --no-user -f sarif -o config.sarif
```

- HG rules: `HG-HOOK-001`, `HG-HOOK-002`, `HG-SEC-003`
- Manual: Check that CODEOWNERS covers .claude/, .cursor/, .codex/, .gemini/, .kiro/, .vscode/, .mcp.json and AGENTS.md-type files, and review any env block in project settings for endpoint or proxy overrides (not covered by an HG rule).

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MANAGE 1.3, MAP 4.2 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security (section numbers UNVERIFIED: 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.1.3 Processes for responsible design and development, A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems; clauses 6.1.2, 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI05, ASI02 |
| OWASP MCP Top 10 (UNSTABLE) | MCP09 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0081, AML.T0050, AML.T0053 |
| MAS AIRM paragraphs | 5.16, 5.22 |
| airmkit (MAS AIRM) | `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.22-SECURITY-REVIEW` |

### GC-09 No auto-approval of repository-declared MCP servers

**Control.** MCP servers declared in a repository file shall not be started or have their tools called without per-server approval. Settings that enable all project MCP servers, mark servers as trusted or auto-approve their tools shall not be used; where the harness supports a managed MCP allowlist, only servers on the organisation's approved list shall be permitted.

**Addresses.** design weakness.

**Why.** A committed MCP declaration asks every cloner's harness to start a local process. Combined with an enable-all or trust setting in the same repository, cloning and opening the repository runs attacker-chosen commands (the CurXecute / MCPoison class).

- Threat classes: T04 MCP trust: tool poisoning, rug pulls, OAuth and server identity (15 counted incidents); T02 Repository and workspace configuration as code execution (52 counted incidents)
- Root causes: RC2 Workspace, repository or agent-written content executed or honoured before or without consent; RC6 Insecure default, missing safeguard or over-privileged mode by design
- Rubric dimensions: D05 MCP governance; D04 Workspace and config trust; D14 Managed and enterprise policy

**How to verify.**

```bash
harnesswatch audit mcp . --user -f json -o mcp.json
```

- HG rules: `HG-MCP-005`, `HG-MCP-006`
- Manual: Confirm the managed MCP policy (e.g. Claude Code allowedMcpServers / allowManagedMcpServersOnly) matches the register (GC-01).

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, MEASURE 2.7, MANAGE 1.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Information Security (section numbers UNVERIFIED: 2.12, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.10.2 Allocation of responsibilities, A.10.3 Suppliers, A.4.4 Tooling resources, A.6.1.3 Processes for responsible design and development, A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems; clauses 8.3, 6.1.2 |
| OWASP Top 10 for LLM Applications 2025 | LLM03, LLM01, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04, ASI02, ASI05 |
| OWASP MCP Top 10 (UNSTABLE) | MCP03, MCP04, MCP05, MCP07, MCP09, MCP10 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0110, AML.T0109, AML.T0011.002, AML.T0010.005, AML.T0099, AML.T0131, AML.T0081, AML.T0050, AML.T0053 |
| MAS AIRM paragraphs | 5.10, 5.11, 5.16, 5.25, 5.22 |
| airmkit (MAS AIRM) | `AIRM-5.16-THIRD-PARTY-COMPONENTS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.25-CHANGE-CONTROL`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.22-SECURITY-REVIEW` |

### GC-10 MCP server pinning, provenance and change review

**Control.** Every approved MCP server shall be pinned to an exact version or content digest, installed from an approved source or internal mirror, and re-reviewed (including its tool descriptions) before any version change. Launch commands that fetch the latest package at each start shall not be used.

**Addresses.** design weakness, vulnerability.

**Why.** Unpinned launchers (npx -y, uvx, mutable image tags) run whatever the registry serves at each start, so a compromised maintainer account or malicious update runs with the agent's privileges. Tool descriptions are placed in the model context verbatim and can change after approval (rug pull).

- Threat classes: T04 MCP trust: tool poisoning, rug pulls, OAuth and server identity (15 counted incidents); T06 Harness distribution and dependency supply chain (9 counted incidents)
- Root causes: RC5 Package, extension or update-channel compromise or integrity failure
- Rubric dimensions: D05 MCP governance; D13 Distribution supply chain

**How to verify.**

```bash
harnesswatch audit mcp . --user -f json -o mcp.json
harnesswatch audit mcp . --tools-json <saved-tools-list.json> -f json -o mcp-tools.json
```

- HG rules: `HG-MCP-001`, `HG-MCP-004`
- Manual: Save the server's tools/list response at approval and on each update and diff it; harnesswatch never launches MCP servers itself.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, GOVERN 6.2 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Information Security (section numbers UNVERIFIED: 2.12, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.10.2 Allocation of responsibilities, A.10.3 Suppliers, A.4.4 Tooling resources, A.6.2.5 AI system deployment; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM03, LLM01, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04, ASI02 |
| OWASP MCP Top 10 (UNSTABLE) | MCP03, MCP04, MCP05, MCP07, MCP09, MCP10 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0110, AML.T0109, AML.T0011.002, AML.T0010.005, AML.T0099, AML.T0131, AML.T0010.001, AML.T0011.001, AML.T0010, AML.T0083 |
| MAS AIRM paragraphs | 5.10, 5.11, 5.16, 5.25 |
| airmkit (MAS AIRM) | `AIRM-5.16-THIRD-PARTY-COMPONENTS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.25-CHANGE-CONTROL`, `AIRM-5.11-CHANGE-NOTIFICATION`, `AIRM-5.10-THIRD-PARTY-TESTING` |

### GC-11 MCP transport security and authentication

**Control.** Remote MCP servers shall be reached only over TLS with authentication (OAuth 2.1 or a token supplied from an environment variable or secret store), and only on hosts the organisation trusts. Credentials shall not be written as literal values in MCP configuration.

**Addresses.** design weakness.

**Why.** Plaintext transport exposes tool calls, results and tokens on the network path. Literal secrets in MCP configuration are stored in plaintext, copied into backups and, in project files, committed for everyone.

- Threat classes: T04 MCP trust: tool poisoning, rug pulls, OAuth and server identity (15 counted incidents); T07 Secret exposure and residue (12 counted incidents)
- Root causes: RC4 Missing authentication or origin/Host validation on a local or network control endpoint; RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself
- Rubric dimensions: D05 MCP governance; D07 Secrets and credential storage

**How to verify.**

```bash
harnesswatch audit mcp . --user -f json -o mcp.json
```

- HG rules: `HG-MCP-002`, `HG-MCP-003`

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, MEASURE 2.10, MEASURE 2.7, GOVERN 1.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Information Security, Data Privacy (section numbers UNVERIFIED: 2.12, 2.9, 2.4) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.10.2 Allocation of responsibilities, A.10.3 Suppliers, A.4.4 Tooling resources, A.4.3 Data resources, A.4.5 System and computing resources, A.6.2.8 AI system recording of event logs; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM03, LLM01, LLM06, LLM02 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04, ASI02, ASI03 |
| OWASP MCP Top 10 (UNSTABLE) | MCP03, MCP04, MCP05, MCP07, MCP09, MCP10, MCP01 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0110, AML.T0109, AML.T0011.002, AML.T0010.005, AML.T0099, AML.T0131, AML.T0055, AML.T0083, AML.T0037, AML.T0098 |
| MAS AIRM paragraphs | 5.10, 5.11, 5.16, 5.25, 5.4 |
| airmkit (MAS AIRM) | `AIRM-5.16-THIRD-PARTY-COMPONENTS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.25-CHANGE-CONTROL`, `AIRM-5.4-DATA-SECURITY`, `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.16-SECURITY-CONTROLS` |

### GC-12 Instruction-file review

**Control.** Instruction, rules and skill files that harnesses load automatically (AGENTS.md, CLAUDE.md, GEMINI.md, .cursor/rules, copilot-instructions.md, SKILL.md and equivalents) shall be reviewed like code, with diffs that reveal hidden and confusable Unicode, and shall not import or tell the agent to fetch instructions from remote URLs.

**Addresses.** design weakness.

**Why.** These files are placed in the model context verbatim. Hidden characters let an author conceal instructions from reviewers ('rules file backdoor'), and remote imports make agent behaviour depend on content that can change after review. Injection that steers an agent behaving as designed (RC1) is not fixed by patching the harness.

- Threat classes: T01 Indirect prompt injection via workspace and retrieved content (14 counted incidents); T05 Skills, plugins, extensions and marketplaces (2 counted incidents)
- Root causes: RC1 Untrusted content treated as instructions (no distinct control failure)
- Rubric dimensions: D04 Workspace and config trust; D06 Extensions, skills and plugins

**How to verify.**

```bash
harnesswatch audit instructions . -f sarif -o instructions.sarif
```

- HG rules: `HG-INJ-001`, `HG-INJ-002`, `HG-INJ-003`
- Manual: HG-INJ-002 is a scored heuristic; reviewers decide on flagged lines. A deterministic instruction-file policy checker (e.g. rulewarden) can complement it.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MEASURE 2.6, MANAGE 1.3, MANAGE 2.3, MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Value Chain and Component Integration (section numbers UNVERIFIED: 2.9, 2.12) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.1.3 Processes for responsible design and development, A.6.2.4 AI system verification and validation, A.6.2.6 AI system operation and monitoring, A.10.3 Suppliers, A.4.4 Tooling resources, A.10.2 Allocation of responsibilities; clauses 6.1.2, 8.2, 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM01, LLM03 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI01, ASI04 |
| OWASP MCP Top 10 (UNSTABLE) | MCP06, MCP04 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0051.001, AML.T0093, AML.T0068, AML.T0094, AML.T0010.005, AML.T0115.002, AML.T0011.001, AML.T0111 |
| MAS AIRM paragraphs | 5.15, 5.16, 5.22, 5.11 |
| airmkit (MAS AIRM) | `AIRM-5.15-GUARDRAIL-EFFECTIVENESS`, `AIRM-5.15-GENAI-FAILURE-MODES`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-5.16-THIRD-PARTY-COMPONENTS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-4.4-FN22-SHADOW-AI` |

### GC-13 Skills, plugins and extensions from approved sources only

**Control.** Skills, plugins and IDE extensions used with a harness shall come only from sources on the register, be pinned to a reviewed version, and be reviewed again before update. Automatic installation or update of skills and plugins from public marketplaces shall be disabled where the harness supports it.

**Addresses.** design weakness.

**Why.** A skill or plugin runs with the harness's privileges and its text is loaded as instructions. Marketplaces and automatic updates turn a single malicious or hijacked package into code and instructions on every developer machine.

- Threat classes: T05 Skills, plugins, extensions and marketplaces (2 counted incidents); T06 Harness distribution and dependency supply chain (9 counted incidents)
- Root causes: RC5 Package, extension or update-channel compromise or integrity failure
- Rubric dimensions: D06 Extensions, skills and plugins; D13 Distribution supply chain; D14 Managed and enterprise policy

**How to verify.**

```bash
harnesswatch audit instructions . --user -f json -o skills.json
```

- HG rules: `HG-INJ-001`, `HG-INJ-002`
- Manual: Compare installed skills and plugins (inventory, harness plugin lists) with the register and check their pins. The HG-INJ rules cover only the text of skill files, not plugin code.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, GOVERN 6.2 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Information Security (section numbers UNVERIFIED: 2.12, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.10.3 Suppliers, A.4.4 Tooling resources, A.10.2 Allocation of responsibilities, A.6.2.5 AI system deployment; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM03 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04 |
| OWASP MCP Top 10 (UNSTABLE) | MCP04 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0010.005, AML.T0115.002, AML.T0011.001, AML.T0111, AML.T0010.001, AML.T0010, AML.T0083 |
| MAS AIRM paragraphs | 5.11, 5.16, 5.10, 5.25 |
| airmkit (MAS AIRM) | `AIRM-5.16-THIRD-PARTY-COMPONENTS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-4.4-FN22-SHADOW-AI`, `AIRM-5.11-CHANGE-NOTIFICATION`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.10-THIRD-PARTY-TESTING` |

### GC-14 Credentials outside harness configuration files

**Control.** Model-provider keys, tokens and other credentials used by harnesses shall be held in the OS keychain, an organisational secret manager or a credential helper, and shall not be written as literal values in user, project or MCP configuration. Harness sessions shall use scoped, short-lived credentials where the provider supports them.

**Addresses.** design weakness.

**Why.** Plaintext credentials in configuration files are exposed to every local process, backups, dotfile repositories and, in project files, to everyone with read access to the repository.

- Threat classes: T07 Secret exposure and residue (12 counted incidents)
- Root causes: RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself
- Rubric dimensions: D07 Secrets and credential storage

**How to verify.**

```bash
harnesswatch audit config . --user -f json -o config.json
```

- HG rules: `HG-SEC-003`, `HG-MCP-003`
- Manual: Rotate any credential reported, and add harness configuration paths to secret scanning.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.10, MEASURE 2.7, GOVERN 1.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Data Privacy, Information Security (section numbers UNVERIFIED: 2.4, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.4.3 Data resources, A.4.5 System and computing resources, A.6.2.8 AI system recording of event logs; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM02 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI03 |
| OWASP MCP Top 10 (UNSTABLE) | MCP01 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0055, AML.T0083, AML.T0037, AML.T0098 |
| MAS AIRM paragraphs | 5.4, 5.16 |
| airmkit (MAS AIRM) | `AIRM-5.4-DATA-SECURITY`, `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.16-SECURITY-CONTROLS` |

### GC-15 Secrets in state directories, file modes and transcript retention

**Control.** Harness state directories shall be owner-only (0700) and credential, transcript and memory files owner-only (0600), including all parent directories on shared hosts, CI runners and dev containers. Transcript and log retention shall be configured to the organisation's retention policy, and agents shall be denied read access to secret files.

**Addresses.** design weakness.

**Why.** Harnesses persist transcripts, tool output and memory; any secret that passed through a session is then stored at rest, often indefinitely. World-readable state exposes it to every local account and to processes running as other users.

- Threat classes: T07 Secret exposure and residue (12 counted incidents); T15 Telemetry, data residency, retention and audit gaps (1 counted incident)
- Root causes: RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself
- Rubric dimensions: D07 Secrets and credential storage; D12 Telemetry and data retention

**How to verify.**

```bash
harnesswatch audit secrets -f json -o secrets.json
```

- HG rules: `HG-SEC-001`, `HG-SEC-002`
- Manual: Findings are redacted; rotate exposed credentials and purge affected session files. Check the configured retention setting (e.g. Claude Code cleanupPeriodDays).

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.10, MEASURE 2.7, GOVERN 1.1, MEASURE 2.8, MANAGE 4.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Data Privacy, Information Security, Intellectual Property (section numbers UNVERIFIED: 2.4, 2.9, 2.10) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.4.3 Data resources, A.4.5 System and computing resources, A.6.2.8 AI system recording of event logs, A.7.3 Acquisition of data, A.8.2 System documentation and information for users; clauses 8.3, 7.5, 9.1 |
| OWASP Top 10 for LLM Applications 2025 | LLM02 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI03 |
| OWASP MCP Top 10 (UNSTABLE) | MCP01, MCP08 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0055, AML.T0083, AML.T0037, AML.T0098 |
| MAS AIRM paragraphs | 5.4, 5.16, 5.11, 5.23 |
| airmkit (MAS AIRM) | `AIRM-5.4-DATA-SECURITY`, `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.4-DATA-CLASSIFICATION`, `AIRM-5.11-THIRD-PARTY-TRANSPARENCY`, `AIRM-5.23-GENAI-LOGGING` |

### GC-16 Execution sandbox for agent tools, including browser and computer use

**Control.** Shell and code execution by agents shall run inside an OS-level sandbox, container or VM that limits file-system writes to the workspace and holds no credentials beyond those the task needs. Browser and computer-use tools shall run in a separate profile or VM without logged-in organisational sessions. Silent fallback to unsandboxed execution shall be disabled where the harness supports it.

**Addresses.** design weakness, vulnerability.

**Why.** Approval prompts and deny rules are policy checks inside the agent process; a sandbox is an isolation boundary that still holds when they fail. Sandbox escapes and weak fallbacks are a recurring incident class, so the sandbox should be layered with, not instead of, the permission controls.

- Threat classes: T17 Execution sandbox and isolation escape (22 counted incidents); T12 Browser and computer-use surfaces (1 counted incident); T14 Destructive and unsafe autonomous actions (no counted incidents)
- Root causes: RC8 Isolation boundary escape or weak isolation fallback; RC11 Autonomous action exceeding user intent without enforced guardrail
- Rubric dimensions: D02 Execution sandbox; D03 Network egress control

**How to verify.**

```bash
harnesswatch observe <harness-id> --image <image-with-harness> --repo <synthetic-repo> -o observe-<harness-id>.json -- <harness command>
```

- HG rules: none; manual check
- Manual: Confirm the sandbox setting in managed configuration and that it is active (observe records the sandboxing it detects). From inside an agent session, attempt a write outside the workspace and a read of a synthetic credential file; both shall fail.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MEASURE 2.6, MANAGE 1.3, MANAGE 2.4, MANAGE 2.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Data Privacy, Human-AI Configuration (section numbers UNVERIFIED: 2.9, 2.4, 2.7) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.1.3 Processes for responsible design and development, A.6.2.5 AI system deployment, A.4.5 System and computing resources, A.6.2.6 AI system operation and monitoring, A.9.4 Intended use of the AI system, A.5.4 Assessing impacts on individuals or groups, A.9.3 Objectives for responsible use of AI systems; clauses 8.3, 6.1.4, 8.4 |
| OWASP Top 10 for LLM Applications 2025 | LLM06, LLM01 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI05, ASI01, ASI02, ASI08 |
| OWASP MCP Top 10 (UNSTABLE) | none mapped in taxonomy/ |
| MITRE ATLAS techniques (release 2026.09) | AML.T0105, AML.T0097, AML.T0100, AML.T0078, AML.T0113, AML.T0112.000, AML.T0101, AML.T0048.000 |
| MAS AIRM paragraphs | 5.16, 5.22, 6.3, 5.9, 5.2, 5.3 |
| airmkit (MAS AIRM) | `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-6.3-INFRASTRUCTURE`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.3-KILL-SWITCH`, `AIRM-5.3-CONTINGENCY-PLAN`, `AIRM-5.2-FN28-PILOT-GUARDRAILS` |

### GC-17 Network egress allowlist

**Control.** Network access from agent tools shall be off by default and limited to an allowlist of approved destinations (package registries, internal documentation, approved model and MCP endpoints), enforced through the harness's domain allowlist or an egress proxy. Automatic rendering or fetching of remote content (e.g. markdown images) shall be disabled where configurable.

**Addresses.** design weakness.

**Why.** Network reach is the exfiltration channel for any successful injection; rendering and auto-fetch features can carry data out without an explicit tool call (RC9).

- Threat classes: T08 Data exfiltration channels (23 counted incidents); T12 Browser and computer-use surfaces (1 counted incident)
- Root causes: RC9 Output-rendering or automatic-fetch feature acts as an exfiltration channel; RC6 Insecure default, missing safeguard or over-privileged mode by design
- Rubric dimensions: D03 Network egress control

**How to verify.**

```bash
harnesswatch audit config . --user -f json -o config.json
harnesswatch observe <harness-id> --image <image-with-harness> --allow <approved-host:port> -o observe-<harness-id>.json -- <harness command>
```

- HG rules: `HG-NET-001`
- Manual: Review the egress-proxy log for destinations outside the allowlist.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.10, MEASURE 2.7, MANAGE 1.3, MEASURE 2.6 |
| NIST AI 600-1 (Generative AI Profile) risks | Data Privacy, Information Security (section numbers UNVERIFIED: 2.4, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.4.3 Data resources, A.6.2.6 AI system operation and monitoring, A.9.2 Processes for responsible use of AI systems, A.9.4 Intended use of the AI system; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM02, LLM05, LLM01, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI02, ASI01 |
| OWASP MCP Top 10 (UNSTABLE) | MCP10 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0086, AML.T0077, AML.T0025, AML.T0057, AML.T0100, AML.T0078, AML.T0113, AML.T0112.000 |
| MAS AIRM paragraphs | 5.4, 5.16, 5.9 |
| airmkit (MAS AIRM) | `AIRM-5.4-DATA-SECURITY`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.9-HUMAN-OVERSIGHT` |

### GC-18 Persistent memory

**Control.** Agent-writable persistent memory shall be disabled unless approved for a use case; where enabled it shall be project-scoped, reviewed periodically, and not synchronised to shared repositories or team stores without review.

**Addresses.** design weakness.

**Why.** Memory replayed into later sessions lets a single successful injection persist, and shared memory spreads it to colleagues.

- Threat classes: T10 Persistent memory and long-lived context poisoning (2 counted incidents)
- Root causes: RC1 Untrusted content treated as instructions (no distinct control failure)
- Rubric dimensions: D09 Persistent memory

**How to verify.**

```bash
harnesswatch audit config . --user -f json -o config.json
```

- HG rules: `HG-MEM-001`
- Manual: Sample memory files in the review cycle and check them for instructions nobody wrote deliberately.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.4, MANAGE 2.2, MANAGE 4.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Information Integrity (section numbers UNVERIFIED: 2.9, 2.8) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.6 AI system operation and monitoring, A.7.4 Quality of data for AI systems, A.7.5 Data provenance; clauses 9.1 |
| OWASP Top 10 for LLM Applications 2025 | LLM04 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI06 |
| OWASP MCP Top 10 (UNSTABLE) | none mapped in taxonomy/ |
| MITRE ATLAS techniques (release 2026.09) | AML.T0080.000, AML.T0080, AML.T0081 |
| MAS AIRM paragraphs | 5.4, 5.23 |
| airmkit (MAS AIRM) | `AIRM-5.23-AGENT-TRACE-MONITORING`, `AIRM-5.15-GENAI-FAILURE-MODES`, `AIRM-5.4-DATA-LINEAGE` |

### GC-19 Sub-agent and delegation restrictions

**Control.** Sub-agents and delegated agents (including other harnesses invoked by an agent) shall inherit the parent session's permission rules or narrower ones, shall have an explicit tool list, and shall not be configured with bypass or allow-all modes. Delegation to another harness shall be recorded in the register (GC-01).

**Addresses.** design weakness.

**Why.** A sub-agent with its own bypass mode runs with broader authority than its parent, and content handed to it executes without prompts. Delegation chains across harnesses make this hard to see.

- Threat classes: T11 Sub-agent and cross-harness trust propagation (2 counted incidents); T03 Permission-model weaknesses and approval bypass (74 counted incidents)
- Root causes: RC6 Insecure default, missing safeguard or over-privileged mode by design; RC8 Isolation boundary escape or weak isolation fallback
- Rubric dimensions: D10 Sub-agent and delegation isolation; D01 Permission model

**How to verify.**

```bash
harnesswatch audit config . --user -f json -o config.json
```

- HG rules: `HG-SUB-001`

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | GOVERN 3.2, MAP 3.5, MANAGE 2.4, MEASURE 2.6 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Human-AI Configuration, Information Security (section numbers UNVERIFIED: 2.12, 2.7, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.1.3 Processes for responsible design and development, A.6.2.6 AI system operation and monitoring, A.10.2 Allocation of responsibilities, A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems, A.9.3 Objectives for responsible use of AI systems, A.9.4 Intended use of the AI system; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI03, ASI07, ASI08, ASI02 |
| OWASP MCP Top 10 (UNSTABLE) | MCP02 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0118, AML.T0118.001, AML.T0053, AML.T0050, AML.T0102 |
| MAS AIRM paragraphs | 4.8, 5.16, 5.23, 5.9 |
| airmkit (MAS AIRM) | `AIRM-4.8-FN25-AGENT-ATTRIBUTES`, `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.23-AGENT-TRACE-MONITORING`, `AIRM-5.16-ACCESS-CONTROL`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.9-DESIGN-FOR-OVERSIGHT` |

### GC-20 Local agent services and control endpoints

**Control.** Local or network services started by a harness (IDE bridges, remote-control gateways, WebSocket or HTTP control endpoints, agent servers) shall be disabled unless needed; where used they shall bind to loopback, require authentication, and validate Origin and Host.

**Addresses.** vulnerability, design weakness.

**Why.** Unauthenticated local endpoints let any web page or local process drive the agent (DNS rebinding, cross-site WebSocket hijacking). This is an ordinary access-control defect class, mostly fixed by vendors as vulnerabilities, so version currency (GC-29) matters as much as configuration.

- Threat classes: T18 Agent control-plane exposure and authorization (34 counted incidents)
- Root causes: RC4 Missing authentication or origin/Host validation on a local or network control endpoint
- Rubric dimensions: D16 Local service and control-plane exposure (PROPOSED)

**How to verify.**

- HG rules: none; manual check
- Manual: With the harness running, list listening sockets (e.g. `ss -ltnp` / `lsof -iTCP -sTCP:LISTEN`), confirm loopback binding, and confirm that requests without the session token, or with a foreign Origin, are rejected.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MANAGE 1.3, MANAGE 3.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security (section numbers UNVERIFIED: 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.5 AI system deployment, A.4.5 System and computing resources, A.6.2.6 AI system operation and monitoring; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | none mapped in taxonomy/ |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI03 |
| OWASP MCP Top 10 (UNSTABLE) | MCP07 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0132, AML.T0006.002, AML.T0049, AML.T0122, AML.T0078 |
| MAS AIRM paragraphs | 5.16, 5.22 |
| airmkit (MAS AIRM) | `AIRM-5.16-ACCESS-CONTROL`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.22-SECURITY-REVIEW` |

## 5. Runtime and CI

### GC-21 Headless agents in CI: no untrusted triggers (pwn-request pattern)

**Control.** A coding agent shall not run non-interactively in CI on events that outsiders can trigger (issue and pull-request comments, issues, pull_request_target) unless the job is gated on author association or an actor allowlist. Event text shall be passed through environment variables, never interpolated into the prompt or script, and deployment secrets shall not be exposed to agent jobs.

**Addresses.** design weakness.

**Why.** The agent reads attacker-written text in a job that may hold secrets and write access. With auto-approval or interpolation and no actor gate, a crafted issue or pull request can steer the agent to leak secrets or push code.

- Threat classes: T09 Headless and CI abuse (pwn request) (5 counted incidents); T01 Indirect prompt injection via workspace and retrieved content (14 counted incidents)
- Root causes: RC1 Untrusted content treated as instructions (no distinct control failure); RC6 Insecure default, missing safeguard or over-privileged mode by design
- Rubric dimensions: D08 Headless and CI safeguards

**How to verify.**

```bash
harnesswatch audit ci . -f sarif -o ci.sarif
```

- HG rules: `HG-CI-001`

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MANAGE 4.1, GOVERN 4.3, MAP 3.5, MEASURE 2.6, MANAGE 1.3, MANAGE 2.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Human-AI Configuration (section numbers UNVERIFIED: 2.9, 2.7) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.5 AI system deployment, A.6.2.6 AI system operation and monitoring, A.9.2 Processes for responsible use of AI systems, A.10.2 Allocation of responsibilities, A.6.1.3 Processes for responsible design and development, A.6.2.4 AI system verification and validation; clauses 8.3, 9.1, 6.1.2, 8.2 |
| OWASP Top 10 for LLM Applications 2025 | LLM01, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI01, ASI02, ASI03 |
| OWASP MCP Top 10 (UNSTABLE) | MCP06 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0051.001, AML.T0093, AML.T0119, AML.T0053, AML.T0068, AML.T0094 |
| MAS AIRM paragraphs | 5.16, 5.22, 5.23, 5.15 |
| airmkit (MAS AIRM) | `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-5.23-AGENT-TRACE-MONITORING`, `AIRM-5.15-GUARDRAIL-EFFECTIVENESS`, `AIRM-5.15-GENAI-FAILURE-MODES`, `AIRM-5.16-SECURITY-CONTROLS` |

### GC-22 Least-privilege GITHUB_TOKEN and agent identities

**Control.** Every CI job that runs an agent shall declare an explicit permissions block with read-only scopes, granting only the single write scope the job needs. Agent jobs shall use dedicated identities with no production credentials, and branch protection shall require human review of agent-authored changes.

**Addresses.** design weakness.

**Why.** A default or write-scoped token lets a steered agent push commits, edit workflows or publish packages. Least privilege bounds the blast radius of a successful injection.

- Threat classes: T09 Headless and CI abuse (pwn request) (5 counted incidents); T14 Destructive and unsafe autonomous actions (no counted incidents)
- Root causes: RC6 Insecure default, missing safeguard or over-privileged mode by design; RC11 Autonomous action exceeding user intent without enforced guardrail
- Rubric dimensions: D08 Headless and CI safeguards; D01 Permission model

**How to verify.**

```bash
harnesswatch audit ci . -f sarif -o ci.sarif
```

- HG rules: `HG-CI-002`
- Manual: Check branch-protection settings and the agent identity's credential scopes in the CI platform.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MANAGE 4.1, GOVERN 4.3, MAP 3.5, MEASURE 2.6, MANAGE 2.4, MANAGE 2.3, MANAGE 1.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Human-AI Configuration (section numbers UNVERIFIED: 2.9, 2.7) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.5 AI system deployment, A.6.2.6 AI system operation and monitoring, A.9.2 Processes for responsible use of AI systems, A.10.2 Allocation of responsibilities, A.5.4 Assessing impacts on individuals or groups, A.9.3 Objectives for responsible use of AI systems; clauses 8.3, 9.1, 6.1.4, 8.4 |
| OWASP Top 10 for LLM Applications 2025 | LLM01, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI01, ASI02, ASI03, ASI08 |
| OWASP MCP Top 10 (UNSTABLE) | MCP06 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0051.001, AML.T0093, AML.T0119, AML.T0053, AML.T0101, AML.T0048.000 |
| MAS AIRM paragraphs | 5.16, 5.22, 5.23, 5.2, 5.3, 5.9 |
| airmkit (MAS AIRM) | `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-5.23-AGENT-TRACE-MONITORING`, `AIRM-5.3-KILL-SWITCH`, `AIRM-5.3-CONTINGENCY-PLAN`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.2-FN28-PILOT-GUARDRAILS` |

### GC-23 Harness-configuration gate on every change

**Control.** Repositories in which agents run shall check harness configuration, MCP declarations, instruction files and CI workflows on every pull request, block merges on high-severity findings, and suppress findings only through a reviewed baseline file.

**Addresses.** design weakness, vulnerability.

**Why.** Repository files are the configuration-as-code attack surface; checking them at review time catches changes before a harness honours them.

- Threat classes: T02 Repository and workspace configuration as code execution (52 counted incidents); T04 MCP trust: tool poisoning, rug pulls, OAuth and server identity (15 counted incidents); T01 Indirect prompt injection via workspace and retrieved content (14 counted incidents)
- Root causes: RC2 Workspace, repository or agent-written content executed or honoured before or without consent; RC1 Untrusted content treated as instructions (no distinct control failure)
- Rubric dimensions: D04 Workspace and config trust; D05 MCP governance; D08 Headless and CI safeguards

**How to verify.**

```bash
harnesswatch audit repo . --fail-on high -f sarif -o harnesswatch.sarif
harnesswatch audit repo . --fail-on high --baseline harnesswatch-baseline.json
```

- HG rules: `HG-PERM-001`, `HG-PERM-002`, `HG-HOOK-001`, `HG-HOOK-002`, `HG-MCP-001`, `HG-MCP-005`, `HG-MCP-006`, `HG-INJ-001`, `HG-INJ-002`, `HG-INJ-003`, `HG-CI-001`, `HG-CI-002`
- Manual: The harnesswatch GitHub Action (pinned to a full commit SHA) or pre-commit hooks run the same audits; confirm the check is required in branch protection.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.7, MANAGE 1.3, MAP 4.2, MAP 4.1, MANAGE 3.1, GOVERN 6.1, MEASURE 2.6, MANAGE 2.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Value Chain and Component Integration (section numbers UNVERIFIED: 2.9, 2.12) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.1.3 Processes for responsible design and development, A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems, A.10.2 Allocation of responsibilities, A.10.3 Suppliers, A.4.4 Tooling resources, A.6.2.4 AI system verification and validation, A.6.2.6 AI system operation and monitoring; clauses 6.1.2, 8.3, 8.2 |
| OWASP Top 10 for LLM Applications 2025 | LLM06, LLM03, LLM01 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI05, ASI02, ASI04, ASI01 |
| OWASP MCP Top 10 (UNSTABLE) | MCP09, MCP03, MCP04, MCP05, MCP07, MCP10, MCP06 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0081, AML.T0050, AML.T0053, AML.T0110, AML.T0109, AML.T0011.002, AML.T0010.005, AML.T0099, AML.T0131, AML.T0051.001, AML.T0093, AML.T0068, AML.T0094 |
| MAS AIRM paragraphs | 5.16, 5.22, 5.10, 5.11, 5.25, 5.15 |
| airmkit (MAS AIRM) | `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-5.16-THIRD-PARTY-COMPONENTS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.25-CHANGE-CONTROL`, `AIRM-5.15-GUARDRAIL-EFFECTIVENESS`, `AIRM-5.15-GENAI-FAILURE-MODES` |

### GC-24 Human approval and stop control for irreversible actions

**Control.** Irreversible or high-impact actions by agents (deleting data, force-pushing, changing production infrastructure, sending external communications, moving money) shall require explicit human approval outside the agent's own permission prompt, and the organisation shall be able to stop running agents and revoke their credentials promptly.

**Addresses.** design weakness.

**Why.** Destructive actions can occur with no attacker involved, when the agent exceeds the user's intent without an enforced guardrail (RC11). Deny rules reduce the likelihood; approval gates and a stop control limit the impact.

- Threat classes: T14 Destructive and unsafe autonomous actions (no counted incidents)
- Root causes: RC11 Autonomous action exceeding user intent without enforced guardrail
- Rubric dimensions: D01 Permission model; D02 Execution sandbox

**How to verify.**

```bash
harnesswatch audit config . --user -f json -o config.json
```

- HG rules: `HG-PERM-003`, `HG-CI-002`
- Manual: Test the stop procedure in an exercise: terminate a running agent session and revoke its credentials, and record the time taken.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.6, MANAGE 2.4, MANAGE 2.3, MANAGE 1.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Human-AI Configuration (section numbers UNVERIFIED: 2.7) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.5.4 Assessing impacts on individuals or groups, A.9.3 Objectives for responsible use of AI systems, A.6.2.6 AI system operation and monitoring; clauses 6.1.4, 8.4 |
| OWASP Top 10 for LLM Applications 2025 | LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI02, ASI08 |
| OWASP MCP Top 10 (UNSTABLE) | none mapped in taxonomy/ |
| MITRE ATLAS techniques (release 2026.09) | AML.T0101, AML.T0048.000 |
| MAS AIRM paragraphs | 5.2, 5.3, 5.9 |
| airmkit (MAS AIRM) | `AIRM-5.3-KILL-SWITCH`, `AIRM-5.3-CONTINGENCY-PLAN`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.2-FN28-PILOT-GUARDRAILS` |

## 6. Monitoring and incident response

### GC-25 Agent activity logging and audit trail

**Control.** The organisation shall retain, in a store the agent cannot modify, a record of agent sessions sufficient to reconstruct what the agent did: the user or trigger, harness and version, permission mode, tool and MCP calls with their approval decisions, sub-agent delegation, and files changed. Logs shall be redacted for secrets and retained according to policy.

**Addresses.** policy choice, design weakness.

**Why.** Without a record of tool calls and approvals an organisation cannot investigate an incident or show supervisors what an agent did. Local transcripts are under the user's and the agent's control and can contain secrets (GC-15).

- Threat classes: T15 Telemetry, data residency, retention and audit gaps (1 counted incident); T11 Sub-agent and cross-harness trust propagation (2 counted incidents); T09 Headless and CI abuse (pwn request) (5 counted incidents)
- Root causes: RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself
- Rubric dimensions: D11 Audit logging

**How to verify.**

- HG rules: none; manual check
- Manual: Pick a recent agent session and reconstruct it from the central log; check that the fields listed above are present and that secrets are redacted.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.10, MEASURE 2.8, GOVERN 1.1, MANAGE 4.3, GOVERN 3.2, MAP 3.5, MANAGE 2.4, MEASURE 2.7, MANAGE 4.1, GOVERN 4.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Data Privacy, Intellectual Property, Value Chain and Component Integration, Human-AI Configuration, Information Security (section numbers UNVERIFIED: 2.4, 2.10, 2.12, 2.7, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.4.3 Data resources, A.7.3 Acquisition of data, A.8.2 System documentation and information for users, A.6.2.8 AI system recording of event logs, A.6.1.3 Processes for responsible design and development, A.6.2.6 AI system operation and monitoring, A.10.2 Allocation of responsibilities, A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems; clauses 7.5, 9.1, 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM02, LLM06, LLM01 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI03, ASI07, ASI08, ASI01, ASI02 |
| OWASP MCP Top 10 (UNSTABLE) | MCP08, MCP06 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0118, AML.T0118.001, AML.T0053, AML.T0051.001, AML.T0093, AML.T0119 |
| MAS AIRM paragraphs | 5.4, 5.11, 5.23, 4.8, 5.16, 5.22 |
| airmkit (MAS AIRM) | `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.4-DATA-CLASSIFICATION`, `AIRM-5.11-THIRD-PARTY-TRANSPARENCY`, `AIRM-5.23-GENAI-LOGGING`, `AIRM-4.8-FN25-AGENT-ATTRIBUTES`, `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.23-AGENT-TRACE-MONITORING`, `AIRM-5.22-SECURITY-REVIEW` |

### GC-26 Continuous configuration posture monitoring

**Control.** The organisation shall audit harness configuration, MCP declarations, secret residue, file modes and installed versions on managed endpoints and build agents on a fixed schedule and after each harness upgrade, and track new findings against an approved baseline.

**Addresses.** design weakness, vulnerability.

**Why.** User-level configuration drifts after onboarding: bypass modes are switched on, MCP servers added, transcripts accumulate. A scheduled audit with a baseline turns drift into tickets.

- Threat classes: T03 Permission-model weaknesses and approval bypass (74 counted incidents); T07 Secret exposure and residue (12 counted incidents); T06 Harness distribution and dependency supply chain (9 counted incidents)
- Root causes: RC6 Insecure default, missing safeguard or over-privileged mode by design; RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself; RC5 Package, extension or update-channel compromise or integrity failure
- Rubric dimensions: D14 Managed and enterprise policy; D07 Secrets and credential storage; D13 Distribution supply chain

**How to verify.**

```bash
harnesswatch audit all . --online -f json -o <host>-<date>.json
harnesswatch report <host>-*.json --baseline baseline.json -f sarif -o posture.sarif
```

- HG rules: `HG-PERM-001`, `HG-PERM-002`, `HG-PERM-003`, `HG-SEC-001`, `HG-SEC-002`, `HG-SEC-003`, `HG-SUP-001`, `HG-SUP-002`, `HG-MCP-001`, `HG-MCP-003`
- Manual: --online sends package name and version only to OSV.dev; omit it on hosts without approved egress.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | GOVERN 3.2, MAP 3.5, MEASURE 2.6, MANAGE 2.4, MEASURE 2.10, MEASURE 2.7, GOVERN 1.1, MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, GOVERN 6.2 |
| NIST AI 600-1 (Generative AI Profile) risks | Human-AI Configuration, Information Security, Data Privacy, Value Chain and Component Integration (section numbers UNVERIFIED: 2.7, 2.9, 2.4, 2.12) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.6.2.5 AI system deployment, A.9.2 Processes for responsible use of AI systems, A.9.3 Objectives for responsible use of AI systems, A.9.4 Intended use of the AI system, A.4.3 Data resources, A.4.5 System and computing resources, A.6.2.8 AI system recording of event logs, A.10.3 Suppliers, A.4.4 Tooling resources; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM06, LLM02, LLM03 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI02, ASI03, ASI04 |
| OWASP MCP Top 10 (UNSTABLE) | MCP02, MCP01, MCP04 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0053, AML.T0050, AML.T0102, AML.T0055, AML.T0083, AML.T0037, AML.T0098, AML.T0010.001, AML.T0011.001, AML.T0010 |
| MAS AIRM paragraphs | 5.9, 5.16, 5.4, 5.10, 5.11, 5.25 |
| airmkit (MAS AIRM) | `AIRM-5.16-AGENT-PERMISSIONS`, `AIRM-5.16-ACCESS-CONTROL`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.9-DESIGN-FOR-OVERSIGHT`, `AIRM-5.4-DATA-SECURITY`, `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.11-CHANGE-NOTIFICATION`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.10-THIRD-PARTY-TESTING` |

### GC-27 Harness-specific incident response

**Control.** The incident-response plan shall cover agent-harness incidents, including: revoking and rotating credentials the harness could reach; purging transcripts, memory and caches that hold secrets or injected instructions; removing or disabling MCP servers, skills and plugins; stopping running agents; detecting unapproved or attacker-operated harness use; and notifying the supplier and, where required, the supervisor.

**Addresses.** vulnerability, design weakness, policy choice.

**Why.** A compromised harness session leaves state in places conventional playbooks do not cover (transcripts, memory, MCP tokens). Attackers also operate harnesses as tools; detecting that is an incident-management task, not a product fix.

- Threat classes: T16 Offensive misuse of harnesses by attackers (3 counted incidents); T07 Secret exposure and residue (12 counted incidents); T14 Destructive and unsafe autonomous actions (no counted incidents)
- Root causes: RC12 Adversarial use of a legitimate capability (no product defect); RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself; RC11 Autonomous action exceeding user intent without enforced guardrail
- Rubric dimensions: D11 Audit logging; D07 Secrets and credential storage

**How to verify.**

```bash
harnesswatch audit secrets -f json -o secrets.json
```

- HG rules: `HG-SEC-001`, `HG-SEC-002`
- Manual: Run a tabletop exercise for a prompt-injection-led credential leak through a harness.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MANAGE 4.3, MANAGE 2.3, GOVERN 4.3, MEASURE 2.10, MEASURE 2.7, GOVERN 1.1, MEASURE 2.6, MANAGE 2.4, MANAGE 1.3 |
| NIST AI 600-1 (Generative AI Profile) risks | Information Security, Data Privacy, Human-AI Configuration (section numbers UNVERIFIED: 2.9, 2.4, 2.7) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.8.4 Communication of incidents, A.9.2 Processes for responsible use of AI systems, A.3.3 Reporting of concerns, A.4.3 Data resources, A.4.5 System and computing resources, A.6.2.8 AI system recording of event logs, A.5.4 Assessing impacts on individuals or groups, A.9.3 Objectives for responsible use of AI systems, A.6.2.6 AI system operation and monitoring; clauses 10.2, 8.3, 6.1.4, 8.4 |
| OWASP Top 10 for LLM Applications 2025 | LLM02, LLM06 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI10, ASI03, ASI02, ASI08 |
| OWASP MCP Top 10 (UNSTABLE) | MCP01 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0124, AML.T0116, AML.T0117, AML.T0055, AML.T0083, AML.T0037, AML.T0098, AML.T0101, AML.T0048.000 |
| MAS AIRM paragraphs | 4.4, 5.23, 5.4, 5.16, 5.2, 5.3, 5.9 |
| airmkit (MAS AIRM) | `AIRM-5.23-INCIDENT-MANAGEMENT`, `AIRM-4.4-FN22-SHADOW-AI`, `AIRM-5.4-DATA-SECURITY`, `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.16-SECURITY-CONTROLS`, `AIRM-5.3-KILL-SWITCH`, `AIRM-5.3-CONTINGENCY-PLAN`, `AIRM-5.9-HUMAN-OVERSIGHT`, `AIRM-5.2-FN28-PILOT-GUARDRAILS` |

## 7. Supplier management

### GC-28 Verified installers and a controlled update channel

**Control.** Harnesses shall be installed from a package manager with a lockfile or from vendor artefacts whose checksum or signature is verified, not through unverified 'curl | sh' installers. Automatic updates shall follow an organisation-controlled channel or version pin, so that new versions are adopted deliberately and can be rolled back.

**Addresses.** design weakness.

**Why.** With on-by-default auto-update, whoever controls the download host or CDN path controls code that runs with the developer's credentials. Harness packages and update channels have been compromised (RC5).

- Threat classes: T06 Harness distribution and dependency supply chain (9 counted incidents)
- Root causes: RC5 Package, extension or update-channel compromise or integrity failure
- Rubric dimensions: D13 Distribution supply chain; D14 Managed and enterprise policy

**How to verify.**

```bash
harnesswatch audit supply -f json -o supply.json
```

- HG rules: `HG-SUP-001`
- Manual: Confirm the auto-update setting in managed configuration.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, GOVERN 6.2 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Information Security (section numbers UNVERIFIED: 2.12, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.10.3 Suppliers, A.4.4 Tooling resources, A.6.2.5 AI system deployment; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM03 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04 |
| OWASP MCP Top 10 (UNSTABLE) | MCP04 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0010.001, AML.T0011.001, AML.T0010, AML.T0083 |
| MAS AIRM paragraphs | 5.10, 5.11, 5.25 |
| airmkit (MAS AIRM) | `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.11-CHANGE-NOTIFICATION`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.10-THIRD-PARTY-TESTING` |

### GC-29 SBOM, advisories and patch deadlines

**Control.** The organisation shall keep an SBOM of installed harnesses, subscribe to each supplier's security advisories, and apply security fixes for harnesses within a defined deadline set by severity. Versions with known exploitable advisories shall not remain in use past that deadline.

**Addresses.** vulnerability.

**Why.** Most counted harness incidents are vulnerabilities, and fixes are usually available by the time an advisory is published (see context figures), so the exposure window is set mainly by how fast adopters upgrade.

- Threat classes: T06 Harness distribution and dependency supply chain (9 counted incidents); T19 Conventional software defects in agent runtimes and SDKs (45 counted incidents)
- Root causes: RC5 Package, extension or update-channel compromise or integrity failure; RC10 Conventional implementation defect not gating an agent capability
- Rubric dimensions: D13 Distribution supply chain; D15 Vulnerability disclosure

**How to verify.**

```bash
harnesswatch audit supply --online --sbom harness-sbom.cdx.json -f json -o supply.json
```

- HG rules: `HG-SUP-002`

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, GOVERN 6.2, MEASURE 2.7, MANAGE 4.1 |
| NIST AI 600-1 (Generative AI Profile) risks | Value Chain and Component Integration, Information Security (section numbers UNVERIFIED: 2.12, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.10.3 Suppliers, A.4.4 Tooling resources, A.6.2.5 AI system deployment, A.6.2.4 AI system verification and validation, A.6.2.7 AI system technical documentation; clauses 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM03, LLM05, LLM10 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04, ASI05 |
| OWASP MCP Top 10 (UNSTABLE) | MCP04, MCP05 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0010.001, AML.T0011.001, AML.T0010, AML.T0083, AML.T0049, AML.T0029 |
| MAS AIRM paragraphs | 5.10, 5.11, 5.25, 5.14, 5.22 |
| airmkit (MAS AIRM) | `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.11-CHANGE-NOTIFICATION`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.10-THIRD-PARTY-TESTING`, `AIRM-5.22-SECURITY-REVIEW`, `AIRM-5.14-TESTING-APPROACHES`, `AIRM-5.25-CHANGE-CONTROL` |

### GC-30 Supplier terms: transparency, change notice and disclosure

**Control.** Contracts or terms for harness and model suppliers shall cover: data use, retention and processing locations; notice of material changes to the client, its data flows or default settings; a security contact and advisory process; incident notification; and the organisation's right to test the client's behaviour (GC-03). Gaps shall be risk-accepted by the accountable owner.

**Addresses.** policy choice.

**Why.** Accountability for third-party AI tooling stays with the adopting organisation. Telemetry, default changes and update behaviour are supplier decisions the adopter can only manage if they are disclosed.

- Threat classes: T15 Telemetry, data residency, retention and audit gaps (1 counted incident); T06 Harness distribution and dependency supply chain (9 counted incidents)
- Root causes: RC7 Unintended exposure, leakage or over-collection of secrets or data by the harness itself; RC5 Package, extension or update-channel compromise or integrity failure
- Rubric dimensions: D12 Telemetry and data retention; D15 Vulnerability disclosure; D13 Distribution supply chain

**How to verify.**

- HG rules: none; manual check
- Manual: Procurement and legal review against this list at contract signature and renewal.

**Framework mapping** (inherited from the cited threat classes).

| Framework | Mapped items |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | MEASURE 2.10, MEASURE 2.8, GOVERN 1.1, MANAGE 4.3, MAP 4.1, MAP 4.2, MANAGE 3.1, GOVERN 6.1, GOVERN 6.2 |
| NIST AI 600-1 (Generative AI Profile) risks | Data Privacy, Intellectual Property, Value Chain and Component Integration, Information Security (section numbers UNVERIFIED: 2.4, 2.10, 2.12, 2.9) |
| ISO/IEC 42001:2023 Annex A controls and clauses (THIRD-PARTY titles) | A.4.3 Data resources, A.7.3 Acquisition of data, A.8.2 System documentation and information for users, A.6.2.8 AI system recording of event logs, A.10.3 Suppliers, A.4.4 Tooling resources, A.6.2.5 AI system deployment; clauses 7.5, 9.1, 8.3 |
| OWASP Top 10 for LLM Applications 2025 | LLM02, LLM03 |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | ASI04 |
| OWASP MCP Top 10 (UNSTABLE) | MCP08, MCP04 |
| MITRE ATLAS techniques (release 2026.09) | AML.T0010.001, AML.T0011.001, AML.T0010, AML.T0083 |
| MAS AIRM paragraphs | 5.4, 5.11, 5.23, 5.10, 5.25 |
| airmkit (MAS AIRM) | `AIRM-5.4-DATA-PRIVACY`, `AIRM-5.4-DATA-CLASSIFICATION`, `AIRM-5.11-THIRD-PARTY-TRANSPARENCY`, `AIRM-5.23-GENAI-LOGGING`, `AIRM-5.11-SUPPLY-CHAIN`, `AIRM-5.11-CHANGE-NOTIFICATION`, `AIRM-5.25-DYNAMIC-UPDATES`, `AIRM-5.10-THIRD-PARTY-TESTING` |

## 8. Mapping status and gaps

### Framework status

| Framework | Status |
|---|---|
| NIST AI RMF 1.0 (AI 100-1) subcategories | Subcategory statements read on the NIST AIRC Playbook; MEASURE 3.x and MAP 5.x not used (pages not read). |
| NIST AI 600-1 (Generative AI Profile) risks | Referenced by risk name. Section numbers are UNVERIFIED (PDF text not re-read; 2.2, 2.5, 2.6 and 2.9 corroborated only through the airmkit crosswalk). |
| ISO/IEC 42001:2023 Annex A controls and clauses | THIRD-PARTY: Annex A ids and titles cross-read from two public listings; the standard text is paywalled and was not read. Confirm in a licensed copy before relying on them. Clause numbers are management-system clauses. |
| OWASP Top 10 for LLM Applications 2025 | 2025 ids. A 2026 edition exists and reportedly renumbers entries; remap once its text is read. |
| OWASP Top 10 for Agentic Applications 2026 (ASI) | Names read from the OWASP GenAI Security Project repository; the PDF was not retrieved as text. |
| OWASP MCP Top 10 | UNSTABLE (beta, unversioned project); re-check before publication. |
| MITRE ATLAS techniques (release 2026.09) | Every id machine-checked against ATLAS-latest.yaml. |
| MAS Guidelines on AI Risk Management (issued 2026-10-07) and airmkit control ids | Paragraph numbers follow the MAS PDF (hash-matched); only the contents page and paragraph 5.16 were re-read, other paragraph references are as indexed in airmkit. AIRM-* ids exist in airmkit controls.yaml. |

### Gaps flagged per control

- **GC-01**: No HG rule compares a machine's inventory with an approval register; reconciliation is manual.
- **GC-01** (mapping note): T16: ASI10 (Rogue Agents) concerns agents deviating from intended behaviour; the fit with attacker-operated agents is loose, so treat as indicative.
- **GC-02**: Rubric dimension D16 is proposed and is not yet scored in matrix/.
- **GC-03** (mapping note): T15: ATLAS has no technique for vendor-side collection or audit gaps, so mitre_atlas is empty by design.
- **GC-05**: OWASP Agentic has no entry for T15, so the telemetry mapping rests on NIST, ISO and MAS items (and OWASP LLM02 / MCP08).
- **GC-05** (mapping note): T15: ATLAS has no technique for vendor-side collection or audit gaps, so mitre_atlas is empty by design.
- **GC-06**: harnesswatch reads managed-scope files, but no HG rule fires when the bypass lock is absent; HG-PERM-001 only reports bypass modes that are enabled.
- **GC-08**: No HG rule flags a project-scoped env block that redirects the model endpoint or proxy.
- **GC-13**: T05 has only partial rule coverage (instruction text); no HG rule checks plugin pinning or provenance.
- **GC-15** (mapping note): T15: ATLAS has no technique for vendor-side collection or audit gaps, so mitre_atlas is empty by design.
- **GC-16**: No HG rule targets T17 (sandbox) or T12 (browser/computer use); verification is manual.
- **GC-17**: HG-NET-001 reports only configuration that explicitly opens egress; enforcement is verified at the proxy.
- **GC-18** (mapping note): T10: OWASP LLM04 (Data and Model Poisoning) is the closest LLM Top 10 2025 entry; it is framed around training data, so the mapping is partial.
- **GC-20**: No HG rule and no harnesswatch command target T18; OWASP LLM Top 10 2025 has no fitting entry; rubric D16 is proposed only.
- **GC-20** (mapping note): T18: No OWASP LLM Top 10 2025 entry fits (classic OWASP API/Web risk); left empty rather than forced. Added in Phase 2. D16 is a proposed new dimension.
- **GC-25**: No HG rule checks audit-log configuration; D11 is assessed manually.
- **GC-25** (mapping note): T15: ATLAS has no technique for vendor-side collection or audit gaps, so mitre_atlas is empty by design.
- **GC-27**: taxonomy/mappings.yaml links AIRM-5.23-INCIDENT-MANAGEMENT only through T16; no HG rule targets T16 and OWASP LLM 2025 has no T16 entry.
- **GC-27** (mapping note): T16: ASI10 (Rogue Agents) concerns agents deviating from intended behaviour; the fit with attacker-operated agents is loose, so treat as indicative.
- **GC-30** (mapping note): T15: ATLAS has no technique for vendor-side collection or audit gaps, so mitre_atlas is empty by design.

## 9. Maintenance

Review this checklist when the taxonomy, rule pack or a referenced framework changes, and at least
annually. `scripts/gen_checklist_check.py` checks that every HG rule, threat class, root cause, rubric
dimension and framework id referenced in `brief/governance-checklist.yaml` exists in `rules/` or
`taxonomy/`, that each framework id is supported by a threat class the control cites, and that this page
matches the YAML. Run `uv run python scripts/gen_checklist_check.py --write` to re-render it after
editing the YAML.
