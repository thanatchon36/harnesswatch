# Attack trees for AI coding-agent harnesses

Phase 2 deliverable for RQ1. Defensive level of detail only: each tree names the weakness class,
the control that mitigates it and a published incident where one exists; none contains working
exploit steps. Classes (`Txx`) are defined in `harness-threats.yaml`; controls (`Dxx`) in
`matrix/rubric.yaml` (D16 is a proposed dimension); incident ids are the `id` column of
`evidence/incidents.csv`.

## How to read the trees

- Root = attacker goal. A **diamond-shaped gate** `OR` means any one child suffices; `AND` means all
  children are required.
- Leaves (rectangles) read `weakness | class | control | example incident`. A leaf with `no incident`
  is a plausible path with no incident in the dataset.
- The class on a leaf is the weakness the leaf describes. The example's primary class in
  `incident-classification.csv` can differ, because that file records the first control that failed.
- Colour: orange = gate, grey = precondition that the attacker must satisfy, white = weakness leaf.
- Mitigating a single leaf does not remove the goal; the useful reading is the **minimum cut set**:
  for an OR root, every branch needs a control; for an AND node, one control on any child suffices.
  The cut-set notes below each tree state where controls are cheapest.

---

## Tree 1: Execute code on the developer machine through repository content

```mermaid
flowchart TD
  G0["GOAL: code runs on the developer machine after the victim opens or clones an attacker repository"]
  O1{"OR"}
  G0 --> O1

  O1 --> B1{"OR: config executed without consent"}
  B1 --> L1["Hooks or settings run before the trust dialog | T02 | D04 | G1-I028"]
  B1 --> L2["Trust dialog bypassed by repo-controlled settings or worktree spoofing | T02 | D04 | G1-I013"]
  B1 --> L3["IDE task set to run on folder open, workspace trust off by default | T02 | D04 | G6-080"]
  B1 --> L4["Project MCP or CLI config starts a process | T02 | D05 | G1-I040"]
  B1 --> L5["Git config such as fsmonitor or hooksPath run by helper operations outside the sandbox | T02 | D04 | G7-I032"]
  B1 --> L6["Workspace-resident executable found through the search path | T02 | D04 | G7-I054"]

  O1 --> A1{"AND: injected instructions plus capability"}
  A1 --> P1["Precondition: agent reads attacker text in an instruction file, README or issue | T01 | D01 | G6-073"]
  A1 --> C1{"OR: capability to act"}
  C1 --> L7["Allowlist or command parser bypass | T03 | D01 | G4-I004"]
  C1 --> L8["Permissive default allowlist or approve-everything mode | T03 | D14 | G1-I032"]
  C1 --> L9["Path or symlink restriction bypass for file write | T03 | D01 | G1-I026"]

  O1 --> A2{"AND: agent writes then host executes"}
  A2 --> P2["Precondition: injected agent can write files without approval | T01 | D01 | G2-I007"]
  A2 --> L10["Execution-sensitive file is auto-loaded (tasks.json, mcp.json, settings) | T02 | D04 | G4-I002"]

  classDef gate fill:#fde7c8,stroke:#b36b00,color:#222;
  classDef pre fill:#e6e6e6,stroke:#777,color:#222;
  class O1,B1,A1,C1,A2 gate;
  class P1,P2 pre;
```

Cut set: D04 (trust gating of every config class, including git helper operations) removes branch
B1; D01 plus a sandbox (D02) reduce branches A1 and A2. Branch A2 needs both approval of writes to
execution-sensitive paths and trust gating to stop.

---

## Tree 2: Exfiltrate secrets through a headless CI agent

```mermaid
flowchart TD
  G0["GOAL: obtain repository or cloud secrets through an agent running in CI"]
  A0{"AND"}
  G0 --> A0

  A0 --> P1{"OR: attacker text reaches the agent prompt"}
  P1 --> L1["Issue or PR title/body drives a triage or review agent | T09 | D08 | G7-I027"]
  P1 --> L2["Branch name or title interpolated into a shell step | T09 | D08 | G7-I116"]
  P1 --> L3["PR head config such as .mcp.json honoured by the CI action | T09 | D04 | G7-I023"]

  A0 --> P2["Agent step holds secrets or a write-scoped token in its environment | T07 | D07 | G7-I118"]

  A0 --> E1{"OR: egress or persistence channel"}
  E1 --> L4["Agent posts secrets into a comment or log | T09 | D08 | G7-I027"]
  E1 --> L5["Cache poisoning feeds a later privileged workflow | T09 | D08 | G2-I004"]
  E1 --> L6["Rendered image or fetched URL carries data out | T08 | D03 | G7-I044"]
  E1 --> L7["DNS or allowed-domain request from a command classed as safe | T08 | D03 | G2-I005"]

  classDef gate fill:#fde7c8,stroke:#b36b00,color:#222;
  classDef pre fill:#e6e6e6,stroke:#777,color:#222;
  class A0,P1,E1 gate;
  class P2 pre;
```

Cut set: because the root is an AND, the cheapest cut is removing P2 (no secrets or write token in
the agent step, D07 and D08) or restricting who can trigger the job (D08). Egress filtering (D03)
is a second independent cut.

---

## Tree 3: Persist across sessions through memory or configuration poisoning

```mermaid
flowchart TD
  G0["GOAL: attacker instructions survive restart and influence future sessions"]
  A0{"AND"}
  G0 --> A0
  A0 --> S1{"OR: one-time write channel"}
  S1 --> L1["Prompt injection leads the agent to write memory or summary content | T10 | D09 | G3-I011"]
  S1 --> L2["Injected agent edits its own settings or allowlist | T02 | D01 | G4-I036"]
  S1 --> L3["Malware writes into harness config files on disk | T06 | D13 | G7-I114"]
  S1 --> L4["Poisoned rules or instruction file committed to the repository | T01 | D04 | G6-073"]
  S1 --> L5["Context compression output retains attacker text | T10 | D09 | G3-I009"]

  A0 --> S2{"OR: store is loaded as trusted context"}
  S2 --> L6["Memory or instruction file auto-loaded with no user review | T10 | D09 | no incident"]
  S2 --> L7["Settings re-applied on next start including approval rules | T02 | D14 | G4-I018"]
  S2 --> L8["Scanner meant to block injection can be bypassed | T10 | D09 | G3-I011"]

  classDef gate fill:#fde7c8,stroke:#b36b00,color:#222;
  class A0,S1,S2 gate;
```

Cut set: either break the write channel (D01 approval for writes to memory/settings, D14 managed
policy that locks permissions) or make loading conditional on review (D09 visible, project-scoped,
editable memory). Content scanners are listed as a leaf because they have been bypassed; they
should not be counted as a cut.

---

## Tree 4: Compromise through the MCP, skill or plugin supply chain

```mermaid
flowchart TD
  G0["GOAL: attacker-controlled tool or skill runs with the developer's agent privileges"]
  O0{"OR"}
  G0 --> O0

  O0 --> A1{"AND: get the component installed"}
  A1 --> C1{"OR: distribution"}
  C1 --> L1["Malicious or typosquatted MCP package | T04 | D05 | G6-086"]
  C1 --> L2["Malicious skills in a public marketplace | T05 | D06 | G7-I081"]
  C1 --> L3["Poisoned extension in an extension registry | T05 | D06 | G6-088"]
  C1 --> L4["Plugin pin bypass installs different code | T05 | D06 | G1-I003"]
  A1 --> P1["Precondition: user or project config approves the component | T04 | D05 | G6-074"]

  O0 --> A2{"AND: change an approved component"}
  A2 --> P2["Precondition: component was approved once | T04 | D05 | G4-I001"]
  A2 --> L5["Definition or transport headers change after approval (rug pull, TOCTOU) | T04 | D05 | G5a-I13"]

  O0 --> A3{"AND: abuse protocol trust"}
  A3 --> L6["Server-chosen OAuth endpoint or metadata reaches client logic | T04 | D05 | G7-I096"]
  A3 --> L7["Install deeplink hides arguments in the dialog | T04 | D05 | G6-018"]

  O0 --> L8["Locally exposed MCP over HTTP without authentication | T18 | D16 | G7-I100"]

  classDef gate fill:#fde7c8,stroke:#b36b00,color:#222;
  classDef pre fill:#e6e6e6,stroke:#777,color:#222;
  class O0,A1,C1,A2,A3 gate;
  class P1,P2 pre;
```

Cut set: managed allowlists for servers and plugins (D05, D06, D14) cut branches A1 and A3;
re-approval on change plus pinning cuts A2 (D05, D13). Branch L8 is outside D05 and needs D16.

---

## Tree 5: Cross the approval or sandbox boundary

```mermaid
flowchart TD
  G0["GOAL: an agent action executes outside what the user or policy allowed"]
  O0{"OR"}
  G0 --> O0

  O0 --> A1{"AND: approval layer defeated"}
  A1 --> P1["Precondition: attacker influences command text, path or arguments | T01 | D01 | G1-I042"]
  A1 --> C1{"OR: flaw in the check"}
  C1 --> L1["Shell metacharacters, substitution or parameter expansion in an allowlisted command | T03 | D01 | G2-I011"]
  C1 --> L2["Prefix or regex allowlist and safe-command lists | T03 | D01 | G1-I023"]
  C1 --> L3["Symlink, junction or path-prefix confusion | T03 | D02 | G1-I018"]
  C1 --> L4["Environment-variable prefixes or builtins skip denylist | T03 | D01 | G7-I071"]
  C1 --> L5["Approval persisted for a path, then reused with different arguments | T03 | D01 | G7-I076"]

  O0 --> A2{"AND: sandbox boundary defeated"}
  A2 --> P2["Precondition: agent can run or write inside the sandbox | T17 | D02 | G1-I014"]
  A2 --> C2{"OR: escape route"}
  C2 --> L6["Write to a config or git hook that an unsandboxed component later honours | T17 | D02 | G4-I010"]
  C2 --> L7["Symlink or TOCTOU in path handling | T17 | D02 | G3-I020"]
  C2 --> L8["Weak fallback when container runtime is missing | T17 | D02 | G5b-I22"]
  C2 --> L9["Network or DNS leak in a sandbox that is meant to be offline | T17 | D03 | INC-G5c-08"]

  O0 --> L10["Policy not applied: managed settings skipped on one credential path | T03 | D14 | G1-I002"]

  classDef gate fill:#fde7c8,stroke:#b36b00,color:#222;
  classDef pre fill:#e6e6e6,stroke:#777,color:#222;
  class O0,A1,A2,C1,C2 gate;
  class P1,P2 pre;
```

Cut set: defence in depth is the only robust design: parsing-based approval (D01) fails often
(97 RC3 incidents in the dataset), so a default-on sandbox with a network allowlist (D02, D03)
and central policy (D14) should assume D01 will be bypassed.

---

## Tree 6: Take control of the agent through an exposed control plane

```mermaid
flowchart TD
  G0["GOAL: issue commands to a developer's agent or read its state remotely"]
  O0{"OR"}
  G0 --> O0

  O0 --> A1{"AND: browser as the bridge"}
  A1 --> P1["Precondition: victim visits an attacker web page while the harness runs | T18 | D16 | G1-I039"]
  A1 --> C1{"OR: local service flaw"}
  C1 --> L1["No authentication on a localhost HTTP API | T18 | D16 | G1-I039"]
  C1 --> L2["Cross-site WebSocket without Origin check | T18 | D16 | G2-I001"]
  C1 --> L3["DNS rebinding where Host validation is absent or off by default | T18 | D16 | G6-053"]
  C1 --> L4["Upgrade or install endpoint reachable cross-site | T18 | D16 | G1-I037"]

  O0 --> A2{"AND: network exposure"}
  A2 --> P2["Precondition: gateway or panel bound to a public interface | T18 | D16 | G3-I033"]
  A2 --> L5["No authentication, or token leaked through a URL parameter | T18 | D16 | G3-I015"]

  O0 --> L6["Authenticated but low-scope client escalates to admin through pairing or reconnect | T18 | D16 | G3-I027"]
  O0 --> L7["Webhook accepted without signature validation | T18 | D16 | G3-I019"]

  classDef gate fill:#fde7c8,stroke:#b36b00,color:#222;
  classDef pre fill:#e6e6e6,stroke:#777,color:#222;
  class O0,A1,A2,C1 gate;
  class P1,P2 pre;
```

Cut set: requiring a per-install secret or Unix-socket transport on every local API plus Host and
Origin validation removes branches A1 and A2 together; scope subsetting rules address L6. No D01-D15
control addresses this tree, which is why D16 is proposed.

---

## Tree 7: Steal developer and agent credentials through the harness distribution chain

```mermaid
flowchart TD
  G0["GOAL: harvest credentials from developer machines at scale through the harness ecosystem"]
  A0{"AND"}
  G0 --> A0

  A0 --> S1{"OR: attacker artifact reaches machines"}
  S1 --> L1["Maintainer account takeover or unauthorised publish of the harness package | T06 | D13 | G2-I003"]
  S1 --> L2["Typosquatted harness package | T06 | D13 | G7-I115"]
  S1 --> L3["Compromised dependency of tooling | T06 | D13 | G7-I111"]
  S1 --> L4["Self-propagating package worm | T06 | D13 | G6-078"]
  S1 --> L5["Trojanised vendor extension release | T06 | D13 | G6-071"]

  A0 --> S2{"OR: payload finds something to take"}
  S2 --> L6["Credentials in plaintext agent config files | T07 | D07 | G7-I113"]
  S2 --> L7["Installed AI CLI re-used with auto-approve flags | T06 | D01 | G6-077"]
  S2 --> L8["Worm writes into harness config for persistence | T06 | D14 | G7-I114"]

  classDef gate fill:#fde7c8,stroke:#b36b00,color:#222;
  class A0,S1,S2 gate;
```

Cut set: this is an AND of an inbound channel and an outbound target. Registry-side controls
(2FA, trusted publishing, provenance, D13) shrink S1; local controls (keychain storage and secret
protection D07, refusing bypass flags from non-interactive callers D01/D14) shrink S2 and are
within each harness vendor's control.
