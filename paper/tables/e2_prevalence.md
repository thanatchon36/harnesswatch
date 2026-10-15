E2 prevalence (2026-10-15): 1010 repositories, 1017 files audited.

| Rule | Title | Repos | Repo rate (95% CI) | Files |
|---|---|---:|---|---:|
| HG-MCP-005 | MCP server declared in a repository config | 311 | 30.8% (28.0-33.7) | 316 |
| HG-MCP-001 | MCP server fetched from a registry at launch without a version pin | 170 | 16.8% (14.6-19.3) | 173 |
| HG-CI-002 | Agent CI job runs with a write-scoped GITHUB_TOKEN | 112 | 11.1% (9.3-13.2) | 112 |
| HG-MCP-002 | Remote MCP server over plaintext HTTP, wildcard host, or without authentication | 86 | 8.5% (7.0-10.4) | 86 |
| HG-CI-001 | Headless agent in a workflow triggered by untrusted input ("pwn request") | 50 | 5.0% (3.8-6.5) | 50 |
| HG-HOOK-001 | Repository config defines hooks that execute shell commands | 43 | 4.3% (3.2-5.7) | 43 |
| HG-MCP-003 | Literal secret in an MCP server's env, headers or arguments | 21 | 2.1% (1.4-3.2) | 21 |
| HG-SEC-003 | Credential stored in plaintext in a harness config file | 14 | 1.4% (0.8-2.3) | 14 |
| HG-PERM-001 | Approve-everything (YOLO / bypass / full-auto) mode enabled in config | 12 | 1.2% (0.7-2.1) | 12 |
| HG-PERM-003 | Unrestricted execution without a deny list for destructive or credential-reading commands | 12 | 1.2% (0.7-2.1) | 12 |
| HG-NET-001 | Unrestricted network egress for agent tools where the harness supports restriction | 5 | 0.5% (0.2-1.1) | 5 |
| HG-MCP-006 | MCP servers or their tools are auto-approved without a per-server prompt | 3 | 0.3% (0.1-0.9) | 3 |
| HG-INJ-002 | Prompt-injection phrasing in an instruction file | 2 | 0.2% (0.1-0.7) | 2 |
| HG-SUB-001 | Sub-agent or delegated agent configured with bypass permissions | 2 | 0.2% (0.1-0.7) | 2 |
| HG-HOOK-002 | Hook command fetches or sends data over the network, or runs code fetched at runtime | 1 | 0.1% (0.0-0.6) | 1 |
| HG-INJ-001 | Hidden or confusable Unicode in an instruction file | 1 | 0.1% (0.0-0.6) | 1 |
| HG-MEM-001 | Persistent agent-writable memory enabled (or shared through version control) | 1 | 0.1% (0.0-0.6) | 1 |
| HG-PERM-002 | Over-broad tool allowlist | 1 | 0.1% (0.0-0.6) | 1 |
