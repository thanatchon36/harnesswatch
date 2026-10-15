| Rule | Severity | Confidence | Kind | Taxonomy | Title |
|---|---|---|---|---|---|
| HG-CI-001 | high | high | vulnerability-pattern | T09, T01, T08 | Headless agent in a workflow triggered by untrusted input ("pwn request") |
| HG-CI-002 | medium | medium | design-weakness | T09, T14 | Agent CI job runs with a write-scoped GITHUB_TOKEN |
| HG-HOOK-001 | medium | high | design-weakness | T02 | Repository config defines hooks that execute shell commands |
| HG-HOOK-002 | medium | medium | vulnerability-pattern | T02, T06, T08 | Hook command fetches or sends data over the network, or runs code fetched at runtime |
| HG-INJ-001 | medium | high | vulnerability-pattern | T01, T05 | Hidden or confusable Unicode in an instruction file |
| HG-INJ-002 | medium | medium | vulnerability-pattern | T01, T05, T08 | Prompt-injection phrasing in an instruction file |
| HG-INJ-003 | medium | medium | design-weakness | T01, T06 | Instruction file pulls remote content at load time |
| HG-MCP-001 | medium | high | vulnerability-pattern | T04, T06 | MCP server fetched from a registry at launch without a version pin |
| HG-MCP-002 | medium | medium | vulnerability-pattern | T04, T08 | Remote MCP server over plaintext HTTP, wildcard host, or without authentication |
| HG-MCP-003 | high | medium | vulnerability-pattern | T07, T04 | Literal secret in an MCP server's env, headers or arguments |
| HG-MCP-004 | medium | medium | vulnerability-pattern | T04, T01 | MCP tool description contains instruction-like content (tool poisoning) |
| HG-MCP-005 | low | high | design-weakness | T02, T04 | MCP server declared in a repository config |
| HG-MCP-006 | high | high | design-weakness | T02, T04, T03 | MCP servers or their tools are auto-approved without a per-server prompt |
| HG-MEM-001 | low | medium | design-weakness | T10 | Persistent agent-writable memory enabled (or shared through version control) |
| HG-NET-001 | low | medium | design-weakness | T08 | Unrestricted network egress for agent tools where the harness supports restriction |
| HG-PERM-001 | medium | high | design-weakness | T03, T14, T01 | Approve-everything (YOLO / bypass / full-auto) mode enabled in config |
| HG-PERM-002 | medium | high | design-weakness | T03, T14 | Over-broad tool allowlist |
| HG-PERM-003 | medium | medium | design-weakness | T14, T07 | Unrestricted execution without a deny list for destructive or credential-reading commands |
| HG-SEC-001 | high | medium | design-weakness | T07 | Secret-like strings in harness logs, transcripts or memory |
| HG-SEC-002 | medium | high | design-weakness | T07 | Harness state or credential file readable by other users |
| HG-SEC-003 | high | medium | design-weakness | T07 | Credential stored in plaintext in a harness config file |
| HG-SUB-001 | medium | medium | design-weakness | T11, T03 | Sub-agent or delegated agent configured with bypass permissions |
| HG-SUP-001 | low | medium | design-weakness | T06 | Harness installed through a `curl \| sh` installer without checksum or signature verification |
| HG-SUP-002 | high | high | vulnerability-pattern | T06 | Installed harness package version has known vulnerabilities (OSV) |
| HG-TEL-001 | info | high | policy | T15 | Telemetry, prompt logging or data sharing explicitly enabled |
