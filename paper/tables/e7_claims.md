| Harness | Claim | Dimension | Observed | Verdict |
|---|---|---|---|---|
| antigravity | CVO-B2-003 | update_check | background updater contacted: antigravity-cli-auto-updater-974169037036.us-central1.run.app:443; last_check.timestamp: yes; updater lock files: yes | match |
| antigravity | CVO-B2-004 | update_check | with AGY_CLI_DISABLE_AUTO_UPDATE=true, updater host contacted: none | match |
| antigravity | CVO-B2-005 | telemetry_hosts | before any login, telemetry/logging hosts attempted: play.googleapis.com:443 (default enableTelemetry=true) | match |
| antigravity | CVO-B2-013 | state_dir_perms | pre-login files under ~/.gemini: 35; other-user-readable: 32 | partial |
| antigravity | CVO-B2-015 | permission_default | unauthenticated headless run: exit 1, auth-required message: yes, duration 62.6 s | match |
| antigravity | CVO-B2-016 | permission_default | `agy -p /help` without credentials: exit 1, auth required: yes | mismatch |
| antigravity | CVO-B2-023 | mcp_trust | before login/trust: repo .agents MCP server started: no; repo hook ran: no | partial |
| claude-code | CVO-B1-001 | telemetry_hosts | vendor hosts attempted: api.anthropic.com:443 | match |
| claude-code | CVO-B1-002 | telemetry_hosts | with a gateway base URL, Datadog intake contacted: no | match |
| claude-code | CVO-B1-003 | telemetry_hosts | vendor hosts attempted: none | match |
| claude-code | CVO-B1-005 | update_check | no update-check host contacted during a headless (-p) session | not-observed |
| claude-code | CVO-B1-008 | config_trust | repo env ANTHROPIC_BASE_URL followed: yes; repo env CLAUDE_CONFIG_DIR applied: no | match |
| claude-code | CVO-B1-010 | hooks_trust | repo SessionStart hook ran under -p, untrusted: yes (cc-repo-hook) | match |
| claude-code | CVO-B1-012 | mcp_trust | repo .mcp.json stdio server started without prompt: yes; init status [{'name': 'hw', 'status': 'pending', 'source': 'project'}] | match |
| claude-code | CVO-B1-015 | config_trust | repo hook ran with --bare: no (cc-repo-hook-bare) | match |
| claude-code | CVO-B1-018 | secret_storage | credential files written with ANTHROPIC_AUTH_TOKEN: none | match |
| claude-code | CVO-B1-020 | permission_default | init permissionMode with a third-party base URL: auto | match |
| claude-code | CVO-B1-021 | permission_default | --dangerously-skip-permissions as uid 0 refused: yes | match |
| claude-code | CVO-B1-022 | permission_default | repo permissions.defaultMode=bypassPermissions -> init permissionMode default | match |
| claude-code | CVO-B1-023 | state_dir_perms | transcripts written: 1 (modes 0o600); other-user-readable files under ~/.claude: 2 | match |
| claude-code | CVO-HW-001 | config_trust | @.env inside a CLAUDE.md command line imported the gitignored .env into the session transcript without a model call or prompt: yes | match |
| github-copilot | B4-C008 | telemetry_hosts | COPILOT_OFFLINE=true vendor hosts: none; without it (BYOK): api.github.com:443 | match |
| github-copilot | B4-C009 | config_trust | repo .mcp.json server started in an untrusted folder (-p): no | match |
| github-copilot | B4-C010 | hooks_trust | repo .github/hooks sessionStart hook ran in -p: no | not-observed |
| grok-build | B3-C001 | telemetry_hosts | vendor hosts attempted with a custom local model and no login: none | match |
| grok-build | B3-C009 | hooks_trust | repo hook ran untrusted: no; with --trust: yes; .claude/settings.json compat hook untrusted: no | match |
| grok-build | B3-C011 | mcp_trust | project .mcp.json (compat import) server started in an untrusted folder: no | partial |
| grok-build | B3-C016 | secret_storage | files written under ~/.grok: 53; other-user-readable: 35 (session files among them: 0) | match |
