# Harness profile schema (`rules/harness_profiles/<id>.yaml`)

One YAML file per harness. Profiles are **data**: the rules engine, `inventory`, and the
parsers read them, so every path/flag must be verified against current docs or source.
Unknown → omit the key or use `null`; never guess. Every non-trivial fact goes in `sources`.

```yaml
id: claude-code                 # kebab-case, stable; used everywhere (matrix, bench, findings)
name: Claude Code
vendor: Anthropic
tier: B                          # A (open source) | B (closed product) | C (runtime/SDK)
license: Proprietary             # SPDX id where applicable, else free text
open_source: false
status: analysed                 # analysed | docs-only | N/A (no access: <reason>) | unverified-existence
version_analysed: "2.1.300"      # exact version string, or null for docs-only
analysed_on: "2026-10-15"
homepage: https://...
repo: https://github.com/...     # null when closed

binaries: [claude]               # names looked up on PATH by `inventory`
packages:                        # distribution channels (for SBOM / supply audit)
  - {ecosystem: npm, name: "@anthropic-ai/claude-code"}
install_methods:                 # observed official install methods
  - {method: curl-installer, command: "curl -fsSL https://claude.ai/install.sh | bash", checksum_verified: true|false|null, signed: true|false|null, source: https://...}
  - {method: npm, command: "npm install -g @anthropic-ai/claude-code"}
auto_update: {default: true, config: "autoUpdates (settings.json) / DISABLE_AUTOUPDATER env", source: https://...}

state_dirs: ["~/.claude"]        # `~` = home; `$XDG_CONFIG_HOME` allowed
credential_files: ["~/.claude/.credentials.json"]   # where tokens/keys live when not in OS keychain
credential_storage: "macOS Keychain; plaintext 0600 file on Linux"     # prose
log_paths: ["~/.claude/projects/*/*.jsonl"]          # transcripts / session logs / trajectories (globs)
memory_paths: ["~/.claude/CLAUDE.md"]                # persistent memory files (globs)

config_files:                    # every settings/MCP/hooks/rules file the harness reads
  - path: "~/.claude/settings.json"     # home-relative (user scope) …
    scope: user                         # user | project | project-local | managed (admin/system) | env
    format: json                        # json | jsonc | toml | yaml | markdown | ini | env
    kind: settings                      # settings | mcp | hooks | instructions | rules | skills | agents | ignore
  - path: ".claude/settings.json"       # … or repo-relative (project scope)
    scope: project
    format: json
    kind: settings

instruction_files: ["CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md?"]  # repo-relative names/globs auto-loaded into context
skills_paths: [".claude/skills/*/SKILL.md", "~/.claude/skills/*/SKILL.md"]

mcp:
  files: [".mcp.json", "~/.claude.json"]  # files that declare MCP servers
  servers_key: "mcpServers"               # dotted key to the name->server map ("" when the file root is the map)
  server_fields:                          # how a server entry is spelled in this harness
    command: command
    args: args
    env: env
    url: url
    headers: headers
    type: type
  project_servers_require_approval: true  # true/false/null + source
  notes: "..."

permissions:
  config_keys:                    # dotted keys inside the settings file(s)
    mode: "permissions.defaultMode"
    allow: "permissions.allow"
    deny: "permissions.deny"
  default_mode: "default"         # what ships out of the box
  auto_approve_values:            # config values that mean "approve everything"
    - {key: "permissions.defaultMode", value: "bypassPermissions"}
  cli_flags_auto_approve: ["--dangerously-skip-permissions"]
  allow_rule_syntax: "Bash(npm run test:*)"   # example of an allowlist entry
  overbroad_patterns: ["Bash(*)", "Bash", "*"]

hooks:
  supported: true
  config_key: "hooks"             # where hooks live in settings
  repo_scoped_allowed: true       # can a checked-in project file define hooks?
  command_field: "command"

sandbox: {available: true, default_on: false, mechanism: "bubblewrap (Linux) / Seatbelt (macOS)", config: "sandbox.enabled", source: https://...}
network: {domain_allowlist: true, config: "...", default: "...", source: https://...}
workspace_trust: {prompt_on_new_folder: true, notes: "...", source: https://...}
memory: {persistent: true, cross_project: true, agent_writable: true, notes: "...", source: https://...}
subagents: {supported: true, inherits_permissions: "...", notes: "...", source: https://...}
telemetry: {default_on: true, opt_out: "DISABLE_TELEMETRY=1 / CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", training_default: "...", source: https://...}
headless:
  command: "claude -p"            # verified non-interactive invocation
  flags: ["--output-format json", "--permission-mode", "--allowedTools"]
  ci_integrations: ["anthropics/claude-code-action"]   # official GitHub Actions/GitLab templates
  model_override: "--model / ANTHROPIC_BASE_URL"       # how to point it at another model/endpoint (bench needs this)
  local_model_support: "Anthropic-compatible endpoint via ANTHROPIC_BASE_URL"   # can it use Ollama / OpenAI-compatible local servers?

security_policy: {security_md: https://..., bug_bounty: https://... | null, advisories: https://...}
sources:                          # all URLs consulted, with access date
  - {url: https://docs..., accessed: "2026-10-15", note: "settings reference"}
```

Keys may be omitted when not applicable. Add harness-specific keys under `extra:`.
