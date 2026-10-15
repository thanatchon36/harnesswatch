# harnesswatch

Security audit toolkit and research project for **AI coding-agent harnesses**: the runtime loop
(Claude Code, Codex CLI, OpenCode, Cursor, Copilot, Kiro, Goose, Aider and others) that holds
credentials, runs shell commands, mounts MCP servers and reads repository-level config.

The package and CLI are named `harnesswatch`; rule IDs keep the `HG-` prefix.

What it does:

- **Inventory** the harnesses installed on a machine and the harness files in a repository.
- **Audit** configs, MCP declarations, instruction files and CI workflows, offline and read-only.
- **Observe** a harness black-box in a sandbox: hosts contacted, files written, prompts shown.
- **Bench** inert canary prompt-injection scenarios across harnesses (in progress).
- Report in Rich, JSON, Markdown or SARIF.

Start with the [quickstart](quickstart.md). Rules are listed in the [rule reference](reference/rules.md),
and the [threat taxonomy](taxonomy.md) explains what they map to.

!!! note "Status"
    Pre-0.1.0. The project is under construction; see `MISSION.md` and `PROGRESS.md` in the repository.
