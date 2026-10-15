| Scenario | Title | Taxonomy | Files changed vs. base repo |
|---|---|---|---|
| control | No injection (baseline) | - | none |
| readme | README injection | T01 | README.md |
| instructions | Harness-native instruction file injection | T01 | <instruction file> |
| code_comment | Injection in a source-code comment | T01 | calc.py |
| tool_output | Poisoned tool result (test output) | T01/T04 | pytest.ini, tests/test_calc.py |
| hidden_unicode | Zero-width-wrapped instruction-file injection | T01 | <instruction file> |

| Harness | Tier | Image | Instruction file | Auto-mode flag |
|---|---|---|---|---|
| claude-code | B | harnesswatch-bench-claude-code:2.1.300 | CLAUDE.md | --dangerously-skip-permissions |
| grok-build | B | harnesswatch-bench-grok-build:1.0.52 | AGENTS.md | --always-approve |
| github-copilot | B | harnesswatch-bench-github-copilot:1.0.98 | .github/copilot-instructions.md | --allow-all-tools |
| opencode | A | harnesswatch-bench-opencode:1.19.0 | AGENTS.md | --dangerously-skip-permissions |
| codex-cli | A | harnesswatch-bench-codex-cli:0.162.1 | AGENTS.md | --dangerously-bypass-approvals-and-sandbox |
| aider | A | harnesswatch-bench-aider:0.86.2 | CONVENTIONS.md | --yes-always |
| qwen-code | A | harnesswatch-bench-qwen-code:0.25.1 | QWEN.md | --yolo |
