# LinkedIn announcement (draft; not posted)

**The harness is the attack surface.**

Most security discussion about AI coding agents is about the model. In 2025–2026 the incidents moved to the
*harness*: the runtime around the model that holds credentials, runs shell commands, loads repository
configuration, starts MCP servers and runs unattended in CI.

I've released two things, free and open (Apache-2.0):

🔧 **harnesswatch**: a Python CLI (`pip install harnesswatch`) that audits harness configuration across 58 tools, including Claude Code,
Codex, Cursor, Copilot, Kiro, Grok Build, Antigravity, OpenCode, Goose and Aider. It looks for auto-approve modes,
repository hooks, unpinned MCP servers, injection indicators, secret residue and risky CI patterns, and outputs SARIF for GitHub
code scanning. It also has a sandboxed black-box probe that checks what closed-source clients actually do.

📄 **The Harness Is the Attack Surface (2025–2026)**: a paper with a threat taxonomy, a control matrix, a survey
of verified incidents, a public-repo configuration study, a sandboxed prompt-injection benchmark, and a
comparison of vendors' documented controls with observed client behaviour. It comes with a 2-page executive brief and a
30-control governance checklist mapped to NIST AI RMF, ISO 42001, OWASP, MITRE ATLAS and MAS guidelines.

Every number in the paper is generated from published results files, and every claim carries an evidence label.

Links: GitHub · docs · paper (arXiv) · brief  ← fill in after publishing

#AISecurity #AppSec #AIAgents #MCP #DevSecOps
