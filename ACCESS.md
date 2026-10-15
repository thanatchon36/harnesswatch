# ACCESS.md — what this run can reach (MISSION §1, §9 Phase 0)

Detected 2026-10-15 on the WSL2 dev box (A03). Detection only checks that binaries and files exist, plus
non-secret account metadata. **No token, key or credential content was read, printed or copied.**
Our rule (A05, A16): the author's own logins stay on the host. They are never mounted into a
bench or `observe` container, so a harness that needs a vendor login gets no vendor-model run
here. Where a harness supports a custom or local model endpoint, its bench and `observe` cells
use the project's private Ollama container (no account, $0).

| Harness | Tier | Installed here | Vendor login here | What we can test (method) | Status |
|---|---|---|---|---|---|
| Claude Code | B | yes: `~/.local/bin/claude` 2.1.300, native installer | yes: Claude Max subscription OAuth (`~/.claude/.credentials.json`, mode 0600); no `ANTHROPIC_API_KEY` | Black-box only. We install the official npm package in a container and point it at local Ollama through `ANTHROPIC_BASE_URL` (documented LLM-gateway feature), then run `observe` and the bench. The subscription is not used for automated runs (A05). | **reachable** (local model) |
| Google Antigravity CLI (`agy`) | B | no | no Google login on this machine | Package and installer metadata, plus `observe` of install and first run without credentials (hosts contacted, files written). Docs say a headless non-TTY run without cached credentials exits "authentication required", and the CLI has no documented OpenAI or Ollama endpoint (Gemini-compatible base URL only). | **partial**: bench `N/A (no access: needs a Google account login; no local-model path)` |
| Google Antigravity IDE | B | no | no | Needs a GUI session and a Google login. The IDE is not installed on the Windows host. | `N/A (no access: not installed, needs a GUI session and a Google login)`; docs-only (Tier C method) |
| xAI Grok Build (`grok`) | B (MISSION) / source public (see A18) | no | no SuperGrok-tier account | Docs say `[model.<name>] base_url` custom models are supported, which is a possible Ollama path without an xAI login. We will verify in a container. Package metadata, `observe` and the bench if a custom-model run works without login. | **to verify in container**; vendor-model cells `N/A (no access: no SuperGrok-tier account)` |
| Cursor CLI (`agent`) | B | no (the Cursor IDE is installed on the Windows host and is not used) | no CLI login in WSL | No documented local-model path; requests go through the Cursor backend. | `N/A (no access: needs a Cursor account; no local-model path)`; installer metadata and `observe` of the pre-login run only |
| GitHub Copilot CLI | B | no (a Windows-side `~/.copilot` dir exists; not used) | `gh` is logged in, but that token is the author's real credential and is never put into a container (§8.3) | BYOK and local-model support to verify. | Bench `N/A (no access: needs a Copilot entitlement; author's token not used)` unless BYOK works without login |
| AWS Kiro CLI | B | no | no | Kiro-hosted models only (docs). | `N/A (no access: needs an AWS Builder ID / Kiro login; no local-model path)`; installer metadata only |
| Amp, Factory Droid, Augment (Auggie), Qoder, Junie, Jules, Trae, Windsurf/Devin Desktop | B | no | no | Package metadata and docs. BYOK and local-model paths are checked per harness in Phase 1b (B4). | `N/A (no access: vendor account required)` unless B4 finds a no-login local-model path |
| Tier A harnesses (OpenCode, Codex CLI, Goose, Aider, Qwen Code, Crush, Kilo, …) | A | not on host (A06) | none needed | Installed inside bench images; local Ollama models | reachable |

Vendor API keys in the environment: none (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`,
`GOOGLE_API_KEY`, `XAI_API_KEY` and `GITHUB_TOKEN` are all unset).

Model backend: project-owned `hw-ollama` container (A07). Its GPU is shared with a process outside this
project; see A15.
