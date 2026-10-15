# VERSIONS.md — exact versions analysed

Harness versions move monthly. Every claim in the paper refers to the version pinned here.
Status values: `analysed` (docs+source/package read), `bench` (also run in canary-bench),
`docs-only` (closed product, documentation-level analysis), `N/A (no access: <reason>)`.

## Local environment (2026-10-15)

| Component | Version |
|---|---|
| OS | Ubuntu 24.04.5 LTS on WSL2 (kernel 6.18.54.1-microsoft-standard-WSL2) |
| Python | 3.12.3 (uv 0.13.1) |
| Docker | 29.9.1 (NVIDIA runtime available) |
| Ollama (bench model server, container) | 0.40.4, image `ollama/ollama@sha256:926d40fd6eeeebd346b5c358a63de2a10ec995371cd93dd22f1843200694b1a6` |
| Claude Code (installed on host) | 2.1.300 |

## Harnesses

| harness | vendor | tier | license (verified) | version analysed | release date | status | source |
|---|---|---|---|---|---|---|---|
| aider | Aider-AI | A | Apache-2.0 (verified) | aider-chat 0.86.2 (PyPI); source 5dc9490 (0.86.3.dev) | 2026-02-12 (PyPI); last GitHub release v0.86.0 2025-08-09 | analysed (source read, not executed) | https://pypi.org/project/aider-chat/ |
| amp | Amp Inc. (spun out of Sourcegraph Dec 2025) | B | Proprietary (npm: SEE LICENSE IN LICENSE.md) | 0.0.1792036844-g99022c (npm @sourcegraph/amp latest) | 2026-10-15 | docs-only | https://registry.npmjs.org/@sourcegraph/amp |
| antigravity | Google | B | Proprietary (public repo google-antigravity/antigravity-cli = docs/issues/binaries only, no LICENSE; SDK license unverified) | CLI 1.3.5 (docs changelog lags at 1.3.1); app 2.23.1; IDE 2.5.5; SDK 0.1.21 | CLI 2026-10-14; app 2026-10-13; IDE 2026-08-13 | docs-only (pre-login observe planned, B2) | https://github.com/google-antigravity/antigravity-cli/releases/tag/1.3.5 ; https://antigravity.google/docs/changelog |
| augment | Augment Computing, Inc. | B | Custom proprietary (LICENSE.md in augmentcode/auggie) | 0.36.0 (npm @augmentcode/auggie latest; 0.37.0 prerelease) | 2026-08-21 | docs-only | https://registry.npmjs.org/@augmentcode/auggie |
| azure-ai-foundry-agent-service (now Microsoft Foundry Agent Service) | Microsoft | C | Proprietary hosted | docs updated 2026-10-15 | n/a | docs-only | https://learn.microsoft.com/en-us/azure/foundry/agents/overview |
| bedrock-agentcore (incl. Harness) | Amazon Web Services | C | Proprietary hosted; SDK and starter toolkit Apache-2.0 | harness GA (docs 2026-10-15) | n/a | docs-only | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html |
| claude-agent-sdk (Python `claude-agent-sdk`) | Anthropic | C | MIT LICENSE file in repo; README states use is governed by Anthropic Commercial Terms; bundles proprietary Claude Code CLI 2.1.300 | 0.2.167 (source read at main, 2026-10-15) | 2026-10-14 | docs-only (source read, not executed) | https://github.com/anthropics/claude-agent-sdk-python/releases/tag/v0.2.167 |
| claude-agent-sdk (TypeScript `@anthropic-ai/claude-agent-sdk`) | Anthropic | C | "All rights reserved", Commercial Terms (LICENSE.md); repo contains docs/changelog only (not OSS) | 0.3.300 (release tag v0.3.300) | 2026-10-14 | docs-only | https://github.com/anthropics/claude-agent-sdk-typescript |
| claude-code | Anthropic | B | Proprietary (GitHub API: no SPDX; public repo = changelog/issues/plugins only) | 2.1.300 (local install + latest GitHub release) | 2026-10-14 | analysed (docs + public repo + local structure) | https://github.com/anthropics/claude-code/releases/tag/v2.1.300 |
| claude-managed-agents | Anthropic | C | Proprietary hosted service | beta, header `managed-agents-2026-04-01` (memory: `agent-memory-2026-07-22`) | n/a (beta) | docs-only | https://platform.claude.com/docs/en/managed-agents/overview |
| cline | Cline Bot Inc. | A | Apache-2.0 (verified: LICENSE, GitHub API, npm) | VS Code ext 4.1.24; CLI cline@3.0.71; SDK 0.0.93; desktop 0.0.46 (source 789f79e) | 2026-10-13 | analysed (source read, not executed) | https://github.com/cline/cline/releases |
| codex-cli | OpenAI | A | Apache-2.0 | 0.162.1 (rust-v0.162.1; source read at main bb64b89) | 2026-10-09 | analysed (source + docs); Codex cloud/web/desktop = closed, docs-only | https://github.com/openai/codex/releases/tag/rust-v0.162.1 |
| continue | Continue Dev, Inc. | A | Apache-2.0 (verified) | @continuedev/cli 1.5.47; final v2.0.0/v2.1.0-vscode (source 5522c6f) | 2026-06-19 | analysed; repo no longer maintained (read-only) | https://github.com/continuedev/continue |
| copilot-studio (GitHub Copilot harness) | Microsoft | C | Proprietary SaaS | n/a (docs dated 2026-05..2026-10; harness GA per Sept 2 blog) | n/a | docs-only | https://learn.microsoft.com/en-us/microsoft-copilot-studio/harnesses-overview |
| crewai | CrewAI Inc. | C | MIT | 1.15.28 (HEAD 3da2d4e) | 2026-10-14 | analysed | https://github.com/crewAIInc/crewAI |
| crush | Charm | A | FSL-1.1-MIT (source-available, not OSI; GitHub shows NOASSERTION) | 0.98.1 (source read at main f49b281) | 2026-10-09 | analysed (source + docs) | https://github.com/charmbracelet/crush/releases/tag/v0.98.1 |
| cursor | Anysphere | B | Proprietary (no source; github.com/cursor/cursor is advisories/issues only) | docs-level; docs changelog references Cursor 3.23; CLI build 2026.08.11-e8db854 (third-party tracker, unverified) | 3.23: 2026-10-01 (docs) | docs-only | https://cursor.com/docs/agent/security/run-modes |
| deepagents | LangChain | C | MIT | deepagents 0.7.25 / deepagents-code 0.1.85 | 2026-10-14 | analysed | https://github.com/langchain-ai/deepagents/releases |
| deepseek-harness | DeepSeek AI | A | MIT | 0.2.1-alpha.3 (npm tag alpha; repo tag dsh-v0.2.1-alpha.3, commit 57190202) | 2026-10-14 | analysed (developer preview; npm `latest` = 0.2.0-rc.2, 2026-09-29) | https://github.com/deepseek-ai/deepseek-harness |
| devin | Cognition | B | Proprietary | Devin CLI v3000.11.3 | 2026-09-22 | docs-only | https://docs.devin.ai/cli/changelog/stable.md |
| factory-droid | Factory AI | B | Proprietary (npm droid: UNLICENSED) | 0.242.0 (CLI) | 2026-10-15 | docs-only | https://docs.factory.com/changelog/release-notes.md ; https://registry.npmjs.org/droid |
| gemini-cli | Google | A | Apache-2.0 | 0.64.0 (source read at main 06d3298) | 2026-10-13 | analysed; consumer service ended 2026-06-18 (verified), enterprise/API continue | https://github.com/google-gemini/gemini-cli/releases/tag/v0.64.0 |
| github-copilot | GitHub (Microsoft) | B | Proprietary; Copilot CLI custom 'GitHub Copilot CLI License' (SPDX NOASSERTION) | copilot-cli v1.0.98 | 2026-10-14 | docs-only | https://api.github.com/repos/github/copilot-cli/releases/latest |
| github-copilot-sdk | GitHub | C | MIT (SDKs; bundled Copilot CLI runtime not in repo) | 1.0.22 (HEAD 5817ec0) | 2026-10-14 | analysed | https://github.com/github/copilot-sdk |
| google-adk | Google | C | Apache-2.0 | 2.12.0 (2.0.0 GA 2026-05-19) | 2026-10-13 | analysed | https://github.com/google/adk-python/releases |
| goose | AAIF (originated by Block) | A | Apache-2.0 (verified) | v1.54.0 (source dd17bf2, workspace 1.55.0) | 2026-10-08 | analysed (source read, not executed) | https://github.com/aaif-goose/goose/releases |
| grok-build | SpaceXAI (xAI) | A/B hybrid (source read white-box at 1.0.45; the public tree lags the npm release and its build injects endpoints at build time → the shipped npm binary is observed black-box; MISSION listed B) | Apache-2.0 (repo LICENSE + npm license field) | 1.0.52 (npm @xai-official/grok latest; 1.0.60 alpha 2026-10-15); public source HEAD 2bdd1d6a = crate 1.0.45 (2026-09-29, SOURCE_REV 559751fd); no git tags/releases | 2026-10-11 | docs-only + source read (B3, 2026-10-15); local-model bench path identified, not yet run | https://registry.npmjs.org/@xai-official/grok ; https://github.com/xai-org/grok-build ; evidence/research/B3_observe_plan.md |
| hermes-agent | Nous Research | A | MIT | 0.22.1 (commit 7bda2a33) | 2026-10-14 | analysed | https://github.com/NousResearch/hermes-agent |
| jules | Google | B | Proprietary (npm @google/jules has no license field) | Jules Tools 0.1.42; service changelog newest 2026-03-09 | CLI pkg modified 2025-12-16 | docs-only (Oct 2026 status unverified, docs live) | https://jules.google/docs/changelog/ |
| junie | JetBrains | B | Proprietary (JetBrains AI Service ToS; JetBrains/junie repo = installers only) | release tag 3800.1 (npm @jetbrains/junie 3110.7.0) | 2026-10-14 | docs-only | https://github.com/JetBrains/junie |
| kilo-code | Kilo Code (Kilo-Org) | A | MIT (verified; MISSION.md said Apache-2.0) | v7.8.10 (source a72ad30); JetBrains v7.1.10-rc.4 | 2026-10-14 | analysed (source read, not executed) | https://github.com/Kilo-Org/kilocode/releases |
| kimi-cli | Moonshot AI | A | MIT (kimi-code); legacy kimi-cli Apache-2.0 archived | kimi-code 2.2.0 (commit b260326); legacy kimi-cli 1.52.0 | 2026-10-14 (legacy 2026-09-22) | analysed (successor product; legacy repo archived) | https://github.com/MoonshotAI/kimi-code |
| kiro | AWS | B | Proprietary (EULA not read) | IDE 1.3.0; CLI 2.31.0 (V3 engine opt-in) | 2026-10-13 | docs-only | https://kiro.dev/changelog/ |
| langgraph | LangChain | C | MIT | 1.2.15 (1.0.0 2025-10-17) | 2026-10-12 | analysed | https://github.com/langchain-ai/langgraph/releases |
| langgraph-platform (LangSmith Deployment / Agent Server) | LangChain | C | langgraph MIT (GitHub API); langgraph-api Elastic-2.0 (PyPI); platform proprietary/Enterprise | langgraph 1.2.15, langgraph-api 0.16.0, langgraph-cli 0.4.35 | 2026-10-14/15 (PyPI/GitHub) | docs-only | https://pypi.org/pypi/langgraph-api/json ; https://github.com/langchain-ai/langgraph |
| manus | Butterfly Effect (Manus) | C | Proprietary SaaS | n/a | n/a | docs-only | https://manus.im/security |
| microsoft-agent-framework | Microsoft | C | MIT | python agent-framework-core 1.21.0 / dotnet 1.25.0 (1.0 GA 2026-04-02) | 2026-10-14 | analysed | https://github.com/microsoft/agent-framework/releases |
| mistral-vibe | Mistral AI | A | Apache-2.0 | 2.26.1 (commit 4ae5c59) | 2026-10-09 | analysed | https://github.com/mistralai/mistral-vibe |
| oh-my-pi | Stencil Labs (Can Bölük) | A | MIT | 18.11.0 (commit c2cb79e) | 2026-10-14 | analysed | https://github.com/can1357/oh-my-pi |
| openai-agentkit | OpenAI | C | Proprietary hosted; ChatKit Apache-2.0, openai-guardrails-python MIT | Agent Builder scheduled shutdown 2026-11-30 | n/a | docs-only (product winding down) | https://developers.openai.com/api/docs/guides/agent-builder |
| openai-agents-sdk | OpenAI | C | MIT | 0.24.0 (JS sibling 0.20.0) | 2026-10-15 (JS 2026-10-08) | analysed | https://github.com/openai/openai-agents-python/releases/tag/v0.24.0 |
| openclaw | OpenClaw project | A | MIT | 2026.10.3 (commit b325a926) | 2026-10-13 | analysed | https://github.com/openclaw/openclaw |
| opencode | anomalyco (formerly SST; `sst/opencode` redirects to `anomalyco/opencode`) | A | MIT | 1.19.0 (tag v1.19.0 source; `dev` branch is a v2 rewrite, not analysed) | 2026-10-11 | analysed (source + docs) | https://github.com/anomalyco/opencode/releases/tag/v1.19.0 |
| openhands | OpenHands (All Hands AI) | A | MIT (verified, 3 repos) | Agent Canvas v1.27.1; Software Agent SDK v1.54.0; OpenHands-CLI 1.16.0 | 2026-10-12 (Canvas); 2026-10-09 (SDK); 2026-05-08 (CLI) | analysed; CLI no longer maintained; SDK tracked separately in openhands-sdk profile | https://github.com/OpenHands/OpenHands/releases |
| openhands-sdk | All Hands AI | C | MIT | 1.54.0 (HEAD 8efff8d) | 2026-10-09 | analysed | https://github.com/OpenHands/software-agent-sdk |
| pi | Earendil Works (Mario Zechner) | A | MIT | 1.2.0 (commit b06c1f2) | 2026-10-12 | analysed | https://github.com/earendil-works/pi |
| pydantic-ai | Pydantic Services | C | MIT | 2.56.0 (source HEAD 9ac853b, 2026-10-14) | 2026-10-13 | analysed | https://github.com/pydantic/pydantic-ai |
| qoder (CLI; also IDE/desktop) | Alibaba (Qoder) | B | Proprietary; npm package declares none; QoderAI/qoder-action MIT (GitHub API) | none executed; docs/npm latest CLI 1.1.71 | 2026-10-14 | docs-only | https://docs.qoder.com/release-notes/qoder-cli.md ; npm view @qoder-ai/qodercli |
| qwen-code | Alibaba (Qwen) | A | Apache-2.0 | 0.25.1 (source read at main 0ed9976; 0.25.2-preview.0 out 2026-10-13) | 2026-10-11 | analysed (source + docs) | https://github.com/QwenLM/qwen-code/releases/tag/v0.25.1 |
| raven-evermind | EverMind | C | Apache-2.0 (pyproject + LICENSE agree at HEAD; no conflict found) | 0.2.4 (HEAD 2a139f8) | 2026-10-03 | analysed (pre-alpha per README) | https://github.com/EverMind-AI/Raven |
| replit-agent | Replit | B | Proprietary SaaS | n/a (cloud) | n/a | docs-only | https://docs.replit.com/llms.txt |
| roo-code | Roo Code, Inc. | A | Apache-2.0 (verified) | 3.54.0 final (src/package.json 3.53.0 at HEAD b867ec9); @roo-code/cli 0.1.17 | 2026-05-15 | analysed; PRODUCT DISCONTINUED, repo archived | https://github.com/RooCodeInc/Roo-Code |
| smolagents | Hugging Face | C | Apache-2.0 | main 1.27.0.dev0 (96f33fa); latest release 1.26.0 | 2026-05-29 (1.26.0) | analysed | https://github.com/huggingface/smolagents |
| strands-agents | AWS / strands-agents org | C | Apache-2.0 | strands-agents 1.61.0 / strands-harness 0.3.0 | 2026-10-14 | analysed (repo renamed to harness-sdk) | https://github.com/strands-agents/harness-sdk |
| trae (IDE / all-new TRAE) | ByteDance | B | Proprietary | none executed; docs changelog TRAE v3.6.0 | 2026-10-08 | docs-only | https://docs.trae.ai/ide/changelog |
| trae-agent (open-source sibling, in trae profile extra) | ByteDance | B (OSS) | MIT (GitHub API) | 0.1.0 at HEAD e839e559ac61bdd0e057c375dd1dee391fee797d (source read, not run) | last push 2026-02-05 (no tags/releases) | analysed (source) | https://github.com/bytedance/trae-agent |
| trueforge | TrueFoundry | C | MIT | @truefoundry/trueforge 0.179.1 (HEAD d3d80a2) | 2026-10-14 (npm created 2026-08-13; repo 2026-07-23) | analysed | https://github.com/truefoundry/trueforge |
| vertex-ai-agent-engine (now Agent Runtime in Gemini Enterprise Agent Platform) | Google Cloud | C | Proprietary hosted | docs as of 2026-10-15 (renamed 2026-04-22) | n/a | docs-only | https://docs.cloud.google.com/gemini-enterprise-agent-platform/release-notes |
| warp | Warp (Denver Technologies, Inc.) | A (open-core) | AGPL-3.0 for repo + MIT for warpui_core/warpui crates only (verified; MISSION 'MIT + AGPL' confirmed with scope clarified) | stable v0.2026.06.03.09.49.stable_00 (source dc0b890) | 2026-06-03 | analysed client only; server/Oz/Drive closed | https://github.com/warpdotdev/warp/releases |
| windsurf | Cognition | B | Proprietary | Devin Desktop v3.10.67 (Windsurf renamed 2026-06-02) | 2026-10-12 | docs-only (renamed) | https://docs.devin.ai/desktop/changelog.md |
