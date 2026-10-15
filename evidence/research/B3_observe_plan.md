# B3 — Grok Build (`grok`): tier verdict and observe/bench plan (accessed 2026-10-15)

Labels: FOD = from-official-docs (A09: vendor docs, vendor source and registry metadata), TPR = third-party-report,
UNV = unverified. Nothing was installed or run on the host. No xAI login was used. The npm tarballs were fetched with
`npm pack --ignore-scripts` in a throwaway `node:22-slim` container (A06).

Source citations below are to `xai-org/grok-build` at HEAD `2bdd1d6a` (2026-09-29, crate version 1.0.45,
`SOURCE_REV 559751fd`), paths relative to `crates/codegen/` unless they start with `crates/`. Apache-2.0, © 2023-2026 SpaceXAI.

## 1. Open-source status and tier

| Check | Finding | Label |
|---|---|---|
| Repo | `xai-org/grok-build`, SPDX `Apache-2.0` (LICENSE: "Copyright 2023-2026 SpaceXAI"), Rust, 27.4k stars, not archived | FOD (GitHub API) |
| Dates | Repo created 2026-07-14T20:04Z. First commit `c68e39f6` "Publish harness and TUI open-source" 2026-07-16T05:46Z (22:46 on 07-15 US Pacific, which matches the press date of 07-15). 51 commits, all "Synced from monorepo" by `grokkybara[bot]`. Last push 2026-09-29. | FOD |
| Releases/tags | None. Versions are inferred only from `crates/codegen/xai-grok-version/Cargo.toml` per sync: 0.2.101 (07-16) … 1.0.0 (08-07) … 1.0.45 (09-29). | FOD |
| npm | `@xai-official/grok`: `latest` 1.0.52 (2026-10-11), `alpha` 1.0.60 (2026-10-15), 607 versions since 2025-10-22, maintainer `xai-security <security@x.ai>`, license Apache-2.0, **no `repository` field, no gitHead, no provenance attestation** (registry signatures only). Wrapper (5 files) plus a `postinstall` that brotli-decompresses the binary from `@xai-official/grok-<os>-<arch>` into `~/.grok/bin/grok-<ver>` and writes `[cli] installer = "npm"` (and `npm_registry` if set) into `~/.grok/config.toml`. Platform package `latest` tag is stale (0.1.220); the wrapper pins its exact version. | FOD |
| Repo vs npm version | The repo lags: source 1.0.45 vs npm latest 1.0.52 and alpha 1.0.60. Each sync carries the crate version of an npm release already published hours before it (for example npm 1.0.45 at 09-29T06:10Z, sync at 09-29T11:19Z). | FOD |
| Is npm built from this source? | **Only partly.** The `linux-x64` 1.0.45 binary (static-pie ELF, 188 MB, version string `1.0.45 (c33bff361a6f)`) embeds Rust source paths of **12 crates that are not in the public tree** at the same version: `grove`, `grove-daemon-db`, `grove-git`, `grove-git-api`, `grove-shm`, `xai-agent-host-state`, `xai-agent-host-transport`, `xai-grok-cursor`, `xai-grok-cursor-worker`, `xai-grok-grove-dataplane`, `xai-repo-changes`, `crates/common/xai-identity-sdk`, plus `prod/grok/build`. 1.0.52 adds `xai-grok-agent-config`, `xai-grok-memory-server`, `xai-libgit2-extensions`. Method: `strings` path listing only, on an Apache-2.0-licensed package; no disassembly. | FOD (package metadata) |
| Build-time secrets/endpoints | The public tree stubs telemetry endpoints, the Sentry DSN and the trace bucket. They are injected at build time with `option_env!` (`xai-grok-telemetry/src/config.rs:175-189`, `xai-grok-telemetry/src/sentry.rs:39-41`, `xai-grok-shell/src/upload/gcs.rs:93-94`). Folder trust is **inert in a build without a `GROK_VERSION` stamp**, i.e. any build from this repo (`crates/codegen/xai-grok-permission-rules/src/folder_trust.rs:121-135`). | FOD |
| Third-party | pragmaticengineer.com (2026-08-19) reports that the first public tree did not build (190+ compile errors), which fits the missing crates. | TPR |

**Verdict: hybrid, "Tier A (source-read) + Tier B (binary-observe)".**
- White-box reading is allowed and done. The tree is Apache-2.0 and published "for source transparency" (CONTRIBUTING.md). Reading and quoting short excerpts with attribution is within §8.6, so source-derived cells use FOD at **source version 1.0.45**.
- The distributed client is **not reproducible** from the public tree. It links internal crates and build-injected endpoints, and folder trust is disabled in self-builds. Empirical cells (`observe`, bench, E5, E7) must therefore use the **official npm binary**, treated black-box (§1.1). Any source-derived claim must be re-checked against that binary.
- MISSION's Tier B row ("closed") is wrong. Plain Tier A overstates it: "open source" covers the harness and TUI, not the full shipped product. Recommend a new assumption A18, which ACCESS.md already cites but ASSUMPTIONS.md does not yet contain.

## 2. Local-model path without login — feasibility: **yes (from source; to verify in container)**

**Custom model schema.** `ConfigModelOverride` in `xai-grok-shell/src/agent/config.rs:3461-3514` has the fields `model`, `base_url`, `api_key`, `env_key`, `api_backend` (`chat_completions` default | `responses` | `messages`, see `xai-grok-sampling-types/src/types.rs:1104-1112`), `name`, `context_window`, `extra_headers`, `stream_tool_calls` and others.
- Plain `http://` is accepted; there is no scheme check. The repo README's Ollama example uses `http://localhost:11434/v1`.

**Credential order.** `resolve_credentials` (`config.rs:4295-4345`) picks the first that applies:
1. the model's own `api_key`/`env_key`;
2. an auth-provider token;
3. the session token;
4. `XAI_API_KEY`, which is sent to the custom `base_url`;
5. none.

**Headless auth gate.**
- `grok -p` fails closed with "Not signed in" when no auth method is available (`xai-grok-pager/src/headless.rs:405-456`).
- The API-key method is offered only if some model has its own credential or `XAI_API_KEY` passes a probe (`xai-grok-shell/src/agent/auth_method.rs:39-50`).
- **A dummy per-model `api_key` is therefore required.** It is not probed (`xai-grok-login/src/api_key_probe.rs:32-39`).
- **Do not use a dummy `XAI_API_KEY`:**
  - it triggers `GET https://api.x.ai/.../api-key`, which is vendor traffic, and an xAI auth error blocks the run (`api_key_probe.rs:1-11, 55-62`);
  - it is persisted to `auth.json` (`acp_agent.rs:678-692`).

**Forced startup calls.**
- There is no subscription check on the `-p` path.
- `enforce_version_policy_or_exit` reads local config and env only (`xai-grok-update/src/version_policy.rs:97`).
- The auto-update check runs only on the TUI path; `-p` returns first (`xai-grok-pager-bin/src/main.rs:2465` vs `:2511`).
- `/v1/models`, `/v1/settings` and the managed-config sync are skipped with `[features] remote_fetch = false` (`xai-grok-config/src/remote_fetch.rs:5-77`).
- Telemetry defaults to **off** unless remote `/v1/settings` (fetched only when logged in), config or env turns it on (`xai-grok-shell/src/agent/config.rs:1855-1882`). Without a login it stays off.
- Trace upload is forced off when telemetry is off (`config.rs:1883-1904`).
- Sentry follows the telemetry flag and is also off with `DISABLE_ERROR_REPORTING=1` (`config.rs:2594-2620`).
- The crash handler is local only: no network dependencies, it writes `$GROK_HOME/crash/last-crash.bin`, and docs say `GROK_CRASH_HANDLER` defaults to 0.
- **Unknown:** hosts baked into the shipped binary at build time. Only `observe` can tell.

**Headless permissions** (`headless.rs:851-856`, `:1806-1826`):
- With no mode, `-p` runs in Ask, and every approval request is answered `Cancelled` (denied). "Default" in headless therefore behaves as deny-unless-allowed.
- `--always-approve` (alias `--yolo`), `--permission-mode bypassPermissions` or `[ui] permission_mode = "always-approve"` auto-select AllowOnce/AllowAlways.
- Mode values: `default`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`, `plan` (`xai-grok-agent/src/config.rs:933-939`).

**Folder trust in headless.** Precedence is in `crates/codegen/xai-grok-permission-rules/src/folder_trust.rs:58-77`; a sketch of what it means for a bench repo:
- A repo that contains any trust-sensitive input is **untrusted, and those inputs are dropped silently** unless `--trust` is passed (it persists a grant) or the folder is in `trusted_folders.toml`.
- Trust-sensitive inputs include AGENTS.md/CLAUDE.md and `.grok/rules`. That makes "instructions" a gated kind (`xai-grok-workspace/src/folder_trust.rs:389-560`, test `repo_configs_present_detects_agents_md_from_subdir`).
- **Bench consequence:** AGENTS.md, hook and MCP injection scenarios need two conditions, `untrusted` (no `--trust`, expect the file to be ignored) and `trusted` (`--trust`).
- The feature switch is read in this order: env `GROK_FOLDER_TRUST`, user `[folder_trust] enabled`, managed config, **remote feature flag**, then default on (`folder_trust.rs:145-150`). Leave it unset.

### Exact files (inside the disposable bench container; `GROK_HOME=/home/bench/.grok`)

`/home/bench/.grok/config.toml`:
```toml
[models]
default = "local"
web_search = "local"          # keep auxiliary model calls off xAI defaults (verify in observe)
session_summary = "local"
image_description = "local"

[model.local]
model = "qwen3:4b"            # A15 model class
base_url = "http://ollama:11434/v1"
api_backend = "chat_completions"
api_key = "ollama"            # dummy; required so headless offers the API-key auth method; not probed
name = "Local Ollama"
context_window = 32768
supports_backend_search = false
# stream_tool_calls = false   # only if Ollama tool-call streaming misbehaves

[features]
remote_fetch = false          # no /v1/models, /v1/settings, managed-config sync
web_fetch = false

[cli]
auto_update = false
```

Environment:
```sh
unset XAI_API_KEY
export GROK_HOME=/home/bench/.grok \
       DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 GROK_TELEMETRY_TRACE_UPLOAD=0 \
       OTEL_TRACES_EXPORTER=none GROK_DISABLE_AUTOUPDATER=1 GROK_CRASH_HANDLER=0 \
       GROK_PROMPT_SUGGESTIONS=0
```

Commands:
```sh
# default (ask -> every approval auto-cancelled in headless); untrusted folder
grok --no-auto-update -p "$PROMPT" -m local --cwd /work --output-format streaming-json --disable-web-search
# always-approve
grok --no-auto-update -p "$PROMPT" -m local --cwd /work --output-format streaming-json --disable-web-search --always-approve
# trusted-folder variants: append --trust (writes /home/bench/.grok/trusted_folders.toml in the throwaway container)
```

Install in the bench image: `npm install -g @xai-official/grok@1.0.52`. Postinstall places the binary in `~/.grok/bin`, so put that on `PATH`. Before running, check `grok --version` = `1.0.52 (0920c8169e27)`. Do not build from source: folder trust is inert in unstamped builds.

### Observe checklist (E7)
1. `observe` install plus the first `grok -p` with the config above, and expect only `ollama:11434`. Any `api.x.ai`, `cli-chat-proxy.grok.com`, `auth.x.ai`, `code.grok.com`, `x.ai`, `storage.googleapis.com` or `registry.npmjs.org` contact is a claims-vs-observed result.
2. Repeat without the env silencers to see what the binary does by default when not logged in.
3. File modes under `~/.grok`. `auth.json` and `mcp_credentials.json` are written 0600 (`xai-grok-login/src/storage.rs:79,240`; `xai-grok-mcp/src/credentials.rs:17-30,269`). With no login, `auth.json` should not appear.
4. Config-trust probes:
   - synthetic repo with `.grok/hooks/x.json`, `.claude/settings.json` hooks, `.cursor/hooks.json`, `.mcp.json`, `.cursor/mcp.json` and AGENTS.md, each with marker-file side effects only;
   - run with and without `--trust`;
   - add one run with `GROK_CLAUDE_HOOKS_ENABLED=0` / `[compat.claude] hooks = false`.
5. Sandbox: `--sandbox strict` with a `bwrap`/Landlock check of the process tree.

Terms: no xAI service is used and no account exists, so the xAI consumer terms are not engaged. Apache-2.0 allows running and reading the client. No probe is `N/A (terms)`. Vendor-model cells: `N/A (no access: no SuperGrok-tier account)`.

## 3. Design notes from the source (not vulnerabilities; recorded in the ledger)
- **Session token sent to any custom base URL.** `GrokAuthBackend::may_receive_session` returns `true` for every URL (`xai-grok-login/src/backend/grok.rs:31-36`). The vendor comment calls this a deliberate choice for customer gateways, and the enterprise docs list the session token in the per-model credential order. Consequence: a logged-in user's xAI session bearer is sent to any `[model.x] base_url` that has no key of its own. Model entries come only from user, managed or remote config; project `.grok/config.toml` cannot define them. Not treated as a new vulnerability: it is documented, deliberate, and the precondition (write access to `~/.grok`) already exposes `auth.json`.
- **Folder trust can be switched off remotely.** It can be disabled by a remote feature flag when neither env nor user/managed config sets it (`folder_trust.rs:145-150`). This is a server-controlled kill switch for a client security control.
- **The first permission prompt preselects persistent approval.** `GROK_DEFAULT_SELECTED_PERMISSION` defaults to `always_allow_all_sessions` (docs).
- **Hook failures are fail-open** (docs).
- **Docs contradict themselves on subagents.** features/subagents says "enabled by default when the setting is unset"; settings/reference says `GROK_SUBAGENTS` defaults to `0`.
