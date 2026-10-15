# B2: `observe` plan for Google Antigravity (`agy` CLI + IDE), pre-login only

Written 2026-10-15 for Antigravity CLI 1.3.5 (GitHub release and updater manifest, 2026-10-14), app 2.23.1 and IDE 2.5.5.
Claim rows: `matrix/claims_vs_observed.d/B2.csv` (CVO-B2-001…032). Facts: `evidence/ledger.d/B2.csv`.
Rules: MISSION §1.1 and §8 (rule 8), A05, A16 and A17. Nothing here decompiles, unpacks or disassembles the binary.
The installer is read as text only. The binary is downloaded and run **only inside a disposable container**, never
on the host. No Google login and no real API key are used.

## 0. What can run here

| Question | Answer | Source |
|---|---|---|
| Linux x64 build? | Yes. glibc build `linux_amd64` and musl build `linux_amd64_musl` (also arm64 and arm64-musl). The installer picks musl if `/lib/libc.musl-*.so.1` exists or `ldd /bin/ls` mentions musl. | install.sh; manifests `…/manifests/linux_amd64{,_musl}.json` (1.3.5, payload 62,830,042 bytes, HEAD only) |
| glibc requirement for `agy`? | **Not documented.** The desktop-app download page states glibc ≥ 2.28 and glibcxx ≥ 3.4.25 (Ubuntu 20, Debian 10, Fedora 36, RHEL 8). That is the app, not the CLI. Use `debian:12-slim` (glibc 2.36) as the primary image and `alpine:3.20` with the musl build as the cross-check. Do not run `ldd` or `readelf` on the binary to find out: reading ELF headers is harmless metadata, but we keep to "run it and see". | https://antigravity.google/download/linux |
| Known Linux pitfalls | Issue #1029: the embedded ripgrep has a Google-internal ELF interpreter (`/usr/grte/v5/…`), so `/codesearch` falls back. Issue #1160: the terminal sandbox fails on WSL2 (`seccomp … EBUSY`). Issue #1204: AppArmor userns restrictions. Issue #64: TCMalloc fails on 39-bit-VA arm64 kernels. Our host is WSL2, so run the container on Docker's Linux VM and record the kernel. | GitHub issues (third-party) |
| Can it run without a Google login? | **Partly.** Without credentials, a non-TTY `agy -p` exits with `authentication required`. Read-only print answers (`-p "/help"`, `/config`, `/permissions`, `/hooks`, `/changelog`) do not start an agent turn, but whether they need auth is untested. The only no-sign-in model path is `modelProvider: "gemini"` plus `GEMINI_API_KEY`, which still needs a Google AI Studio or Gemini Enterprise key. We have neither. | docs/cli/headless; docs/cli/install; CHANGELOG 1.1.12, 1.1.13 |
| Local model? | **No documented CLI path.** Only `GOOGLE_GEMINI_BASE_URL`, a *Gemini-API-compatible* endpoint, in API-key mode. Ollama does not serve the Gemini API, and a translation shim would be our own code. The consumer Terms also forbid "using the Service in connection with products not provided by us". So the bench cell is `N/A (no access: needs Google login or API key; no documented local-model path)`. The Python SDK, not the CLI, does support Ollama (`LocalOpenAIAgentConfig`). It is a different harness surface and out of scope here. | docs/cli/install; docs/sdk/local-models; https://antigravity.google/terms |
| Terms | Installing means accepting the Antigravity Additional Terms ("BY DOWNLOADING, INSTALLING…"). The author decides that before P1 runs. If declined, every row below is `N/A (terms)`. The FAQ forbids wrapping `agy` in third-party agents under consumer plans. Our observe wrapper only runs the binary and does not proxy a login, but we note it. | terms; docs/faq |

## 1. Container baseline

- **Image:** `debian:12-slim` plus `curl`, `ca-certificates`, `procps` and `inotify-tools`. Non-root user `agent` (uid 1000),
  fresh `HOME=/home/agent`. **No D-Bus session bus and no keyring daemon.** That matches the CI case the changelog
  describes (CLI 1.1.3: the keyring is bypassed when no session bus is present). Variant B adds `dbus-x11` and
  `gnome-keyring` with an unlocked test keyring, to compare the storage-backend message.
- **Egress:** default route only via the project's logging sink (`HTTPS_PROXY=http://sink:3128`). The sink logs
  `CONNECT host:port` and **forwards only during P1 (install)**, since the payload must download. In P2–P6 it logs and
  answers 403, so the vendor sees no completed requests beyond the TLS-less CONNECT attempt. `agy` is a Go binary
  (docs). Whether it honours `HTTPS_PROXY` is not documented. A DNS logger on the container resolver plus an
  `iptables` REDIRECT of :443 to the sink catches non-proxy-aware connections. A17: hostnames, ports and timing
  only. No TLS interception, no bodies.
- **Filesystem watch:** before/after `find /home/agent /tmp -printf '%m %u %s %p\n'`, plus `inotifywait -m -r` on
  `~/.gemini`, `~/.cache`, `~/.local` and the shell rc files. File contents are never read, except our own canaries.
- **Process log:** `ps -eo pid,ppid,user,args` sampled at 100 ms, to see updater children, MCP/hook children and any
  `nsjail`/`unshare`/namespace helpers.
- **Synthetic repo** `/work/repo` (git init) seeded with the files in §4.

## 2. Probes (pre-login)

| # | Run | What it shows | Claim rows |
|---|---|---|---|
| P1 | `curl -fsSL https://antigravity.google/cli/install.sh \| bash` (inside the container) | hosts (`antigravity.google`, `antigravity-cli-auto-updater-974169037036.us-central1.run.app`, `storage.googleapis.com`); files written (`~/.local/bin/agy`, `~/.cache/antigravity/staging` cleanup); shell-profile edits by `agy install`; repeat with `--skip-path --skip-aliases` passed through `bash -s --` (check whether accepted) | 001, 002, 014 |
| P1b | P1 against a local mirror (container DNS override) whose manifest carries a wrong `sha512` | the "Security Halt" path. Our own mirror, no vendor traffic altered | 001 |
| P2 | `agy --version`; then `agy -p hi </dev/null` with no credentials | exit code, stderr, time to exit (must not hang), hosts before the auth error (update check? telemetry? auth?), files created (`~/.gemini/antigravity-cli/{settings.json,updater/,…}` with modes), storage-backend message | 003, 005, 013, 015 |
| P2b | P2 with `AGY_CLI_DISABLE_AUTO_UPDATE=true` | no manifest/GCS host; no `updater/` writes | 004 |
| P2c | P2 with `{"enableTelemetry": false}` | diff of the host set against P2 | 006 |
| P2d | after P2 exits: process list and connections for 15 min | no lingering updater/telemetry process (Terms: "only when you have the Service running") | 007 |
| P3 | `agy -p "/help"`, `"/config"`, `"/permissions"`, `"/hooks"`, `--output-format json` | whether these answer pre-login; if so, the static default permission set and the hooks the CLI *would* load from `.agents/hooks.json` before trust | 016, 017, 022 |
| P4 | `modelProvider: "gemini"` in settings with the canary key only in `/work/repo/.env` | expect startup error "GEMINI_API_KEY is not set" and no network; a request carrying the canary = `.env` loaded (contradicts docs) | 011 |
| P4b (optional, author decision) | `GEMINI_API_KEY=hw-invalid-dummy` exported | hosts contacted in API-key mode (expect the Gemini API host only, failing 400/403); any account/sign-in host = finding. No quota is used. Skip if the author reads A16 strictly | 008 |
| P5 | `cd /work/repo` (seeded, §4); (a) `agy -p hi </dev/null`; (b) pty `agy` until the first prompt, then kill | **config trust before login:** does the `SessionStart` hook canary appear, does the stdio MCP canary server spawn, are `.agents/plugins/*` MCP servers spawned, in which order are sign-in and the trust prompt shown | 021, 022, 023 |
| P6 | P2 in variant B (D-Bus + keyring) vs variant A | stderr backend message ("file-based token storage because container environment detected", issue #479) and whether `~/.gemini/antigravity-cli/antigravity-oauth-token` is created pre-login (path, mode; never read) | 009, 010, 013 |

## 3. N/A rows and why

| Claim rows | Label | Reason |
|---|---|---|
| 012 (MCP OAuth token file), 009 token write | `N/A (no access)` | needs a signed-in session and an OAuth MCP flow |
| 017, 018, 024, 026, 028, 032 (permission defaults, skip-permissions, rule triggers, sandbox, URL fetch, subagents) | `N/A (no access)` | each needs a model turn; the CLI has no local-model path and we have no Google login or API key (A16) |
| 019, 025, 031 (app presets, project config, knowledge items) | `N/A (no access)` | desktop app needs a GUI session and a Google login |
| 020, 027, 029, 030 (IDE terminal policy, IDE sandbox, browser allowlist, separate Chrome profile) | `N/A (no access)` | IDE not installed; GUI and Google login required; IDE not supported for enterprise. Docs-only (Tier C method) |
| bench (E3) for Antigravity | `N/A (no access: needs Google login or API key; no documented local-model path)` | see §0 |

## 4. Synthetic repo for P5 (inert canaries only, §8.1)

```
/work/repo/.agents/hooks.json        {"hw": {"SessionStart": [{"type": "command", "command": "touch /tmp/hw-canary-hook"}]}}
/work/repo/.agents/mcp_config.json   {"mcpServers": {"hw": {"command": "/bin/sh", "args": ["-c", "touch /tmp/hw-canary-mcp; sleep 5"]}}}
/work/repo/.agents/plugins/hwp/plugin.json + mcp_config.json (same pattern, canary hw-canary-plugin-mcp)
/work/repo/.agents/agents/hw.md      front matter with mcpServers: [{name: hw2, command: /bin/sh, args: [-c, "touch /tmp/hw-canary-agent-mcp"]}]
/work/repo/.agents/rules/hw.md       trigger: always_on, body "HW-CANARY-RULE"
/work/repo/AGENTS.md, GEMINI.md      body "HW-CANARY-INSTR"
/work/repo/.env                      GEMINI_API_KEY=hw-canary-not-a-key-0000   (P4 only)
```

Read the canary files' **existence** only. `harnesswatch audit config|mcp /work/repo` should report the same surfaces
statically (fixed parser coverage: `.agents/{mcp_config.json,hooks.json,plugins/*/…,agents/*.md}` are now parsed, and
`~/.gemini/antigravity*` / `~/.gemini/config/` user files are no longer shadowed by the gemini-cli owner prefix).

## 5. Known limits

- Everything after sign-in (sandbox evidence, approval prompts, credential write, telemetry after login, browser
  agent) stays docs-only. Those cells use `from-official-docs` or `third-party-report`, never `verified-by-test`.
- The installer integrity check is only as strong as the manifest origin. No signature exists to verify (HEAD of
  `.sig/.asc/.sha512/.intoto.jsonl/.sigstore.json` beside the payload = 404; GitHub release assets carry no checksums).
- The docs changelog lags the binary (lists CLI 1.3.1; manifest and GitHub serve 1.3.5). Pin the observed version
  from `agy --version` in every result row.
- If `agy` ignores proxy env vars, P2–P6 still log hosts through DNS and the REDIRECT. If DNS is resolved through DoH
  inside the binary, record "hosts: unresolved (DoH?)" rather than guessing.
