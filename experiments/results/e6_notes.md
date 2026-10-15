# E6: rule-pack precision and recall (synthetic corpus)

Reproduce with `uv run python experiments/e6_generate.py` (seed 6, deterministic) and then
`uv run python experiments/e6_eval.py`. Outputs: `e6_accuracy.json` (after),
`e6_accuracy_before.json` (before the rule/engine changes), and `paper/tables/e6_accuracy.{tex,md}`.

## Corpus

- **376 cases:** 113 hand-crafted (`h-*`) and 263 generated (`g-*`, 9 families). They cover more than 20
  harness formats (Claude Code, Codex, Gemini, Qwen, Cursor, VS Code/Copilot, OpenCode, Kilo, Kiro, Roo,
  Cline, Windsurf, Goose, Crush, Continue, Amp, Antigravity, Factory, Kimi, Aider, Grok, Vibe), plus
  GitHub/GitLab CI, home state dirs and tool manifests.
- 108 cases are fully negative. There are many near-misses: pinned `npx`/`uvx`/`--package=`/git-commit
  pins, HTTPS MCP with auth (header, `${input:}`, `bearer_token_env_var`), hooks that only run local
  linters, emoji ZWJ, accented names, SI units, specific allowlists, Kiro specific `autoApprove`,
  UUIDs and model ids in `env`.
- Labels come from construction, following the conventions written at the top of
  `e6_generate.py`. All audits run on every case, so a rule firing anywhere it is not labelled
  counts as an FP. The unit is the (case, rule) pair.
- **Split:** `sha256(id) mod 100 >= 60` is test. Realised: 245 dev / 131 test (34.8 %, about 2 sd below
  the 40 % target). The hash was not changed after results were seen. Only dev errors were
  inspected; `e6_accuracy.json` lists dev errors only.

## Results (held-out test split, Wilson 95 %)

| | before | after |
|---|---|---|
| micro precision | 0.960 [0.920, 0.981] (FP 7) | **0.982 [0.950, 0.994]** (FP 3) |
| micro recall | 0.982 [0.950, 0.994] | 0.982 [0.950, 0.994] |
| macro P / R | 0.958 / 0.952 | 0.971 / 0.952 |

On dev, precision went from 0.939 to 1.000 and recall from 0.959 to 0.976. These are in-sample
numbers (the fixes were found on dev), so do not quote them as accuracy.

"Before" is measured after the corpus-content fixes listed in `e6_label_fixes.md`. The very first
run (with those corpus bugs) gave test P = 0.959, R = 0.959.

**Worst rules on test:**
- HG-SUB-001: recall 0/1.
- HG-MCP-004: precision 1/2.
- HG-PERM-001: P = R = 0.91.
- HG-PERM-003 is next at 0.93.

Supports are small: CIs on many rules span 0.4–1.0. HG-SUP-001 has no test support.

## Rule/engine changes (each FP class has a `should_not_fire` regression fixture)

1. `audits/config.py` `_setting_hits`: an explicit `value: "*"` matched *any* value, so specific
   `sandbox.network.allowedDomains` triggered NET-001 and Kiro `autoApprove: ["search_docs"]`
   triggered MCP-006. `"*"` is now literal; omitting `value` means "any value"; map-valued settings
   match on enabled keys.
2. `audits/mcp.py`: `npx --package=pkg@x.y.z bin` is now parsed, and `github:org/repo#<40-hex>`
   counts as pinned (MCP-001).
3. `parsers/generic.py`: Codex/Grok `bearer_token_env_var` / `env_http_headers` count as auth
   headers (MCP-002).
4. `secrets.py`:
   - any `${…}` expression (`${VAR:-default}`, `${env:X}`, `${input:x}`) is a reference;
   - package specifiers are not secrets;
   - UUIDs and separator-joined identifiers (model ids) count as secrets only under a
     credential-named key.

   This fixes MCP-003/SEC-003 FPs.
5. `rules/HG-PERM-001.yaml` and `HG-PERM-003.yaml`: Continue's `allow` allowlist was added to
   `ignore_keys`, because it is PERM-002 territory, not an approve-everything mode.
6. `textscan.py`:
   - mixed-script tokens that are SI quantities (`10μm`) are no longer INJ-001;
   - `curl … | sh` in a prohibitive sentence ("Never pipe … ") is no longer an INJ-002 indicator;
   - "rules adapted from <url>" attribution is no longer INJ-003.

**Recall fixes** (with `should_fire` fixtures):
- MCP-003 reads credential-named `--flag=value` arguments.
- SEC-003 treats MCP header maps like `env` blocks.
- Kiro `command_field: "action.command|command"`, so legacy `.kiro.hook` `runCommand` is read.

  The hook walker now stops descending into a node once it has yielded a command; this prevents
  v1 double counts.

A first version of the args change introduced 7 new dev FPs (`pkg==1.2.3`, `--package=@…`). These
were caught on dev and fixed by restricting the check to credential-named flags.

## Known remaining errors (dev; deliberately not fixed)

- **Kilo `agent.*.permission` (SUB-001):** the Kilo agent schema in `kilo.jsonc` is unverified, so
  no rule params were added.
- **SEC-003 for literal secrets in MCP `args`:** labelled by my convention; the parser does not
  map args to keys.
- **`Bash(python:*)` as an over-broad allowlist (PERM-002):** profile data.
- **VS Code `{"/.*/": true}` terminal auto-approve (PERM-001):** profile data.

Threats to validity: one author wrote both the labels and the fixes; the corpus is synthetic; the
test split is small.
