# E6 label fixes log

**No label was changed.** All labels were written before the first evaluation run (2026-10-15
06:37 UTC). At that point the SHA-256 of the concatenated `label.yaml` files was
`2eb574a3ef26fe5a39e1e8008a41ed256d90f31e95e473367b18784ef6226efb`, and it is unchanged in the
final corpus.

Three *case-content* bugs were fixed so that the files match the labels as they were written.
These fixes did not change any expectation:

| Cases | Problem | Fix |
|---|---|---|
| `g-ci-*` (26 generated) | Generator bug: the workflow `on:` block held only the trigger's inner value (e.g. `on: {types: [created]}`), so the file had no trigger at all. Labels were computed for the intended trigger. | `e6_generate.py` now writes `on: {<trigger>: …}`; regenerated (same seed, labels identical). |
| `h-099-ci-review-comment-copilot` | Invalid YAML: a plain `run:` scalar containing `: ` meant the workflow could not be parsed, by GitHub or anyone else. | Rewrote `run:` as a block scalar; same command. |
| `h-069…h-072` (SUP binaries) | The eval harness normalised `home/` files to 0600, which stripped the exec bit, so the binaries were invisible on PATH. | Marked the corpus binaries executable; `e6_eval.py` keeps 0700 for executable files. |
