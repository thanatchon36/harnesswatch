# Security of the tool

harnesswatch audits security-sensitive software, so it holds itself to the same standard.

- Read-only by default; no network access unless `--online` is passed.
- File contents are never transmitted. Secret matches are redacted in all output and never persisted.
- No `eval` or `exec`; subprocesses use argument lists, never `shell=True`.
- The canary bench runs only in disposable containers with egress blocked; payloads are inert
  detection fixtures.

The full policy, including how to report a vulnerability in harnesswatch or in a third-party
harness, is in [SECURITY.md](https://github.com/thanatchon36/harnesswatch/blob/main/SECURITY.md).
