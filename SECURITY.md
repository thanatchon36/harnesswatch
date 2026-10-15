# Security policy

## Reporting a vulnerability in harnesswatch

Please report vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not open a public issue.
We aim to acknowledge within 5 working days and to ship a fix or mitigation within 90 days.

## Reporting a vulnerability in a third-party harness

If harnesswatch helps you find a vulnerability in an AI coding-agent harness, report it to that
vendor's security programme first. This project follows coordinated disclosure: no public details
until a fix ships or 90 days have passed.

## Design commitments of the tool itself

- Read-only by default; no network access unless `--online` is passed.
- File contents are never transmitted anywhere. Secret matches are redacted in all output and never
  persisted.
- No `eval`/`exec`; subprocesses are launched with argument lists, never `shell=True`.
- The canary benchmark runs only inside disposable containers with egress blocked, and its payloads
  are inert detection fixtures (marker files, canary strings, a local sink at 127.0.0.1).
