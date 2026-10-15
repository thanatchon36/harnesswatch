# Observe: black-box probe

`harnesswatch observe` runs a harness command inside a disposable container behind an egress proxy
and records what it does. It works on closed harnesses where no source is available.

```bash
harnesswatch observe claude-code --image my-image --repo ./synthetic-repo -o report.json -- claude --version
```

## What it records

Metadata only:

- hostnames and ports (proxy CONNECT targets, DNS query names, connection attempts);
- file paths, modes and sizes written or deleted (a `docker diff` against a copied-in baseline);
- process names and command lines;
- whether permission or trust prompts appear in the harness's own output;
- whether a sandbox is observed.

## What it never records

- request or response bodies and file contents;
- decrypted TLS: the probe does not intercept or break the client's transport security;
- the author's real credentials: containers run with synthetic values only and no vendor login.

A closed harness is driven only through a documented custom or local model endpoint. Harnesses that
only work with a vendor login are observed pre-login (install and first run) and are otherwise
reported as `N/A (no access)`.

These limits are recorded as assumptions A16 and A17 in `ASSUMPTIONS.md`.
