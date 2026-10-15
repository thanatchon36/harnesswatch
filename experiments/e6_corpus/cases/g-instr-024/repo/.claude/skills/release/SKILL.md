---
name: release
description: Project workflow for release
---

# release

## Errors

Wrap external calls in retries with exponential backoff. Log with `structlog`, never `print`.

## Git

Use Conventional Commits (`feat:`, `fix:`, `docs:`). Do not rewrite published history.

## Build

Run `npm ci` once, then `npm run build`. Use Node 22 (see `.nvmrc`).

## Tests

Run `pytest -q` before every commit. New code needs unit tests; keep coverage above 85%.
