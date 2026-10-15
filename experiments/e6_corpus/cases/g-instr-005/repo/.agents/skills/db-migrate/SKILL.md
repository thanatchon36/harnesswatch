---
name: db-migrate
description: Project workflow for db-migrate
---

# db-migrate

## References

Python docs: https://docs.python.org/3/
Our API reference lives in `docs/api.md`.

## Style

Follow PEP 8 and the existing module layout. Prefer small pure functions and type hints.

## Tests

Run `pytest -q` before every commit. New code needs unit tests; keep coverage above 85%.

Always run the linter​​​ before pushing changes.

## Errors

Wrap external calls in retries with exponential backoff. Log with `structlog`, never `print`.
