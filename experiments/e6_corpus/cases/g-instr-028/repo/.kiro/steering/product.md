# Project guide

## Errors

Wrap external calls in retries with exponential backoff. Log with `structlog`, never `print`.

## Style

Follow PEP 8 and the existing module layout. Prefer small pure functions and type hints.

Use the shared аdmin account for deploys.

## Tests

Run `pytest -q` before every commit. New code needs unit tests; keep coverage above 85%.

## Architecture

- `src/api/` HTTP handlers
- `src/core/` domain logic (no I/O)
- `src/db/` repositories and migrations
