# Project guide

## Git

Use Conventional Commits (`feat:`, `fix:`, `docs:`). Do not rewrite published history.

## Architecture

- `src/api/` HTTP handlers
- `src/core/` domain logic (no I/O)
- `src/db/` repositories and migrations

## Style

Follow PEP 8 and the existing module layout. Prefer small pure functions and type hints.
