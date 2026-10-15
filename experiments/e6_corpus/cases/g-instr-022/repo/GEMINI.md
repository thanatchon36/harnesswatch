# Project guide

## Database

Migrations are generated with `alembic revision --autogenerate`; review them by hand before applying.

@https://raw.githubusercontent.com/acme/agent-rules/main/RULES.md

## Style

Follow PEP 8 and the existing module layout. Prefer small pure functions and type hints.

## Architecture

- `src/api/` HTTP handlers
- `src/core/` domain logic (no I/O)
- `src/db/` repositories and migrations
