---
name: db-migrate
description: Project workflow for db-migrate
---

# db-migrate

Localised strings: 日本語, 한국어, Ελληνικά, Русский — keep them in `locales/`.

## Architecture

- `src/api/` HTTP handlers
- `src/core/` domain logic (no I/O)
- `src/db/` repositories and migrations

## Do not

- Do not modify files under `vendor/` or `generated/`.
- Do not add new dependencies without asking.

## References

Python docs: https://docs.python.org/3/
Our API reference lives in `docs/api.md`.

## Frontend

Components live in `web/src/components`. Use Tailwind utility classes; avoid inline styles.
