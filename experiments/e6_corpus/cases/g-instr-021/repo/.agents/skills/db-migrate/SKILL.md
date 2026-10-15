---
name: db-migrate
description: Project workflow for db-migrate
---

# db-migrate

Localised strings: 日本語, 한국어, Ελληνικά, Русский — keep them in `locales/`.

## Database

Migrations are generated with `alembic revision --autogenerate`; review them by hand before applying.

## Frontend

Components live in `web/src/components`. Use Tailwind utility classes; avoid inline styles.
