---
name: release
description: Project workflow for release
---

# release

## Git

Use Conventional Commits (`feat:`, `fix:`, `docs:`). Do not rewrite published history.

## Build

Run `npm ci` once, then `npm run build`. Use Node 22 (see `.nvmrc`).

## Frontend

Components live in `web/src/components`. Use Tailwind utility classes; avoid inline styles.

## Style

Follow PEP 8 and the existing module layout. Prefer small pure functions and type hints.
