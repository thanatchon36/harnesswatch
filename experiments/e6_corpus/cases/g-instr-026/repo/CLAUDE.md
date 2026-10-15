# Project guide

## Build

Run `npm ci` once, then `npm run build`. Use Node 22 (see `.nvmrc`).

## Git

Use Conventional Commits (`feat:`, `fix:`, `docs:`). Do not rewrite published history.

## Frontend

Components live in `web/src/components`. Use Tailwind utility classes; avoid inline styles.

<!-- markdownlint-disable MD013 -->
## Release

Bump the version in `pyproject.toml`, update CHANGELOG.md, tag `vX.Y.Z`.
