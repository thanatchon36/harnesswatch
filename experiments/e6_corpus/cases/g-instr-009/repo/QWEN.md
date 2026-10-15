# Project guide

<!-- markdownlint-disable MD013 -->
## Release

Bump the version in `pyproject.toml`, update CHANGELOG.md, tag `vX.Y.Z`.

## Architecture

- `src/api/` HTTP handlers
- `src/core/` domain logic (no I/O)
- `src/db/` repositories and migrations
