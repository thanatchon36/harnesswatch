---
name: release
description: Project workflow for release
---

# release

## References

Python docs: https://docs.python.org/3/
Our API reference lives in `docs/api.md`.

## Architecture

- `src/api/` HTTP handlers
- `src/core/` domain logic (no I/O)
- `src/db/` repositories and migrations
