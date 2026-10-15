# Project guide

## References

Python docs: https://docs.python.org/3/
Our API reference lives in `docs/api.md`.

## Architecture

- `src/api/` HTTP handlers
- `src/core/` domain logic (no I/O)
- `src/db/` repositories and migrations

## Security

Never commit secrets. API keys are read from the environment; do not hardcode credentials or paste tokens into code.

## Build

Run `npm ci` once, then `npm run build`. Use Node 22 (see `.nvmrc`).
