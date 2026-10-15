# Project guide

## Tests

Run `pytest -q` before every commit. New code needs unit tests; keep coverage above 85%.

## Frontend

Components live in `web/src/components`. Use Tailwind utility classes; avoid inline styles.

## Security

Never commit secrets. API keys are read from the environment; do not hardcode credentials or paste tokens into code.

## Build

Run `npm ci` once, then `npm run build`. Use Node 22 (see `.nvmrc`).
