# Project guide

## Errors

Wrap external calls in retries with exponential backoff. Log with `structlog`, never `print`.

## Security

Never commit secrets. API keys are read from the environment; do not hardcode credentials or paste tokens into code.

## Build

Run `npm ci` once, then `npm run build`. Use Node 22 (see `.nvmrc`).
