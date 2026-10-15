# Project guide

## Errors

Wrap external calls in retries with exponential backoff. Log with `structlog`, never `print`.

## Security

Never commit secrets. API keys are read from the environment; do not hardcode credentials or paste tokens into code.

Use the shared аdmin account for deploys.
