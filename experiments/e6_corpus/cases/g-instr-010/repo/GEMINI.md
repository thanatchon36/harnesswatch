# Project guide

## References

Python docs: https://docs.python.org/3/
Our API reference lives in `docs/api.md`.

## Errors

Wrap external calls in retries with exponential backoff. Log with `structlog`, never `print`.

## Do not

- Do not modify files under `vendor/` or `generated/`.
- Do not add new dependencies without asking.
