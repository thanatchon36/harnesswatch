# payments-service

FastAPI service. Python 3.12, uv.

- `uv sync` then `uv run pytest -q`
- Lint: `uv run ruff check . && uv run mypy src`
- Never log card numbers or tokens; use `redact()` from `payments.logging`.
