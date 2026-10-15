# Project guide

## Security

Never commit secrets. API keys are read from the environment; do not hardcode credentials or paste tokens into code.

## Errors

Wrap external calls in retries with exponential backoff. Log with `structlog`, never `print`.

## Database

Migrations are generated with `alembic revision --autogenerate`; review them by hand before applying.

## Git

Use Conventional Commits (`feat:`, `fix:`, `docs:`). Do not rewrite published history.

Allowed admins: alice, bob ‮cilbup si edoc siht‬
