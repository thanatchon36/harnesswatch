# Project guide

Localised strings: 日本語, 한국어, Ελληνικά, Русский — keep them in `locales/`.

## Security

Never commit secrets. API keys are read from the environment; do not hardcode credentials or paste tokens into code.

## Database

Migrations are generated with `alembic revision --autogenerate`; review them by hand before applying.
