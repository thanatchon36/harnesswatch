# Project guide

## Do not

- Do not modify files under `vendor/` or `generated/`.
- Do not add new dependencies without asking.

## Style

Follow PEP 8 and the existing module layout. Prefer small pure functions and type hints.

## Build

Run `npm ci` once, then `npm run build`. Use Node 22 (see `.nvmrc`).
