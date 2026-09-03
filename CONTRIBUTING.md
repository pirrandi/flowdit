# Contributing to Flowdit

Thanks for your interest in contributing. Here's what you need to know.

## Getting started

1. Fork the repo and clone your fork
2. Set up the dev environment (see README.md)
3. Create a branch: `git checkout -b feat/your-feature` or `fix/your-fix`
4. Make your changes, test them locally
5. Open a pull request against `master`

## Development setup

```bash
# Start PostgreSQL (Docker)
docker compose up -d db

# Run migrations
cd backend && node src/db/migrate.js

# Start backend (nodemon for auto-reload)
cd backend && npm run dev

# Frontend is served by Nginx, or open frontend/index.html directly
```

## Project structure

```
backend/src/
  db/migrate.js      all DB migrations, run sequentially and idempotently
  routes/            one file per resource (vulns, targets, projects…)
  services/          WebSocket hub, activity logger, DOCX renderer, mailer
  middleware/        auth guard, project access control

frontend/
  *.html             one HTML file per page/view
  js/views/          page-specific logic
  js/services/       api.js, state.js, utils.js, ws.js
  css/main.css       Signal design system tokens + all component styles
```

## Running tests

Tests are integration tests that hit a real PostgreSQL database, no mocks. They run against a **separate database whose name contains `test`** (never your dev database: `resetDb()` truncates every table between tests).

```bash
# One-time setup: create the test database and run migrations against it
docker exec flowdit-db-1 createdb -U pirra flowdit_test   # adjust user if yours differs
cd backend && DB_NAME=flowdit_test node src/db/migrate.js

# Run the suite
cd backend && DB_NAME=flowdit_test DB_USER=pirra DB_PASSWORD=<your-db-password> npm test
```

`test/helpers.js` refuses to run if `DB_NAME` doesn't contain `test`, as a safety net against accidentally wiping real data.

## Linting

```bash
cd backend && npm run lint
```

## Guidelines

**Backend**
- All DB changes go in `backend/src/db/migrate.js` as new entries at the bottom. Migrations are idempotent (`IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`)
- Use parameterized queries everywhere, no string concatenation in SQL
- Keep routes thin; move reusable logic to `services/`

**Frontend**
- No frameworks, vanilla JS, HTML, CSS only
- Use Signal design system tokens (`--bg`, `--t1`, `--a`, etc.), no hardcoded colors
- No emojis in UI, functional Unicode only (`✓ ✕ ✎ ⚠`)
- One HTML file per view; shared logic in `js/page.js` and `js/services/`

**General**
- Keep PRs focused, one feature or fix per PR
- Test your changes against a real PostgreSQL instance before submitting
- If adding a new dependency, explain why in the PR description

## Reporting bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Browser and Node.js version
- Any relevant console errors

## Feature requests

Open an issue describing the use case. Check existing issues and the roadmap in README.md first.
