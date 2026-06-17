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

# Frontend is served by Nginx or directly from frontend/ — open index.html
```

## Project structure

```
backend/src/
  db/migrate.js      — all DB migrations, run sequentially and idempotently
  routes/            — one file per resource (vulns, targets, projects…)
  services/          — WebSocket hub, activity logger, DOCX renderer, mailer
  middleware/        — auth guard, project access control

frontend/
  *.html             — one HTML file per page/view
  js/views/          — page-specific logic
  js/services/       — api.js, state.js, utils.js, ws.js
  css/main.css       — Signal design system tokens + all component styles
```

## Guidelines

**Backend**
- All DB changes go in `backend/src/db/migrate.js` as new entries at the bottom — migrations are idempotent (`IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`)
- Use parameterized queries everywhere — no string concatenation in SQL
- Keep routes thin; move reusable logic to `services/`

**Frontend**
- No frameworks — vanilla JS, HTML, CSS only
- Use Signal design system tokens (`--bg`, `--t1`, `--a`, etc.) — no hardcoded colors
- No emojis in UI — functional Unicode only (`✓ ✕ ✎ ⚠`)
- One HTML file per view; shared logic in `js/page.js` and `js/services/`

**General**
- Keep PRs focused — one feature or fix per PR
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
