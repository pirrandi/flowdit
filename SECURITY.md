# Security Policy

Flowdit is a pentest engagement management platform — it holds sensitive client data (findings, credentials in HTTP proofs, scope, client portal access). We take reports about it seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, report it privately through [GitHub Security Advisories](https://github.com/Pirrandi/flowdit/security/advisories/new) with:

- A description of the vulnerability and its impact
- Steps to reproduce (PoC if possible)
- Affected version/commit

You should get an initial response within 5 business days. If confirmed, we'll agree on a disclosure timeline with you before any public write-up — we ask for at least 90 days, or until a fix ships, whichever is sooner.

## Supported versions

Flowdit does not yet have tagged releases. Until then, only the latest commit on `master` is supported — please confirm the issue reproduces there before reporting.

## Scope

In scope:
- The Flowdit backend (`backend/`) and frontend (`frontend/`)
- Authentication, authorization, and cross-project/cross-organization data isolation
- Report export (PDF/DOCX) and the client portal

Out of scope:
- Vulnerabilities in third-party dependencies (report those upstream)
- Self-inflicted issues from a misconfigured self-hosted deployment (e.g. running with default `.env.example` secrets in production)
