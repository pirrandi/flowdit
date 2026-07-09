# GitHub Integration — design notes

Status: **v1 shipped** (one-way push). This doc exists so a future pass at
bidirectional sync doesn't have to re-derive the design space from scratch —
see [Extending to bidirectional sync](#extending-to-bidirectional-sync-v3) at
the bottom.

## What v1 does

A "Send to GitHub" button on a ticket creates a GitHub issue from it (title,
description, and — if the ticket is linked to a finding — the finding's
severity/description/remediation) and stores the resulting issue URL back on
the ticket. That's the whole feature. No webhooks, no OAuth app, no status
sync. Once linked, the button becomes a "View on GitHub ↗" link; a ticket can
only be linked once.

This was a deliberate scope cut over building bidirectional sync first — see
the tradeoffs below. It validates whether the integration gets used at all
before paying for the expensive version.

## Configuring it

Per-project, in **Settings → GitHub Integration**:
- **Repository** — `owner/repo`.
- **Personal access token** — needs `Issues: Read and write` permission on
  that repo (fine-grained PAT) or `repo` scope (classic PAT).

The token is encrypted at rest and never returned by the API after being
set — `GET /projects/:id` only exposes `has_github_pat: boolean`, the same
pattern `organization_sso_configs.client_secret_enc` and
`users.totp_secret_enc` already use.

## Architecture

**Data model** (`backend/src/db/migrate.js`):
- `projects.github_repo` — plain column, `owner/repo`.
- `projects.github_pat_enc` — AES-256-GCM via `backend/src/utils/crypto.js`
  (same key as the SSO client secret, `SSO_ENCRYPTION_KEY`).
- `ticket_integrations` table — `(id, ticket_id, provider, external_id,
  external_url, external_status, created_by, created_at)`, unique on
  `(ticket_id, provider)`. **`provider` is a column, not an assumption** —
  `CHECK (provider IN ('github'))` for now, but adding Jira/Linear later is
  an `ALTER ... DROP CONSTRAINT` + re-add, not a new table.
  **`external_status` is written by nothing in v1** — it exists so a future
  webhook handler has somewhere to persist GitHub's side of the issue
  without a schema migration.

**Backend:**
- `backend/src/services/github.js` — `createIssue(repo, pat, {title, body})`,
  a bare `fetch()` call to `POST /repos/:repo/issues` (same pattern as
  `services/ai/groq.js` — no new HTTP client dependency). This is the one
  function a bidirectional version would extend (add `updateIssue`,
  `getIssue`) or leave as-is if v3 moves to a GitHub App's REST client.
- `backend/src/routes/tickets.js`, `POST /:ticketId/github` — looks up the
  project's repo/PAT, 400s if unconfigured, 409s with the existing link if
  already sent, builds the issue body from the ticket + its linked finding,
  calls `github.createIssue`, inserts the `ticket_integrations` row.
  `requireEditor`-gated, same bar as every other ticket mutation.
- `backend/src/routes/projects.js` — `github_repo` added to the generic
  `PATCH /:projectId` allow-list; `github_pat` is special-cased (encrypt if
  present, clear if empty string, untouched if omitted) — identical shape to
  `portal_password`'s handling in the same route.
- `GET /` and `GET /:ticketId` in `tickets.js` `LEFT JOIN ticket_integrations
  ... AND provider='github'` to expose `github_url` to the frontend.

**Frontend:**
- `frontend/js/views/settings.js` — "GitHub Integration" card, mirrors the
  existing AI Provider card's layout and the portal-password "Set" button
  pattern (`has_github_pat` flag, never the token itself).
- `frontend/js/views/tickets.js` — `ticketRowHtml` shows a small "GH" badge
  when `github_url` is set; the ticket modal's status-button row grows a
  "Send to GitHub" button (or a "View on GitHub ↗" link once linked).

**Tests:** `backend/test/github.test.js` — mocks
`services/github.createIssue` via `node:test`'s `mock.method` (tickets.js
calls it as `github.createIssue(...)` off the required module object rather
than a destructured import specifically so this works). Covers the
not-configured 400, the secret-never-echoed PATCH round-trip, a successful
push, the already-linked 409, a GitHub API failure surfacing as 502 (not
500), and the `requireEditor` permission gate.

## Why not build bidirectional sync (v3) first

This was discussed with the user before building v1 — recorded here since
the reasoning is the actual justification for shipping the smaller thing:

- **Auth is per-provider, not generic.** Jira needs OAuth 2.0 3LO (refresh
  tokens, rotation). GitHub needs a GitHub App or a PAT. Linear needs its own
  API key model. There's no shared abstraction to build once.
- **Bidirectional sync means a public webhook endpoint** — unauthenticated
  by default, needs signature verification (HMAC, provider-specific scheme),
  replay protection, idempotency. Real security surface, ironic to get wrong
  in a pentest tool.
- **Status vocabularies don't map 1:1.** Flowdit tickets are
  `open`/`in_review`/`closed`. GitHub Issues is just open/closed (loses the
  `in_review` nuance). Jira workflows are arbitrary per-project. This needs
  either a mapping UI or a lossy hardcoded guess.
- **Conflict resolution** (status changed on both sides near-simultaneously)
  can't be designed well without real usage data on how often it actually
  happens.

v1 was scoped so none of this work is wasted: the `ticket_integrations`
table, the `github.js` API client, and the settings UI are the exact
foundation v3 needs. See below for what's additive.

## Extending to bidirectional sync (v3)

If usage justifies it, here's what changes and what doesn't:

**Reused as-is:**
- `ticket_integrations` table — a webhook handler writes into
  `external_status` (already exists, unused) instead of adding a column.
- `services/github.js` — extend with `updateIssue`/`getIssue`; the
  `createIssue` call in `tickets.js` doesn't change.
- The settings UI's repo/token fields — still needed regardless of auth
  model.

**New work, additive (not a rewrite):**
1. **Webhook receiver** — new route, e.g. `POST /webhooks/github`. Must
   verify GitHub's `X-Hub-Signature-256` HMAC before trusting the payload
   (see `crypto.timingSafeEqual`, not `===`, for the comparison). On a
   matching `ticket_integrations.external_id`, update `external_status` and
   optionally auto-transition the Flowdit ticket's `status`.
2. **Auth upgrade (maybe).** A PAT-per-project is fine for v1 (one consultant
   configures it once) but doesn't scale to "every org admin installs
   Flowdit into their GitHub org" — that needs a registered GitHub App
   (install flow, `installation_id`, short-lived installation tokens instead
   of a static PAT). This is a swap of *how the token is obtained*, not of
   `github.js`'s call shape.
3. **Status mapping UI.** A per-project setting: which GitHub label/state
   corresponds to Flowdit's `in_review`? (GitHub Issues has no native
   "in review" — likely modeled as a label, e.g. `flowdit:in-review`.)
4. **Conflict policy.** Simplest defensible default: last-write-wins by
   timestamp, surfaced in the UI so a consultant can see "GitHub says X,
   Flowdit says Y, GitHub wins because it changed more recently" rather than
   silently overwriting.
5. **Multi-provider.** If Jira/Linear are ever added, each is a new
   `services/<provider>.js` + a widened `provider` CHECK constraint — the
   `ticket_integrations` table already supports multiple rows per ticket
   (one per provider) via its `(ticket_id, provider)` unique key.

Rough sizing: v1 was roughly a day of focused work end-to-end (schema,
route, two frontend surfaces, tests, this doc). Bidirectional sync for a
single provider (webhook + status mapping + conflict handling, still no
GitHub App) is closer to a week; the GitHub App auth upgrade is a separate
chunk again on top of that.
