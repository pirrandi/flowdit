<p align="center">
  <img src="frontend/img/flowdit-logo.png" alt="Flowdit" height="60">
</p>

<p align="center">
  Self-hosted pentest engagement management platform — findings, targets, methodologies, client portal, and professional reports in one place.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/stack-Node.js%20%2F%20PostgreSQL%20%2F%20Nginx-informational?style=flat-square" alt="Stack">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/self--hosted-yes-blue?style=flat-square" alt="Self-hosted">
</p>

---

## What is Flowdit?

Flowdit is a self-hosted platform built for penetration testers and security consultants. It centralizes everything that happens during an engagement — findings, targets, methodology checklists, team activity — and exposes a live read-only portal so clients can follow the project in real time.

No more delivering a PDF at the end and hoping the client trusts the process. With Flowdit, they see it as it happens.

---

## Features

**Findings & Vulnerability Tracking**
- Custom vulnerability library with severity, CVSS v3.1 scoring, CWE, checklist items, payloads, and notes
- Built-in interactive CVSS v3.1 calculator with vector string generation
- Evidence attachments (screenshots) per finding
- HTTP Proofs — import request/response pairs from Burp Suite, annotate with markdown, include selectively in reports
- Burp Suite XML import

**Targets & Scope**
- Track hosts, IPs, CIDRs, URLs with in/out-of-scope status
- Port and service inventory per target
- Endpoint tracking with HTTP method, status code, and notes

**Methodologies**
- Full OWASP WSTG checklist with per-test notes and status
- PortSwigger Web Security Academy lab tracker
- Custom methodology builder — create reusable test libraries for your team

**Reporting**
- PDF export — professional report with executive summary, findings, risk breakdown, evidence, HTTP proofs, WSTG results, and targets table. Configurable sections, fonts, accent color, watermark, page header/footer, and password encryption
- DOCX export — full Word document generated server-side, no LibreOffice required

**Client Portal**
- Read-only view for clients, accessible via invite link
- Configurable visibility: findings, WSTG progress, targets, activity feed
- Ticket system — clients can open queries linked to specific findings; team responds in thread

**Collaboration**
- Team members with roles: owner, editor, viewer
- Real-time activity feed via WebSockets
- Collaborative whiteboard per project
- AI assistant for remediation suggestions and report text

**Platform**
- Project branding — upload logo per engagement
- Timeline tracking with start, end, and report dates
- Dark and light theme, compact density mode

---

## Stack

| Layer         | Technology                    |
|---------------|-------------------------------|
| Backend       | Node.js + Express             |
| Database      | PostgreSQL 15+                |
| Auth          | JWT (access + refresh tokens) |
| Realtime      | WebSockets                    |
| Frontend      | Vanilla JS, HTML, CSS         |
| Reverse proxy | Nginx                         |
| Process       | PM2                           |
| PDF export    | Puppeteer (Chromium headless) |
| DOCX export   | docx (native, no LibreOffice) |

---

## Self-hosting

### Requirements

- Ubuntu 22.04 LTS (or similar)
- Node.js 18+
- PostgreSQL 15+
- Nginx
- PM2 (`npm install -g pm2`)
- A domain with DNS pointed to your server
- Chromium or Google Chrome (for PDF export)

### Quick setup

```bash
# 1. Clone the repo
git clone https://github.com/Pirrandi/flowdit.git
cd flowdit

# 2. Configure environment
cp .env.example .env
# Edit .env with your values (DB credentials, JWT secret, domain)

# 3. Install backend dependencies
cd backend && npm install && cd ..

# 4. Run database migrations
cd backend && node src/db/migrate.js && cd ..

# 5. Start the backend with PM2
cd backend && pm2 start src/index.js --name flowdit-backend
pm2 save && pm2 startup

# 6. Configure Nginx
# Point your domain root to frontend/
# Proxy /api and /ws to the backend port (default: 4000)
# See DEPLOY.md for the full Nginx config and SSL setup
```

### Environment variables

| Variable        | Description                              | Required |
|-----------------|------------------------------------------|----------|
| `PORT`          | Backend port (default: 4000)            | No       |
| `DB_HOST`       | PostgreSQL host                          | Yes      |
| `DB_PORT`       | PostgreSQL port (default: 5432)         | No       |
| `DB_NAME`       | Database name                            | Yes      |
| `DB_USER`       | Database user                            | Yes      |
| `DB_PASSWORD`   | Database password                        | Yes      |
| `JWT_SECRET`    | Secret for JWT signing (min 64 chars)   | Yes      |
| `CORS_ORIGIN`   | Allowed frontend origin(s)              | Yes      |
| `FRONTEND_URL`  | Frontend URL, used in email links       | Yes      |
| `SMTP_HOST`     | SMTP server for email notifications     | No       |
| `SMTP_USER`     | SMTP username                            | No       |
| `SMTP_PASS`     | SMTP password                            | No       |

See `.env.example` for the full list with descriptions.

---

## Project structure

```
flowdit/
├── backend/
│   └── src/
│       ├── db/           # PostgreSQL client + migrations (idempotent)
│       ├── middleware/   # Auth guards, project access control
│       ├── routes/       # REST API endpoints
│       └── services/     # WebSocket hub, activity log, DOCX renderer, mailer
├── frontend/
│   ├── css/              # Global styles (Signal design system)
│   ├── img/              # Logo, favicon
│   ├── js/
│   │   ├── views/        # Page-level JS (dashboard, vulns, targets…)
│   │   ├── services/     # API client, state, WebSocket client, utils
│   │   └── components/   # Shared UI (activity feed)
│   └── *.html            # One HTML file per view
└── nginx/                # Nginx config reference
```

---

## Roadmap

- [ ] Nessus `.nessus` import
- [ ] Nmap XML import
- [ ] Common vulnerability template library
- [ ] Retest / remediation tracking workflow
- [ ] Email notifications for ticket replies
- [ ] CVSS v4.0 support
- [ ] Two-factor authentication
- [ ] CSV export for executive summaries

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT — see [LICENSE](LICENSE) for details.
