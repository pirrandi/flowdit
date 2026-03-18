# Flowdit

> Pentest engagement management platform with real-time client portal, vulnerability tracking, and professional PDF reporting.

![Stack](https://img.shields.io/badge/stack-Node.js%20%2F%20PostgreSQL%20%2F%20Nginx-informational?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## What is Flowdit?

Flowdit is a self-hosted platform built for penetration testers and security consultants. It centralizes everything that happens during an engagement — findings, targets, methodology checklists, team activity — and exposes a live read-only portal so clients can follow the project in real time.

No more delivering a PDF at the end and hoping the client trusts the process. With Flowdit, they see it as it happens.

---

## Features

- **Project management** — create engagements, assign team members, track status
- **Vulnerability tracking** — custom vuln library with severity, CVSS v3.1 scoring, checklist items, payloads, and notes
- **CVSS v3.1 calculator** — built-in interactive calculator with vector string generation
- **Targets** — track hosts, IPs, and endpoints per project
- **Methodologies** — custom test libraries (WSTG, PortSwigger, or your own)
- **Client portal** — read-only view for clients with configurable visibility per section
- **Real-time activity** — WebSocket-powered live feed of team actions
- **PDF export** — professional report generation with findings, executive summary, and risk breakdown
- **Project branding** — upload project logo with light/dark background support
- **Team management** — invite members, assign roles (owner / member)

---

## Stack

| Layer     | Technology                        |
|-----------|-----------------------------------|
| Backend   | Node.js + Express                 |
| Database  | PostgreSQL                        |
| Auth      | JWT (access + refresh tokens)     |
| Realtime  | WebSockets (ws)                   |
| Frontend  | Vanilla JS, HTML, CSS             |
| Reverse proxy | Nginx                         |
| Process   | PM2                               |

---

## Self-hosting

### Requirements

- Node.js 18+
- PostgreSQL 14+
- Nginx
- PM2

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/Pirrandi/flowdit.git
cd flowdit

# 2. Configure environment
cp .env.example .env
cp backend/.env.example backend/.env
# Edit both .env files with your values

# 3. Install backend dependencies
cd backend && npm install

# 4. Start the backend (runs migrations automatically on first start)
pm2 start src/index.js --name flowdit
pm2 save

# 5. Configure Nginx
# Point your domain to the frontend/ directory
# Proxy /api and /ws to the backend port (default: 3000)
# See DEPLOY.md for full Nginx config
```

### Environment variables

| Variable        | Description                        |
|-----------------|------------------------------------|
| `DB_HOST`       | PostgreSQL host                    |
| `DB_NAME`       | Database name                      |
| `DB_USER`       | Database user                      |
| `DB_PASSWORD`   | Database password                  |
| `JWT_SECRET`    | Secret for JWT signing             |
| `PORT`          | Backend port (default: 3000)       |

See `.env.example` and `backend/.env.example` for the full list.

---

## Project structure

```
flowdit/
├── backend/
│   └── src/
│       ├── db/          # PostgreSQL client + migrations
│       ├── middleware/  # Auth, project access control
│       ├── routes/      # REST API endpoints
│       └── services/    # WebSocket, activity log
├── frontend/
│   ├── css/             # Global styles
│   ├── js/
│   │   ├── views/       # Page-level JS (vulns, targets, dashboard...)
│   │   ├── services/    # API client, state, WebSocket, utils
│   │   └── components/  # Shared UI components (activity feed...)
│   └── *.html           # One HTML file per view
└── nginx/               # Nginx config example
```

---

## Roadmap

- [ ] Public registration + organization/workspace support
- [ ] Jira / Linear integration for ticket sync
- [ ] Nessus / Burp XML import
- [ ] Two-factor authentication
- [ ] Audit log export

---

## License

MIT
