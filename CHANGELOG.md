# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project does not yet use semantic version tags — entries are grouped by release milestone instead.

## [Unreleased] — first public release

### Added
- Organizations — company/enterprise account layer above projects, with owner/admin/member roles and an org-wide admin panel
- Microsoft Entra ID SSO (OIDC), configurable per organization
- Real SVG icon set (Lucide, vendored — no CDN) replacing Unicode glyph icons
- Vulnerability template library for one-click common findings (SQLi, XSS, IDOR, SSRF, etc.)
- Remediation/retest workflow for findings, with audit trail
- Multi-provider AI (Groq + Anthropic), selectable per project, with estimated spend tracking
- All-in-one Docker Compose profile (backend + PostgreSQL + Nginx)
- Whiteboard — visual engagement map with real-time collaboration
- HTTP Proofs (request/response) with Burp Suite import and markdown annotations
- Burp Suite, Nessus, and OWASP ZAP scan import
- Client portal with real-time updates and email notifications
- DOCX and PDF report export

### Fixed
- Cross-project data isolation (IDOR) audit and remediation across `target_id`/`ticket_id` access paths

### Security
- Removed hardcoded database/JWT credentials from `docker-compose.yml` in favor of environment variable substitution
