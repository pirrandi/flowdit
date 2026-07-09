const path = require('path');
// Load .env from backend/ regardless of where node is invoked from
require('dotenv').config({ path: path.resolve(__dirname, '../../..', '.env') });
const db = require('./index');

const migrations = [


  `CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(50)  UNIQUE NOT NULL,
    email       VARCHAR(255) UNIQUE NOT NULL,
    password    VARCHAR(255) NOT NULL,
    avatar_color VARCHAR(7) NOT NULL DEFAULT '#7c3aed',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      VARCHAR(512) UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(200) NOT NULL,
    target      VARCHAR(500),
    description TEXT,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status      VARCHAR(20) NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','completed','archived')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS targets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    host        VARCHAR(500) NOT NULL,
    type        VARCHAR(20)  NOT NULL DEFAULT 'domain'
                  CHECK (type IN ('domain','ip','cidr','url','other')),
    scope       VARCHAR(10)  NOT NULL DEFAULT 'in'
                  CHECK (scope IN ('in','out')),
    status      VARCHAR(20)  NOT NULL DEFAULT 'active'
                  CHECK (status IN ('active','completed','out-of-scope')),
    notes       TEXT,
    added_by    UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS project_members (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    role       VARCHAR(20) NOT NULL DEFAULT 'member'
                 CHECK (role IN ('owner','editor','viewer')),
    invited_by UUID REFERENCES users(id),
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
  )`,

  `CREATE TABLE IF NOT EXISTS project_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    invited_by  UUID NOT NULL REFERENCES users(id),
    role        VARCHAR(20) NOT NULL DEFAULT 'editor',
    token       VARCHAR(128) UNIQUE NOT NULL,
    label       VARCHAR(100),
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS wstg_progress (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_id     VARCHAR(50) NOT NULL,
    status      VARCHAR(10) CHECK (status IN ('done','fail',null)),
    note        TEXT,
    updated_by  UUID REFERENCES users(id),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, test_id)
  )`,

  `CREATE TABLE IF NOT EXISTS wstg_item_checks (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_id    VARCHAR(50) NOT NULL,
    item_idx   INTEGER NOT NULL,
    checked    BOOLEAN NOT NULL DEFAULT false,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, test_id, item_idx)
  )`,

  `CREATE TABLE IF NOT EXISTS ps_progress (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    cat_id     VARCHAR(20) NOT NULL,
    lab_idx    INTEGER NOT NULL,
    done       BOOLEAN NOT NULL DEFAULT false,
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, cat_id, lab_idx)
  )`,

  `CREATE TABLE IF NOT EXISTS custom_vulns (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name          VARCHAR(300) NOT NULL,
    category      VARCHAR(100) NOT NULL DEFAULT 'Custom',
    items         JSONB NOT NULL DEFAULT '[]',
    payloads      JSONB NOT NULL DEFAULT '[]',
    notes         TEXT,
    status        VARCHAR(10) CHECK (status IN ('done','fail',null)),
    checked_items JSONB NOT NULL DEFAULT '{}',
    created_by    UUID REFERENCES users(id),
    updated_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  // ── CUSTOM METHODOLOGIES ─────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS methodologies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(200) NOT NULL,
    description TEXT,
    is_shared   BOOLEAN NOT NULL DEFAULT false,
    tests       JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `CREATE TABLE IF NOT EXISTS methodology_progress (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    methodology_id  UUID NOT NULL REFERENCES methodologies(id) ON DELETE CASCADE,
    test_idx        INTEGER NOT NULL,
    status          VARCHAR(10) CHECK (status IN ('done','fail',null)),
    note            TEXT,
    target_id       UUID REFERENCES targets(id) ON DELETE SET NULL,
    updated_by      UUID REFERENCES users(id),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, methodology_id, test_idx)
  )`,

  `CREATE TABLE IF NOT EXISTS project_methodologies (
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    methodology_id  UUID NOT NULL REFERENCES methodologies(id) ON DELETE CASCADE,
    added_by        UUID REFERENCES users(id),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, methodology_id)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_project_methodologies ON project_methodologies(project_id)`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS active_methodology_ids UUID[] NOT NULL DEFAULT '{}'`,
  `CREATE INDEX IF NOT EXISTS idx_methodologies_owner    ON methodologies(owner_id)`,
  `CREATE INDEX IF NOT EXISTS idx_method_progress_proj   ON methodology_progress(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_method_progress_method ON methodology_progress(methodology_id)`,

  // ── ACTIVITY LOG ─────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS activity_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action      VARCHAR(50) NOT NULL,
    entity_type VARCHAR(30) NOT NULL,
    entity_id   VARCHAR(100),
    entity_name VARCHAR(300),
    meta        JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  // indexes
  `CREATE INDEX IF NOT EXISTS idx_project_members_user  ON project_members(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_wstg_progress_project ON wstg_progress(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_ps_progress_project   ON ps_progress(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_custom_vulns_project  ON custom_vulns(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_activity_log_project  ON activity_log(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_activity_log_created  ON activity_log(created_at DESC)`,


  // ── Column patches (safe to run on existing DBs) ────────────────
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES targets(id) ON DELETE SET NULL`,
  `CREATE INDEX IF NOT EXISTS idx_targets_project ON targets(project_id)`,
  `ALTER TABLE wstg_progress ADD COLUMN IF NOT EXISTS target_id UUID REFERENCES targets(id) ON DELETE SET NULL`,
  `ALTER TABLE wstg_progress ADD COLUMN IF NOT EXISTS description TEXT`,
  `ALTER TABLE wstg_progress ADD COLUMN IF NOT EXISTS remediation TEXT`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS description TEXT`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS remediation TEXT`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '[]'`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS severity VARCHAR(10) NOT NULL DEFAULT 'medium' CHECK (severity IN ('critical','high','medium','low','info'))`,
  `ALTER TABLE ps_progress ADD COLUMN IF NOT EXISTS note TEXT`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color VARCHAR(7) NOT NULL DEFAULT '#7c3aed'`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id)`,

  `CREATE OR REPLACE FUNCTION update_updated_at()
   RETURNS TRIGGER AS $$
   BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
   $$ LANGUAGE plpgsql`,

  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_users_updated_at') THEN
      CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_projects_updated_at') THEN
      CREATE TRIGGER trg_projects_updated_at BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_custom_vulns_updated_at') THEN
      CREATE TRIGGER trg_custom_vulns_updated_at BEFORE UPDATE ON custom_vulns FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
  END $$`,

  // ── CLIENT VIEW & TICKETS (Fase 2) ───────────────────────────────

  // Flags en projects para habilitar vista cliente y tickets
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS client_view_enabled BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS tickets_enabled     BOOLEAN NOT NULL DEFAULT false`,

  // Visibilidad granular para el cliente
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS show_findings      BOOLEAN NOT NULL DEFAULT true`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS show_wstg_progress BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS show_wstg_notes    BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS show_targets       BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS show_activity      BOOLEAN NOT NULL DEFAULT false`,

  // Puertos/servicios por target
  `CREATE TABLE IF NOT EXISTS target_ports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id   UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol    VARCHAR(3) NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp','udp')),
    state       VARCHAR(10) NOT NULL DEFAULT 'open' CHECK (state IN ('open','filtered','closed')),
    service     VARCHAR(100),
    version     VARCHAR(200),
    notes       TEXT,
    added_by    UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_target_ports_target ON target_ports(target_id)`,

  // Endpoints testeados por target
  `CREATE TABLE IF NOT EXISTS target_endpoints (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id   UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    path        VARCHAR(1000) NOT NULL,
    method      VARCHAR(10) NOT NULL DEFAULT 'GET' CHECK (method IN ('GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','OTHER')),
    status_code INTEGER,
    interesting BOOLEAN NOT NULL DEFAULT false,
    notes       TEXT,
    added_by    UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_target_endpoints_target ON target_endpoints(target_id)`,

  // Tickets de consulta por vulnerabilidad
  `CREATE TABLE IF NOT EXISTS tickets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vuln_id     UUID REFERENCES custom_vulns(id) ON DELETE SET NULL,
    title       VARCHAR(300) NOT NULL,
    description TEXT,
    status      VARCHAR(10) NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_review','closed')),
    opened_by   UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_tickets_project ON tickets(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_tickets_vuln    ON tickets(vuln_id)`,

  // Respuestas de tickets (hilo)
  `CREATE TABLE IF NOT EXISTS ticket_replies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id   UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    body        TEXT NOT NULL,
    author_id   UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ticket_replies_ticket ON ticket_replies(ticket_id)`,

  // ── PROFILE (Fase — avatar + display name) ───────────────────────
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT`,

  // ── PROJECT LOGO ─────────────────────────────────────────────────
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS logo_url TEXT`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS logo_bg  VARCHAR(5) NOT NULL DEFAULT 'light' CHECK (logo_bg IN ('light','dark'))`,

  // ── CVSS v3.1 on findings ────────────────────────────────────────
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS cvss_vector TEXT`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS cvss_score  NUMERIC(3,1)`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS logo_bg  VARCHAR(5) NOT NULL DEFAULT 'light' CHECK (logo_bg IN ('light','dark'))`,

  // ── CWE on findings ──────────────────────────────────────────────
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS cwe VARCHAR(20)`,

  // ── WSTG N/A status + link to custom vuln ────────────────────────
  `ALTER TABLE wstg_progress DROP CONSTRAINT IF EXISTS wstg_progress_status_check`,
  `ALTER TABLE wstg_progress ADD CONSTRAINT wstg_progress_status_check CHECK (status IN ('done','fail','na') OR status IS NULL)`,
  `ALTER TABLE wstg_progress ADD COLUMN IF NOT EXISTS linked_vuln_id UUID REFERENCES custom_vulns(id) ON DELETE SET NULL`,

  // Trigger updated_at para tickets
  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_tickets_updated_at') THEN
      CREATE TRIGGER trg_tickets_updated_at BEFORE UPDATE ON tickets FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
  END $$`,

  // ── TIMELINE + MEMBER LABELS (Fase — dates & invite labels) ─────────
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS date_start  DATE`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS date_end    DATE`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS date_report DATE`,
  `ALTER TABLE project_members ADD COLUMN IF NOT EXISTS label VARCHAR(100)`,
  `ALTER TABLE project_invites  ADD COLUMN IF NOT EXISTS label VARCHAR(100)`,

  // ── PORTAL TOKEN AUTH ────────────────────────────────────────────────
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS portal_token            TEXT UNIQUE`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS portal_password_hash    TEXT`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS portal_require_password BOOLEAN NOT NULL DEFAULT false`,

  // ── PORTAL TICKET SUPPORT ─────────────────────────────────────────────
  // Allow portal (non-user) ticket creation: opened_by and author_id become nullable
  `ALTER TABLE tickets ALTER COLUMN opened_by DROP NOT NULL`,
  `ALTER TABLE tickets ADD COLUMN IF NOT EXISTS client_name  VARCHAR(200)`,
  `ALTER TABLE tickets ADD COLUMN IF NOT EXISTS client_email VARCHAR(255)`,
  `ALTER TABLE ticket_replies ALTER COLUMN author_id DROP NOT NULL`,
  `ALTER TABLE ticket_replies ADD COLUMN IF NOT EXISTS client_name VARCHAR(200)`,

  // ── HTTP PROOFS (request/response from scanner imports) ─────────────
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS http_proofs JSONB NOT NULL DEFAULT '[]'`,

  // ── WHITEBOARD ───────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS whiteboard_state (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    data        JSONB NOT NULL DEFAULT '{}',
    updated_by  UUID REFERENCES users(id),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_whiteboard_state_project ON whiteboard_state(project_id)`,

  // ── VULN TEMPLATES ───────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS vuln_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(200) NOT NULL,
    category    VARCHAR(100),
    severity    VARCHAR(20) NOT NULL DEFAULT 'medium',
    cwe         VARCHAR(50),
    description TEXT,
    remediation TEXT,
    cvss_vector VARCHAR(200),
    is_builtin  BOOLEAN NOT NULL DEFAULT FALSE,
    created_by  UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_vuln_templates_name ON vuln_templates USING gin(to_tsvector('english', name))`,

  // ── AI PROVIDER (per-project) ────────────────────────────────────────
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ai_provider VARCHAR(20) NOT NULL DEFAULT 'groq' CHECK (ai_provider IN ('groq','anthropic'))`,
  // NULL = use the provider's default model (GROQ_MODEL / ANTHROPIC_MODEL env var)
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ai_model VARCHAR(50)`,

  // ── AI USAGE LOG (estimated spend, computed from the token counts each call already returns) ──
  `CREATE TABLE IF NOT EXISTS ai_usage (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    provider      VARCHAR(20) NOT NULL,
    model         VARCHAR(50) NOT NULL,
    action        VARCHAR(30) NOT NULL,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd      NUMERIC(12,6),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ai_usage_project ON ai_usage(project_id)`,

  // ── REMEDIATION / RETEST WORKFLOW ────────────────────────────────────
  // Separate from the legacy `status` column (done/fail — a confirmed/vulnerable
  // toggle inherited from the checklist model). This tracks the finding's
  // real-world lifecycle through the client's fix.
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS remediation_status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (remediation_status IN ('open','remediated','verified_closed'))`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS remediated_at  TIMESTAMPTZ`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS retest_date    DATE`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS retest_notes   TEXT`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS verified_at    TIMESTAMPTZ`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS verified_by    UUID REFERENCES users(id) ON DELETE SET NULL`,

  // ── ORGANIZATIONS (foundational layer for company/enterprise use) ────
  // An organization groups multiple projects under one company account,
  // with its own membership separate from any single project's sharing.
  // Every user gets a silent personal org at registration (is_personal=true);
  // creating a real second org (a company account) is opt-in.
  `CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(200) NOT NULL,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_personal BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  // role tiers deliberately differ from project_members (owner/editor/viewer):
  // only owner/admin grant implicit access to every project in the org —
  // plain 'member' grants zero implicit project access (still needs an
  // explicit per-project invite, exactly like today).
  `CREATE TABLE IF NOT EXISTS organization_members (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            VARCHAR(20) NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','member')),
    invited_by      UUID REFERENCES users(id),
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, user_id)
  )`,

  `CREATE TABLE IF NOT EXISTS organization_invites (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    invited_by       UUID NOT NULL REFERENCES users(id),
    role             VARCHAR(20) NOT NULL DEFAULT 'member' CHECK (role IN ('owner','admin','member')),
    token            VARCHAR(128) UNIQUE NOT NULL,
    label            VARCHAR(100),
    expires_at       TIMESTAMPTZ NOT NULL,
    accepted_at      TIMESTAMPTZ,
    accepted_by      UUID REFERENCES users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE`,

  `CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_organizations_owner ON organizations(owner_id)`,
  // one personal org per owner — makes the backfill/register-time auto-create idempotent
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_org_one_personal_per_owner ON organizations(owner_id) WHERE is_personal`,

  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_organizations_updated_at') THEN
      CREATE TRIGGER trg_organizations_updated_at BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
  END $$`,

  // ── SSO (per-organization OIDC — Microsoft Entra ID first, provider-agnostic) ──
  // email_domain is stored already-lowercased/trimmed by the route layer so the
  // login-time lookup is a plain indexed equality match, no LOWER() at query time.
  `CREATE TABLE IF NOT EXISTS organization_sso_configs (
    organization_id   UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    issuer_url        TEXT NOT NULL,
    client_id         VARCHAR(255) NOT NULL,
    client_secret_enc TEXT NOT NULL,
    email_domain      VARCHAR(255) NOT NULL,
    enforce           BOOLEAN NOT NULL DEFAULT false,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  // only one *enabled* org may claim a given email domain
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_sso_domain_enabled ON organization_sso_configs(email_domain) WHERE enabled`,

  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_org_sso_configs_updated_at') THEN
      CREATE TRIGGER trg_org_sso_configs_updated_at BEFORE UPDATE ON organization_sso_configs FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
  END $$`,

  // ── TOTP 2FA (per-user, opt-in) ────────────────────────────────────
  // totp_secret_enc is AES-256-GCM (utils/crypto.js, reusing SSO_ENCRYPTION_KEY)
  // rather than plaintext — same trust boundary as the SSO client secret.
  // totp_enabled flips true only after the user proves possession of the
  // secret via /auth/mfa/enable, so a `setup` call that's never confirmed
  // leaves a dead secret in place but never blocks login.
  // totp_backup_codes holds bcrypt hashes only, one-time-use (removed from
  // the array on redemption) — never the plaintext codes.
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_backup_codes JSONB NOT NULL DEFAULT '[]'`,
];

const BUILTIN_TEMPLATES = [
  { name: 'SQL Injection', category: 'Injection', severity: 'critical', cwe: 'CWE-89',
    description: 'The application constructs SQL queries using unsanitized user input, allowing an attacker to manipulate the query logic. This can lead to unauthorized data access, data modification, authentication bypass, or remote code execution depending on the database configuration.',
    remediation: 'Use parameterized queries or prepared statements for all database interactions. Apply the principle of least privilege to database accounts. Implement input validation and consider using an ORM that handles query parameterization automatically.' },

  { name: 'Blind SQL Injection', category: 'Injection', severity: 'high', cwe: 'CWE-89',
    description: 'The application is vulnerable to SQL injection but does not return query results or errors directly. An attacker can infer information through boolean-based or time-based techniques, enabling enumeration of the database schema and extracted data.',
    remediation: 'Use parameterized queries or prepared statements for all database interactions. Apply the principle of least privilege to database accounts and disable verbose error messages in production.' },

  { name: 'Reflected Cross-Site Scripting (XSS)', category: 'XSS', severity: 'medium', cwe: 'CWE-79',
    description: 'User-supplied input is reflected in the HTTP response without proper encoding, allowing an attacker to inject and execute arbitrary JavaScript in a victim browser. Exploitation typically requires the victim to visit a crafted URL, making it suitable for phishing attacks.',
    remediation: 'Encode all user-supplied output using context-appropriate encoding (HTML, JavaScript, URL). Implement a Content Security Policy (CSP) header. Validate and sanitize inputs server-side using an allowlist approach.' },

  { name: 'Stored Cross-Site Scripting (XSS)', category: 'XSS', severity: 'high', cwe: 'CWE-79',
    description: 'Malicious scripts supplied by an attacker are persistently stored in the application database and executed in the browser of every user who views the affected content. This enables session hijacking, credential theft, and defacement affecting all users without requiring social engineering.',
    remediation: 'Sanitize and encode all user-supplied content before storing and rendering it. Use a Content Security Policy (CSP) header and restrict the allowed HTML tags with a strict allowlist if rich content is required (e.g., DOMPurify).' },

  { name: 'DOM-Based Cross-Site Scripting (XSS)', category: 'XSS', severity: 'medium', cwe: 'CWE-79',
    description: 'The application writes user-controlled data to the DOM using unsafe sinks (innerHTML, document.write, eval) without sanitization. The payload is never sent to the server, bypassing server-side defenses, and executes entirely in the victim browser.',
    remediation: 'Use safe DOM APIs (textContent, setAttribute) instead of innerHTML. Avoid passing user-controlled data to eval or similar sinks. Implement a strict Content Security Policy to reduce exploitability.' },

  { name: 'Command Injection', category: 'Injection', severity: 'critical', cwe: 'CWE-78',
    description: 'The application passes user-controlled data to a system shell without adequate sanitization, allowing an attacker to execute arbitrary OS commands with the privileges of the web server process. Full system compromise is typically achievable.',
    remediation: 'Avoid invoking OS commands from application code wherever possible. If system calls are necessary, use language-native APIs instead of shell invocation and validate inputs against a strict allowlist. Apply the principle of least privilege to the web server process.' },

  { name: 'Path Traversal', category: 'Injection', severity: 'high', cwe: 'CWE-22',
    description: 'The application uses user-supplied input to construct file paths without proper validation, allowing an attacker to traverse the directory structure and read or write arbitrary files outside the intended directory. Sensitive configuration files, credentials, or source code may be exposed.',
    remediation: 'Resolve file paths server-side and verify they reside within the intended base directory using canonical path comparison. Avoid using user input to construct file paths; use indirect references mapped server-side. Apply the principle of least privilege to file system permissions.' },

  { name: 'Server-Side Request Forgery (SSRF)', category: 'SSRF', severity: 'high', cwe: 'CWE-918',
    description: 'The application fetches remote resources based on user-supplied URLs without sufficient validation, allowing an attacker to cause the server to make requests to internal services, cloud metadata endpoints, or other restricted resources. In cloud environments this commonly leads to credential exposure via the instance metadata service.',
    remediation: 'Validate and sanitize all user-supplied URLs against an allowlist of permitted schemes, hosts, and ports. Block requests to private IP ranges (RFC 1918), loopback, and metadata endpoints. Disable HTTP redirects or validate the final destination after resolution.' },

  { name: 'XML External Entity Injection (XXE)', category: 'XXE', severity: 'high', cwe: 'CWE-611',
    description: 'The application parses XML input with external entity processing enabled, allowing an attacker to read arbitrary files from the server, perform SSRF, or cause denial of service. XXE is particularly impactful when combined with SSRF to reach internal services.',
    remediation: 'Disable external entity and DTD processing in the XML parser. Use a simpler data format such as JSON where XML is not strictly required. Keep XML parser libraries up to date.' },

  { name: 'Insecure Direct Object Reference (IDOR)', category: 'Access Control', severity: 'high', cwe: 'CWE-639',
    description: 'The application exposes internal object identifiers in requests and does not verify that the authenticated user is authorized to access the referenced object. An attacker can enumerate or modify these identifiers to access or manipulate other users data.',
    remediation: 'Enforce authorization checks on every resource access server-side, validating that the authenticated user owns or has permission to access the requested object. Avoid using predictable sequential identifiers; prefer UUIDs. Implement centralized authorization logic.' },

  { name: 'Broken Access Control', category: 'Access Control', severity: 'high', cwe: 'CWE-284',
    description: 'The application does not consistently enforce authorization restrictions, allowing users to access functionality or data beyond their intended privilege level. This may include accessing admin panels, other users records, or privileged API endpoints by manipulating requests.',
    remediation: 'Implement server-side authorization checks on every request using a centralized access control mechanism. Deny by default and explicitly grant permissions. Regularly audit access control logic and test with lower-privileged accounts.' },

  { name: 'Cross-Site Request Forgery (CSRF)', category: 'Auth', severity: 'medium', cwe: 'CWE-352',
    description: 'The application performs state-changing actions without verifying that the request originates from the legitimate user. An attacker can craft a malicious page that causes a victim browser to send authenticated requests to the application, performing actions such as account changes or transactions on their behalf.',
    remediation: 'Implement anti-CSRF tokens (synchronizer token pattern) for all state-changing requests. Use the SameSite=Strict or SameSite=Lax cookie attribute. Verify the Origin and Referer headers for sensitive operations.' },

  { name: 'Open Redirect', category: 'Redirect', severity: 'medium', cwe: 'CWE-601',
    description: 'The application accepts a user-controlled URL parameter and redirects the user to it without validation, allowing attackers to craft legitimate-looking URLs that redirect victims to malicious sites. This is commonly used in phishing campaigns to bypass URL reputation checks.',
    remediation: 'Validate redirect destinations against an allowlist of permitted URLs or domains. Avoid using user-supplied input in redirect parameters. If dynamic redirects are necessary, use indirect references mapped server-side.' },

  { name: 'JWT Algorithm Confusion', category: 'Auth', severity: 'high', cwe: 'CWE-347',
    description: 'The application accepts JWTs signed with the "none" algorithm or allows the client to specify the signing algorithm, enabling an attacker to forge arbitrary tokens without a valid signature. This leads to authentication bypass and privilege escalation.',
    remediation: 'Explicitly specify the expected signing algorithm server-side and reject tokens using unexpected algorithms, especially "none". Use a well-maintained JWT library and keep it updated. Rotate signing keys regularly.' },

  { name: 'Broken Authentication', category: 'Auth', severity: 'high', cwe: 'CWE-287',
    description: 'The application implements authentication mechanisms incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users identities temporarily or permanently.',
    remediation: 'Implement multi-factor authentication. Use strong adaptive hashing for passwords (bcrypt, argon2). Invalidate session tokens on logout and after a configurable timeout. Implement account lockout and rate limiting on authentication endpoints.' },

  { name: 'Sensitive Data Exposure', category: 'Info Disclosure', severity: 'medium', cwe: 'CWE-200',
    description: 'The application transmits, stores, or displays sensitive information (credentials, PII, session tokens, internal paths) in an insufficiently protected manner. An attacker with network access or access to logs can retrieve this information.',
    remediation: 'Identify and classify sensitive data. Encrypt sensitive data at rest and in transit using strong, current standards. Minimize data exposure by returning only what is necessary. Remove debugging information, stack traces, and internal paths from production responses.' },

  { name: 'CORS Misconfiguration', category: 'Misconfiguration', severity: 'medium', cwe: 'CWE-346',
    description: 'The application Cross-Origin Resource Sharing policy is overly permissive, reflecting arbitrary Origin headers or allowing credentials from untrusted origins. An attacker can make cross-origin requests from a malicious site and read the response, effectively bypassing same-origin protections.',
    remediation: 'Define an explicit allowlist of trusted origins and validate against it server-side. Never reflect the incoming Origin header directly. Set Access-Control-Allow-Credentials: true only for explicitly trusted, non-wildcard origins.' },

  { name: 'Missing Security Headers', category: 'Misconfiguration', severity: 'low', cwe: null,
    description: 'The application does not set critical security headers, leaving users exposed to clickjacking, MIME-type sniffing, cross-site scripting, and information disclosure attacks. While often low severity individually, missing headers represent a defense-in-depth gap.',
    remediation: 'Configure the following headers: Content-Security-Policy, X-Frame-Options (or frame-ancestors CSP directive), X-Content-Type-Options: nosniff, Strict-Transport-Security, Referrer-Policy, and Permissions-Policy. Use securityheaders.com to validate the configuration.' },

  { name: 'Clickjacking', category: 'Misconfiguration', severity: 'low', cwe: 'CWE-1021',
    description: 'The application does not prevent its pages from being loaded in an iframe, allowing an attacker to overlay a transparent iframe on a legitimate-looking page to trick users into clicking interface elements they cannot see, performing unintended actions.',
    remediation: 'Set the X-Frame-Options header to DENY or SAMEORIGIN, or use the Content-Security-Policy frame-ancestors directive. Prefer the CSP approach as X-Frame-Options is deprecated in newer specifications.' },

  { name: 'Directory Listing Enabled', category: 'Info Disclosure', severity: 'low', cwe: 'CWE-548',
    description: 'The web server is configured to display directory contents when no index file is present, exposing the file structure and potentially sensitive files such as configuration files, backups, or source code to unauthenticated users.',
    remediation: 'Disable directory listing in the web server configuration (e.g., Options -Indexes in Apache, autoindex off in Nginx). Ensure all directories that should not be publicly accessible have proper access controls applied.' },

  { name: 'Default Credentials', category: 'Auth', severity: 'critical', cwe: 'CWE-1392',
    description: 'The application or a component (admin panel, database, network device) is accessible using publicly known default credentials. An attacker can immediately gain unauthorized access without any exploitation.',
    remediation: 'Change all default credentials during initial setup and enforce this as part of the deployment process. Implement a credential policy that requires strong, unique passwords. Consider removing or disabling default accounts entirely where not required.' },

  { name: 'Account Enumeration', category: 'Info Disclosure', severity: 'low', cwe: 'CWE-204',
    description: 'The application returns different responses for valid and invalid usernames, allowing an attacker to enumerate registered users. This information can be leveraged for targeted attacks or credential stuffing campaigns.',
    remediation: 'Return identical error messages and status codes for invalid username and invalid password scenarios. Normalize response times for authentication failures using constant-time comparison. Implement rate limiting and account lockout policies.' },

  { name: 'Subdomain Takeover', category: 'Misconfiguration', severity: 'high', cwe: 'CWE-284',
    description: 'A DNS entry for a subdomain points to an external service (GitHub Pages, Heroku, S3) that has been deprovisioned or is not claimed. An attacker can claim the service and serve arbitrary content under the organization domain, enabling phishing, cookie theft, and CSP bypass.',
    remediation: 'Audit DNS records regularly and remove CNAME entries pointing to deprovisioned services. Implement a process to remove DNS entries before deprovisioning cloud services. Monitor subdomains using automated tools.' },

  { name: 'Host Header Injection', category: 'Injection', severity: 'medium', cwe: 'CWE-644',
    description: 'The application uses the HTTP Host header to construct URLs (password reset links, redirects) without validating it against an allowlist. An attacker can manipulate the Host header to poison the password reset flow, cause cache poisoning, or bypass security controls.',
    remediation: 'Validate the Host header against an allowlist of legitimate domain names. Configure the web server to reject requests with unexpected Host headers. Use absolute URLs constructed from server-side configuration, not from request headers.' },

  { name: 'Insecure Deserialization', category: 'Injection', severity: 'high', cwe: 'CWE-502',
    description: 'The application deserializes user-controlled data without integrity checks or type validation, allowing an attacker to manipulate serialized objects to achieve remote code execution, privilege escalation, or denial of service.',
    remediation: 'Avoid deserializing data from untrusted sources. If deserialization is necessary, use safe serialization formats (JSON over native formats) and implement integrity checks with digital signatures. Apply the principle of least privilege to processes that perform deserialization.' },

  { name: 'HTTP Request Smuggling', category: 'Injection', severity: 'high', cwe: 'CWE-444',
    description: 'The application is vulnerable to HTTP request smuggling due to discrepancies in how front-end and back-end servers parse Transfer-Encoding and Content-Length headers. An attacker can poison the request queue to bypass security controls, hijack user sessions, or perform cache poisoning.',
    remediation: 'Ensure consistent HTTP specification compliance across all servers in the chain. Configure front-end servers to use HTTP/2 for back-end connections where possible. Normalize ambiguous requests at the edge and reject those with conflicting framing headers.' },

  { name: 'Weak Password Policy', category: 'Auth', severity: 'medium', cwe: 'CWE-521',
    description: 'The application does not enforce a minimum password strength requirement, allowing users to set trivially guessable passwords. This increases the risk of successful brute-force, credential stuffing, and password spray attacks.',
    remediation: 'Enforce a minimum password length of at least 12 characters. Check passwords against known breached password lists (e.g., HaveIBeenPwned API). Implement multi-factor authentication and account lockout after repeated failed attempts.' },

  { name: 'SSL/TLS Misconfiguration', category: 'Crypto', severity: 'medium', cwe: 'CWE-326',
    description: 'The application supports outdated TLS versions (TLS 1.0/1.1), weak cipher suites, or has other TLS configuration weaknesses such as missing HSTS or improper certificate validation. This exposes communications to downgrade attacks and interception.',
    remediation: 'Enforce TLS 1.2 as the minimum supported version with TLS 1.3 preferred. Disable weak and export cipher suites. Implement HTTP Strict Transport Security (HSTS) with a minimum max-age of one year. Use certificates from a trusted CA.' },

  { name: 'GraphQL Introspection Enabled', category: 'Misconfiguration', severity: 'info', cwe: null,
    description: 'The GraphQL endpoint has introspection enabled in production, exposing the complete API schema including all types, queries, mutations, and arguments. This significantly aids attackers in mapping the attack surface and crafting targeted queries.',
    remediation: 'Disable introspection in production environments. If introspection is required for internal tooling, restrict access by IP allowlist or authentication. Consider applying query depth and complexity limits as an additional defense.' },

  { name: 'GraphQL Batching Attack', category: 'Misconfiguration', severity: 'medium', cwe: null,
    description: 'The GraphQL endpoint allows query batching without rate limiting, enabling an attacker to send hundreds of queries in a single HTTP request to perform brute-force attacks, bypass rate limiting, or amplify server load.',
    remediation: 'Implement query complexity and depth limits. Apply per-operation rate limiting rather than per-request. Consider disabling or restricting query batching in production if not required by legitimate clients.' },

  { name: 'Unrestricted File Upload', category: 'Upload', severity: 'high', cwe: 'CWE-434',
    description: 'The application accepts file uploads without adequately validating the file type, content, or name. An attacker can upload malicious files such as web shells, scripts, or polyglots that may be executed server-side or served to other users, leading to remote code execution or stored XSS.',
    remediation: 'Validate file type using server-side content inspection (magic bytes), not only the file extension or MIME type provided by the client. Store uploaded files outside the web root and serve them through a dedicated endpoint. Rename files on upload and restrict execution permissions on the upload directory.' },

  { name: 'Server-Side Template Injection (SSTI)', category: 'Injection', severity: 'critical', cwe: 'CWE-94',
    description: 'User-supplied input is embedded in a server-side template and evaluated by the template engine (Jinja2, Twig, Freemarker, Pebble, etc.) without sanitization. An attacker can inject template directives to read server files, enumerate environment variables, and achieve remote code execution.',
    remediation: 'Never pass user-controlled data directly into template strings. Use sandboxed template rendering where available and treat all user input as data, not as template code. Consider switching to logic-less templates (Mustache) for contexts where user input influences output.' },

  { name: 'Mass Assignment', category: 'Access Control', severity: 'high', cwe: 'CWE-915',
    description: 'The application binds HTTP request parameters directly to internal model objects without filtering, allowing an attacker to set fields that should not be user-controlled (e.g., is_admin, role, balance). This commonly leads to privilege escalation or data integrity issues.',
    remediation: 'Use explicit allowlists of permitted fields when binding request input to model objects. Never deserialize request bodies directly into database models. Apply strong input validation and use DTOs (Data Transfer Objects) to separate external input from internal state.' },

  { name: 'NoSQL Injection', category: 'Injection', severity: 'high', cwe: 'CWE-943',
    description: 'The application constructs NoSQL queries (MongoDB, Redis, CouchDB) using unsanitized user input, allowing an attacker to manipulate query operators to bypass authentication, extract data, or modify documents. Common attack vectors include injecting MongoDB operators such as $where, $gt, or $regex.',
    remediation: 'Validate and sanitize all user-supplied input before using it in database queries. Use typed query builders or ODMs that prevent operator injection. Reject input containing unexpected object structures or NoSQL operator keys.' },

  { name: 'Missing Rate Limiting', category: 'Misconfiguration', severity: 'medium', cwe: 'CWE-770',
    description: 'Critical endpoints (login, password reset, OTP verification, registration) do not implement rate limiting or account lockout, allowing an attacker to perform unlimited brute-force or enumeration attempts. This significantly reduces the effective security of any password or OTP-based control.',
    remediation: 'Implement rate limiting on all authentication and sensitive endpoints. Apply exponential backoff or temporary lockout after a configurable number of failed attempts. Use CAPTCHA for high-risk flows and alert on anomalous request volumes.' },

  { name: 'Insecure Password Reset', category: 'Auth', severity: 'high', cwe: 'CWE-640',
    description: 'The password reset mechanism contains one or more weaknesses: tokens are predictable, do not expire, can be reused after use, or are transmitted insecurely. An attacker can exploit these flaws to take over arbitrary user accounts without knowing the original password.',
    remediation: 'Generate password reset tokens using a cryptographically secure random source with at least 128 bits of entropy. Invalidate tokens after a single use and set a short expiry (15-30 minutes). Transmit tokens only over HTTPS and never include them in URLs that may be logged.' },

  { name: 'Session Fixation', category: 'Auth', severity: 'medium', cwe: 'CWE-384',
    description: 'The application does not regenerate the session identifier after a successful authentication event, allowing an attacker who has obtained a pre-authentication session ID (via XSS, network interception, or explicit fixation) to hijack the authenticated session.',
    remediation: 'Regenerate the session identifier upon every authentication event (login, privilege change). Invalidate all pre-authentication session tokens. Ensure session IDs are not accepted from URL parameters.' },

  { name: 'OAuth Misconfiguration', category: 'Auth', severity: 'high', cwe: 'CWE-601',
    description: 'The OAuth 2.0 implementation contains weaknesses such as an open redirect_uri, missing or predictable state parameter, or authorization code reuse. An attacker can exploit these to steal authorization codes, hijack OAuth flows, and gain unauthorized access to user accounts.',
    remediation: 'Register and validate exact redirect_uri values; reject partial or wildcard matches. Enforce the state parameter as a CSRF token with adequate entropy. Bind authorization codes to the client and ensure single use. Use PKCE for public clients.' },

  { name: 'Hardcoded Secrets', category: 'Info Disclosure', severity: 'high', cwe: 'CWE-798',
    description: 'Sensitive credentials, API keys, cryptographic secrets, or connection strings are hardcoded in application source code, configuration files, or JavaScript bundles. These secrets are accessible to anyone with access to the codebase, build artifacts, or browser developer tools.',
    remediation: 'Remove all hardcoded secrets from source code immediately and rotate the exposed credentials. Use environment variables or a secrets management solution (Vault, AWS Secrets Manager) to inject secrets at runtime. Add secret scanning to the CI/CD pipeline to prevent future occurrences.' },

  { name: 'Verbose Error Messages', category: 'Info Disclosure', severity: 'low', cwe: 'CWE-209',
    description: 'The application returns detailed error messages, stack traces, or debug information to end users in production. This reveals internal paths, library versions, database schema details, and implementation logic that significantly aids an attacker in profiling the target.',
    remediation: 'Configure the application to return generic error messages to users while logging detailed errors server-side. Disable debug mode and developer toolbars in production. Implement a centralized error handler that sanitizes output before returning it in HTTP responses.' },

  { name: 'Prototype Pollution', category: 'Injection', severity: 'high', cwe: 'CWE-1321',
    description: 'The application merges or clones user-supplied objects without sanitizing __proto__, constructor, or prototype keys, allowing an attacker to inject properties into the global Object prototype. This can lead to denial of service, property injection, or remote code execution in Node.js environments.',
    remediation: 'Use Object.create(null) for objects used as maps. Sanitize user input to reject keys such as __proto__ and constructor. Use safe merge libraries (e.g., lodash >= 4.17.21 with the merge fix applied) or implement recursive key validation before merging objects.' },

  { name: 'Race Condition', category: 'Logic', severity: 'high', cwe: 'CWE-362',
    description: 'The application performs multi-step operations (balance checks, coupon redemptions, vote counts, file writes) without adequate locking or atomicity, allowing an attacker to send concurrent requests that exploit the time-of-check to time-of-use (TOCTOU) window to obtain resources or permissions beyond what is authorized.',
    remediation: 'Use database-level atomic operations and transactions with appropriate isolation levels. Implement pessimistic locking for critical state changes. Avoid check-then-act patterns; use atomic compare-and-swap operations where possible. Apply per-user rate limiting on sensitive operations.' },

  { name: 'Business Logic Bypass', category: 'Logic', severity: 'high', cwe: 'CWE-840',
    description: 'The application enforces business rules (pricing, step sequences, quantity limits, discount application) only client-side or in a way that can be circumvented by manipulating request parameters. An attacker can bypass intended workflows to gain unauthorized discounts, skip verification steps, or manipulate financial values.',
    remediation: 'Enforce all business rules server-side and treat all client-supplied values as untrusted. Validate state transitions server-side and ensure multi-step flows cannot be completed out of order. Implement server-side recalculation of prices and quantities rather than accepting them from the client.' },

  { name: 'Exposed Admin Interface', category: 'Misconfiguration', severity: 'high', cwe: 'CWE-284',
    description: 'Administrative interfaces (/admin, /manager, phpMyAdmin, Kibana, Grafana, Jenkins) are exposed to the public internet without IP restriction or strong authentication. An attacker can attempt brute-force attacks or exploit default credentials to gain full administrative control.',
    remediation: 'Restrict access to administrative interfaces by IP allowlist or VPN. Enforce multi-factor authentication for all admin accounts. Remove or disable admin interfaces that are not required in production. Monitor for unauthorized access attempts.' },

  { name: 'LDAP Injection', category: 'Injection', severity: 'high', cwe: 'CWE-90',
    description: 'The application constructs LDAP queries using unsanitized user input, allowing an attacker to manipulate the query to bypass authentication, extract directory information, or enumerate users and groups from the LDAP directory.',
    remediation: 'Escape all user-supplied input before incorporating it into LDAP queries using a library-provided escaping function. Use parameterized LDAP APIs where available. Apply the principle of least privilege to the LDAP service account used by the application.' },

  { name: 'HTTP Method Override', category: 'Misconfiguration', severity: 'medium', cwe: 'CWE-650',
    description: 'The application or an intermediate proxy honors method override headers (X-HTTP-Method-Override, X-Method-Override, _method parameter), allowing an attacker to perform PUT, DELETE, or PATCH requests from a context where only GET and POST are permitted, bypassing firewall rules or access controls based on HTTP method.',
    remediation: 'Disable method override headers if not required by the application. If method override is necessary, validate that the requester has permission to use the overridden method and ensure the authorization logic uses the effective method, not the transport method.' },

  { name: 'WebSocket Injection', category: 'Injection', severity: 'high', cwe: 'CWE-79',
    description: 'The application processes WebSocket messages without adequate input validation or authorization checks, allowing an attacker to inject malicious payloads, perform cross-site WebSocket hijacking (CSWSH), or access WebSocket functionality without proper authentication.',
    remediation: 'Validate and sanitize all data received over WebSocket connections. Implement authentication for WebSocket handshakes (validate the Origin header and require session tokens). Apply the same authorization controls to WebSocket messages as to equivalent HTTP requests.' },

  { name: 'Two-Factor Authentication Bypass', category: 'Auth', severity: 'high', cwe: 'CWE-287',
    description: 'The two-factor authentication implementation can be bypassed through brute force of short OTP codes, reuse of previously valid codes, manipulation of the authentication flow to skip the 2FA step, or exploitation of backup code weaknesses.',
    remediation: 'Implement rate limiting and lockout on OTP verification attempts. Invalidate OTP codes immediately after use and enforce short expiry windows (30-60 seconds for TOTP). Ensure the 2FA verification step cannot be skipped by manipulating session state or request parameters.' },

  { name: 'Regular Expression Denial of Service (ReDoS)', category: 'Injection', severity: 'medium', cwe: 'CWE-1333',
    description: 'The application uses regular expressions with catastrophic backtracking properties on user-controlled input, allowing an attacker to supply crafted strings that cause the regex engine to consume excessive CPU time, leading to denial of service.',
    remediation: 'Audit regular expressions for catastrophic backtracking using tools such as safe-regex or rxxr2. Replace vulnerable patterns with linear-time alternatives. Implement input length limits before regex evaluation and consider using a regex timeout or a non-backtracking engine.' },

  { name: 'Insecure Direct Object Reference via Parameter Tampering', category: 'Access Control', severity: 'high', cwe: 'CWE-639',
    description: 'The application exposes sequential or predictable identifiers in hidden form fields, cookies, or request parameters that control which resource is accessed or modified. An attacker can tamper with these values to access or manipulate other users resources without authorization.',
    remediation: 'Validate server-side that the authenticated user is authorized to access or modify the referenced resource on every request. Use non-predictable identifiers (UUIDs) and implement a centralized authorization check rather than relying on the secrecy of parameter values.' },
];

async function seedTemplates(db) {
  let added = 0;
  for (const t of BUILTIN_TEMPLATES) {
    const { rowCount } = await db.query(
      `INSERT INTO vuln_templates (name, category, severity, cwe, description, remediation, is_builtin)
       SELECT $1,$2,$3,$4,$5,$6,TRUE
       WHERE NOT EXISTS (SELECT 1 FROM vuln_templates WHERE name=$1::varchar AND is_builtin=TRUE)`,
      [t.name, t.category, t.severity, t.cwe || null, t.description, t.remediation]
    );
    added += rowCount;
  }
  if (added > 0) console.log(`  ✦ Seeded ${added} built-in vulnerability templates`);
}

// One-time backfill: every pre-existing project gets grouped into a new
// personal organization owned by its current owner_id. Scoped to
// organization_id IS NULL so re-running this on every deploy is a no-op
// once fully backfilled. Does NOT touch other projects' project_members —
// existing collaborators/clients keep exactly their current access and are
// not added to the new org.
async function backfillOrganizations(db) {
  const { rows: owners } = await db.query(
    `SELECT DISTINCT owner_id FROM projects WHERE organization_id IS NULL`
  );
  let created = 0;
  for (const { owner_id } of owners) {
    const { rows: userRows } = await db.query(`SELECT username FROM users WHERE id=$1`, [owner_id]);
    if (!userRows.length) continue; // orphaned owner_id safety

    const { rows: orgRows } = await db.query(
      `INSERT INTO organizations (name, owner_id, is_personal)
       VALUES ($1,$2,true)
       ON CONFLICT (owner_id) WHERE is_personal DO NOTHING
       RETURNING id`,
      [`${userRows[0].username}'s Organization`, owner_id]
    );
    const orgId = orgRows[0]
      ? orgRows[0].id
      : (await db.query(`SELECT id FROM organizations WHERE owner_id=$1 AND is_personal=true`, [owner_id])).rows[0].id;

    await db.query(
      `INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1,$2,'owner')
       ON CONFLICT DO NOTHING`,
      [orgId, owner_id]
    );
    await db.query(
      `UPDATE projects SET organization_id=$1 WHERE owner_id=$2 AND organization_id IS NULL`,
      [orgId, owner_id]
    );
    created++;
  }
  if (created > 0) console.log(`  ✦ Backfilled ${created} personal organization(s)`);
}

async function migrate() {
  console.log('🔄 Running migrations...');
  for (const sql of migrations) {
    try { await db.query(sql); }
    catch (err) {
      console.error('Migration failed:', sql.slice(0,80), '\n', err.message);
      process.exit(1);
    }
  }
  await seedTemplates(db);
  await backfillOrganizations(db);
  console.log('✅ Migrations complete');
  process.exit(0);
}

migrate();