const path = require('path');
// Load .env from backend/ regardless of where node is invoked from
require('dotenv').config({ path: path.resolve(__dirname, '../../..', '.env') });
const db = require('./index');
const { seedTemplates } = require('./vuln-templates');
const { backfillLegacyPortalLinks } = require('../services/portalLinks');

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
    -- allowed values: project_members_role_check (DROP + ADD further down)
    role       VARCHAR(20) NOT NULL DEFAULT 'member',
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
  // Client-portal privacy switches (project settings). Default true = hide, so a
  // project is private-by-default: the internal team's uploaded avatars and the
  // exact timestamps of the activity log are NOT shown to the client unless the
  // owner explicitly opts into showing them.
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS portal_hide_team_avatars BOOLEAN NOT NULL DEFAULT true`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS portal_hide_log_times    BOOLEAN NOT NULL DEFAULT true`,

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
  // Sin CHECK inline a propósito: ADD COLUMN IF NOT EXISTS saltea la COLUMNA
  // cuando ya existe, pero igual crea el CHECK inline como constraint ANÓNIMO
  // nuevo en cada corrida (projects_ai_provider_check1, _check2, ...), y esos
  // quedan con la lista de proveedores VIEJA. Postgres evalúa todos los CHECK
  // con AND, así que el más restrictivo gana y agregar un proveedor nuevo
  // empieza a fallar con 500. El constraint vigente se define una sola vez,
  // más abajo, con nombre explícito.
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ai_provider VARCHAR(20) NOT NULL DEFAULT 'groq'`,
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
  // No inline CHECK here on purpose: ADD COLUMN IF NOT EXISTS still tries to
  // (re)create the inline constraint on every re-run, and once the base name is
  // taken by the 4-value constraint below it gets auto-named _check1 with the
  // old 3-value set — which then fails against any existing 'not_remediated'
  // row (hit live on prod). The constraint is owned solely by the DROP + ADD
  // pair below, so the column add stays constraint-free and idempotent.
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS remediation_status VARCHAR(20) NOT NULL DEFAULT 'open'`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS remediated_at  TIMESTAMPTZ`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS retest_date    DATE`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS retest_notes   TEXT`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS verified_at    TIMESTAMPTZ`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS verified_by    UUID REFERENCES users(id) ON DELETE SET NULL`,

  // 'not_remediated' — retest confirmed the finding is still present despite
  // a claimed fix. ADD COLUMN's inline CHECK above doesn't re-apply once the
  // column already exists (same trap as ai_provider below), so the allowed
  // values are updated explicitly here.
  `ALTER TABLE custom_vulns DROP CONSTRAINT IF EXISTS custom_vulns_remediation_status_check`,
  `ALTER TABLE custom_vulns ADD CONSTRAINT custom_vulns_remediation_status_check
     CHECK (remediation_status IN ('open','remediated','not_remediated','verified_closed'))`,

  // ── PROJECT ROLES: + pentester ──────────────────────────────────────
  // pentester = technical work only, no client-facing actions (see
  // middleware/project.js). The CREATE TABLE above used to carry this CHECK
  // inline; it's now owned solely by this explicitly-named DROP + ADD pair so
  // the value list can change without leaving a stale copy behind (fresh DBs
  // used to get the inline one auto-named project_members_role_check — same
  // name, so this replaces it there too).
  `ALTER TABLE project_members DROP CONSTRAINT IF EXISTS project_members_role_check`,
  `ALTER TABLE project_members ADD CONSTRAINT project_members_role_check
     CHECK (role IN ('owner','editor','pentester','viewer'))`,

  // ── CLIENT-PORTAL PUBLISH FLAG ──────────────────────────────────────
  // Findings are HIDDEN from the client portal until the pentester explicitly
  // publishes them (opt-in): a draft or half-triaged finding must never leak to
  // the client just because the portal link exists. New rows default to false.
  //
  // Idempotent backfill without re-publishing on every migrate run: add the
  // column NULLable, set every still-NULL row (i.e. rows that predate the
  // column) to true so existing client-visible findings stay visible, THEN set
  // the default/NOT NULL. After the first run nothing is NULL, so the UPDATE is
  // a no-op and never overrides a pentester's later un-publish.
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS client_visible BOOLEAN`,
  `UPDATE custom_vulns SET client_visible = true WHERE client_visible IS NULL`,
  `ALTER TABLE custom_vulns ALTER COLUMN client_visible SET DEFAULT false`,
  `ALTER TABLE custom_vulns ALTER COLUMN client_visible SET NOT NULL`,

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

  // ── GitHub Issues integration (v1 — one-way push, per project) ──────
  // github_pat_enc is AES-256-GCM (utils/crypto.js, same key as the SSO
  // client secret / TOTP secret) — a GitHub PAT is as sensitive as either.
  // v1 is deliberately one-directional: a ticket is pushed to GitHub once
  // and the link is kept for reference, nothing is pulled back. See
  // GITHUB_INTEGRATION.md for the full design and the path to a future
  // bidirectional (webhook-based) sync.
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS github_repo VARCHAR(255)`,
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS github_pat_enc TEXT`,

  // Per-project AI provider API keys (Groq/DeepSeek/Anthropic/Kimi) — same
  // AES-256-GCM encryption as github_pat_enc above, keyed jsonb so a
  // project can override some providers and fall back to the host's
  // global env-var key for the rest. The 'custom' provider is deliberately
  // excluded — its base_url is host-level only (SSRF concern, see
  // services/ai/custom.js), unrelated to this.
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ai_api_keys_enc JSONB NOT NULL DEFAULT '{}'::jsonb`,

  // external_status exists now but is unwritten in v1 — reserved for a
  // future webhook handler to record GitHub's side of the issue without a
  // schema change. provider is already a column (not assumed to be
  // "github") so Jira/Linear can be added as siblings later, one row per
  // (ticket, provider).
  `CREATE TABLE IF NOT EXISTS ticket_integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id       UUID NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    provider        VARCHAR(20) NOT NULL DEFAULT 'github' CHECK (provider IN ('github')),
    external_id     VARCHAR(100) NOT NULL,
    external_url    TEXT NOT NULL,
    external_status VARCHAR(30),
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (ticket_id, provider)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ticket_integrations_ticket ON ticket_integrations(ticket_id)`,

  // ── COMPLIANCE TAGGING (PCI-DSS v1 — framework-agnostic key for future frameworks) ──
  // Shape per tag: { control_id: '6.5.1', title: 'Injection flaws' }. Framework is
  // implicit (PCI-DSS only for now) — no framework field yet, kept as `compliance_tags`
  // (not `pci_tags`) so other frameworks can be added later without a rename.
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS compliance_tags JSONB NOT NULL DEFAULT '[]'`,

  // ── AI PENTEST AGENT (scanner) ───────────────────────────────────────
  // Diseño completo en AI_PENTEST_AGENT.md (branch feature/ai-pentest-agent).
  // Una sesión es una máquina de estados; ai_scan_events es el log completo
  // (event sourcing) usado tanto para auditoría como para reconstruir el
  // estado de quien se conecta tarde al WebSocket.
  `CREATE TABLE IF NOT EXISTS ai_scan_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_id     UUID REFERENCES targets(id) ON DELETE SET NULL, -- null = alcance de todo el proyecto
    status        VARCHAR(20) NOT NULL DEFAULT 'idle'
                    CHECK (status IN ('idle','running','waiting_approval','paused','completed','error')),
    current_phase VARCHAR(50),
    started_by    UUID NOT NULL REFERENCES users(id),
    started_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ai_scan_sessions_project ON ai_scan_sessions(project_id)`,

  `CREATE TABLE IF NOT EXISTS ai_scan_events (
    id          BIGSERIAL PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES ai_scan_sessions(id) ON DELETE CASCADE,
    -- thread_id: sin uso en V1 (siempre NULL). V1 bloquea la sesión ENTERA
    -- ante cualquier finding.proposed pendiente (más simple de razonar).
    -- Gancho barato para la extensión futura a paralelismo (varios hilos de
    -- trabajo por sesión, ej. uno por target, donde una aprobación pendiente
    -- en un hilo no frena a los demás) — evita alterar la tabla ese día,
    -- alcanza con empezar a poblar esta columna. Ver AI_PENTEST_AGENT.md
    -- y ROADMAP.md → "Scanner de IA — soporte multi-hilo".
    thread_id   UUID,
    type        VARCHAR(50) NOT NULL, -- 'phase.started', 'finding.proposed', 'chat.message', etc.
    payload     JSONB NOT NULL DEFAULT '{}',
    created_by  UUID REFERENCES users(id), -- NULL = lo generó la IA, no un humano
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ai_scan_events_session ON ai_scan_events(session_id, created_at)`,

  // ── DEEPSEEK PROVIDER (OpenAI-compatible, ver openaiCompatible.js) ───
  // El DROP+ADD de este CHECK constraint se sacó de acá — ver comentario
  // más abajo, junto a la versión final del constraint, para el porqué
  // (bug real: re-imponer una versión vieja del constraint en cada arranque
  // rompía si algún proyecto ya usaba un provider agregado más tarde).

  // ── ORQUESTACIÓN MULTI-AGENTE (cobra el gancho thread_id de más arriba) ──
  // El thread con parent_thread_id NULL es el coordinador (el que "habla"
  // con el pentester); cada delegate_to_subagent crea uno hijo. Un solo
  // nivel de delegación — enforced en código (agentLoop.js), no acá.
  // Diseño completo en AI_PENTEST_AGENT.md § "Orquestación multi-agente".
  `CREATE TABLE IF NOT EXISTS ai_scan_threads (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id        UUID NOT NULL REFERENCES ai_scan_sessions(id) ON DELETE CASCADE,
    parent_thread_id  UUID REFERENCES ai_scan_threads(id) ON DELETE SET NULL,
    label             VARCHAR(200),
    status            VARCHAR(20) NOT NULL DEFAULT 'running'
                        CHECK (status IN ('running','idle','waiting_approval','completed','error')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at      TIMESTAMPTZ
  )`,
  `CREATE INDEX IF NOT EXISTS idx_ai_scan_threads_session ON ai_scan_threads(session_id)`,

  // ── PROVEEDOR "CUSTOM" (modelos locales — Ollama, LM Studio, vLLM, etc.) ──
  // Configurado por env vars a nivel de quien hostea Flowdit (CUSTOM_API_URL/
  // CUSTOM_API_KEY/CUSTOM_MODEL, ver backend/src/services/ai/custom.js), NO
  // por proyecto — un base_url elegible desde la UI sería SSRF. Ver
  // AI_PENTEST_AGENT.md § Multi-proveedor.
  // (mismo motivo que arriba — DROP+ADD movido a la versión final del constraint)

  // ── MODO DE TOOL-CALLING (fallback en texto plano) ──────────────────────
  // 'native' (default) = tools/tool_calls estructurados, lo que ya usan
  // groq/anthropic/deepseek y la mayoría de modelos locales modernos.
  // 'text' = fallback ACTION: tool(args) parseado a mano, para modelos
  // locales débiles que no soportan tool-calling nativo de forma confiable
  // (solo lo consume el proveedor 'custom' — ver openaiCompatible.js).
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ai_tool_mode VARCHAR(10) NOT NULL DEFAULT 'native' CHECK (ai_tool_mode IN ('native','text'))`,

  // ── GATE DE NIVEL 2/3 OPCIONAL — "MODO SIN RESTRICCIONES" ────────────────
  // Por defecto (false), send_http_request/test_payload/run_exploit_poc
  // (Nivel 2) y propose_finding (Nivel 3) siguen requiriendo aprobación
  // explícita, igual que siempre. En true, corren solas, igual que Nivel 1
  // — pedido explícito del usuario ("chipe libre absoluto en todo"). Ver
  // agentLoop.js needsGate() y AI_PENTEST_AGENT.md § Superficie de tools.
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ai_autonomous_requests BOOLEAN NOT NULL DEFAULT false`,

  // "Un agente a la vez" — oculta delegate_to_subagent del coordinador
  // (agentLoop.js advance()), así nunca hay más de un thread `running` en
  // toda la sesión. Pedido explícito tras encontrar en vivo que Kimi K3 en
  // tier gratuito tiene Concurrency: 1 — con sub-agentes en paralelo eso
  // rompe sin importar el RPM. También sirve en general para no quemar
  // tokens tan rápido, más allá de rate limits bajos.
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS ai_single_agent BOOLEAN NOT NULL DEFAULT false`,

  // ── CONFIG DE IA POR SESIÓN — pisa la del proyecto, no al revés ─────────
  // Mismo patrón que ai_scan_sessions.response_language (se fija UNA vez al
  // arrancar, no se reconfigura a mitad de sesión). NULL = "usá lo del
  // proyecto" — cubre sesiones viejas creadas antes de esta migración sin
  // necesidad de backfill. Pedido explícito: poder tener sesiones con
  // proveedores/configs distintas conviviendo en el mismo proyecto (ej. una
  // en Kimi con rate limit bajo, otra en Claude sin restricciones). Ver el
  // merge `effective` en agentLoop.js advance().
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS ai_provider VARCHAR(20)`,
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS ai_model VARCHAR(50)`,
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS ai_tool_mode VARCHAR(10)`,
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS ai_autonomous_requests BOOLEAN`,
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS ai_single_agent BOOLEAN`,

  // ── ORIGEN DEL HALLAZGO — ¿lo propuso la IA? ─────────────────────────────
  // custom_vulns.created_by siempre es un usuario real (el que aprobó, o
  // quien arrancó la sesión en modo autónomo) — nunca hubo forma de saber,
  // mirando la tabla, si un hallazgo salió de propose_finding o lo escribió
  // un humano a mano. Pedido explícito: "que se complemente mejor con el
  // ecosistema" — la vista de Findings puede marcarlo visualmente con esto.
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS ai_generated BOOLEAN NOT NULL DEFAULT false`,

  // ── IDIOMA DE RESPUESTA DEL AGENTE (ES/EN) ───────────────────────────────
  // Pedido explícito: toggle de idioma en la página del AI Agent (acotado a
  // esa página, no toda la app — decisión explícita del usuario). Se fija UNA
  // vez, al arrancar la sesión (lo que el toggle del frontend valía en ese
  // momento — ver ai-agent.js scanStartSession()), no es reconfigurable a
  // mitad de sesión: cambiaría el idioma de un historial ya en curso.
  // Consumido por buildSystemPrompt() en agentLoop.js.
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS response_language VARCHAR(2) NOT NULL DEFAULT 'es' CHECK (response_language IN ('es','en'))`,

  // NULL = todavía sin nombre — auto-nombrada desde el primer mensaje
  // (deriveSessionName en agentLoop.js) o puesta a mano vía PATCH
  // /sessions/:id (ai-scan.js); el frontend cae al label de fecha si es NULL.
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS name VARCHAR(200)`,

  // ── COSTO Y HALLAZGOS POR SESIÓN ──────────────────────────────────────
  // Van al final del array (no junto a las definiciones originales de
  // ai_usage/custom_vulns más arriba) porque referencian ai_scan_sessions,
  // que recién existe más abajo en este mismo archivo — las migraciones
  // corren en orden. ON DELETE SET NULL, no CASCADE: borrar una sesión de
  // scan no debe borrarse el gasto ya incurrido ni los hallazgos ya
  // creados, son artefactos reales del proyecto — solo pierden el vínculo
  // con la sesión que los originó (mismo espíritu que custom_vulns.target_id).
  `ALTER TABLE ai_usage ADD COLUMN IF NOT EXISTS session_id UUID REFERENCES ai_scan_sessions(id) ON DELETE SET NULL`,
  `CREATE INDEX IF NOT EXISTS idx_ai_usage_session ON ai_usage(session_id)`,
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS session_id UUID REFERENCES ai_scan_sessions(id) ON DELETE SET NULL`,
  `CREATE INDEX IF NOT EXISTS idx_custom_vulns_session ON custom_vulns(session_id)`,

  // ── PERFIL DE SESIÓN — qué tipo de engagement es ─────────────────────
  // Pedido explícito: poder configurar una sesión para un CTF o un laboratorio
  // tipo HTB/THM, no solo un pentest de cliente real — cambia el enfoque que
  // buildSystemPrompt() le da al agente (ver agentLoop.js), no solo el
  // proveedor de IA. Nullable, sin CHECK — mismo criterio que ai_tool_mode acá
  // arriba: es un override de sesión, se valida en la ruta (ai-scan.js), no en
  // la DB. NULL = 'pentest' (comportamiento actual, sin cambios).
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS ai_profile VARCHAR(20)`,

  // ── TOPE DE GASTO REAL POR SESIÓN (en $) ─────────────────────────────
  // Pedido del ROADMAP: el único freno que existía era de ITERACIONES
  // (MAX_ITERATIONS_PER_TURN en agentLoop.js), no de costo — 400 tool calls
  // con un modelo caro puede seguir siendo mucha plata. NULL = sin tope
  // (comportamiento actual). Se compara contra SUM(ai_usage.cost_usd) por
  // session_id — ver el chequeo en advance() (agentLoop.js).
  `ALTER TABLE ai_scan_sessions ADD COLUMN IF NOT EXISTS ai_max_cost_usd NUMERIC(10,4)`,

  // ── projects_ai_provider_check — ÚNICA versión vigente del constraint ──
  // Bug real encontrado en vivo: este constraint se fue actualizando con
  // pares DROP+ADD nuevos cada vez que se sumaba un proveedor (deepseek,
  // luego custom, ahora kimi) — pero migrate.js re-corre TODO el array en
  // cada arranque, no solo lo nuevo. Con un proyecto real ya usando
  // ai_provider='kimi', reiniciar el backend volvía a aplicar la versión
  // VIEJA del constraint (sin 'kimi') antes de llegar a esta, y esa fila ya
  // no encajaba — la migración fallaba y el backend no arrancaba más. Por
  // eso ahora hay un solo DROP+ADD para este constraint, acá, con la lista
  // completa vigente — si se suma un proveedor nuevo a futuro, se EDITA
  // esta lista en el lugar, no se agrega un par nuevo.
  `ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_ai_provider_check`,
  `ALTER TABLE projects ADD CONSTRAINT projects_ai_provider_check CHECK (ai_provider IN ('groq','anthropic','deepseek','custom','kimi'))`,

  // ── Report builder persistence ────────────────────────────────────────
  // The export page used to keep the whole report configuration in the
  // browser's localStorage: cover metadata, section list, and — critically —
  // the per-finding editorial data (risk-matrix probability, remediation
  // priority, business impact, executive action, rewritten description and
  // remediation). That meant a different browser, a cleared profile or a
  // fresh machine silently lost work the user had already done. The report
  // is a project artifact, so it lives with the project, shared by every
  // member exactly like whiteboard_state.
  `CREATE TABLE IF NOT EXISTS report_config (
    project_id UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  // updated_by is an audit stamp, not ownership: deleting the account that
  // last touched the report must not be blocked by it, and must not take the
  // report down with it either. Re-applied here so installs created before
  // this line get the same behavior.
  `ALTER TABLE report_config DROP CONSTRAINT IF EXISTS report_config_updated_by_fkey`,
  `ALTER TABLE report_config ADD CONSTRAINT report_config_updated_by_fkey
     FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL`,

  // Saved report templates (cover metadata + section layout) belong to the
  // user, not to a project — that is the whole point of a template: reuse it
  // on the next engagement.
  `CREATE TABLE IF NOT EXISTS report_templates (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       VARCHAR(200) NOT NULL,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  `CREATE INDEX IF NOT EXISTS idx_report_templates_user ON report_templates(created_by, created_at DESC)`,

  // ── DEEPSEEK — migrar proyectos/sesiones de los modelos retirados ────
  // deepseek.js cambió DEFAULT_MODEL de 'deepseek-chat' a 'deepseek-flash'
  // (retirados por DeepSeek el 2026-07-24), pero ese default de CÓDIGO
  // nunca se aplica a una fila que ya tiene ai_model seteado explícitamente
  // (no NULL) — cualquier proyecto/sesión que eligió "DeepSeek Chat (V3)" o
  // "DeepSeek Reasoner (R1)" antes de este cambio queda apuntando para
  // siempre a un modelo que la API de DeepSeek ya rechaza. Reescrito acá a
  // los equivalentes vigentes: deepseek-chat -> deepseek-flash (chat plano),
  // deepseek-reasoner -> deepseek-v4-pro (con razonamiento).
  `UPDATE projects SET ai_model='deepseek-flash' WHERE ai_provider='deepseek' AND ai_model='deepseek-chat'`,
  `UPDATE projects SET ai_model='deepseek-v4-pro' WHERE ai_provider='deepseek' AND ai_model='deepseek-reasoner'`,
  `UPDATE ai_scan_sessions SET ai_model='deepseek-flash' WHERE ai_provider='deepseek' AND ai_model='deepseek-chat'`,
  `UPDATE ai_scan_sessions SET ai_model='deepseek-v4-pro' WHERE ai_provider='deepseek' AND ai_model='deepseek-reasoner'`,

  // ── PROJECT TASKS (internal work assignment) ───────────────────────────
  // A lead assigns work to a team member; the "instructions" are the task's
  // description + its comment thread (no separate entity). Internal only:
  // never exposed to client-portal sessions. CHECK constraints are declared
  // with explicit names via DROP + ADD (not inline) so the value lists can
  // change later without leaving a stale copy behind.
  `CREATE TABLE IF NOT EXISTS project_tasks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title        VARCHAR(300) NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    status       VARCHAR(20) NOT NULL DEFAULT 'pending',
    priority     VARCHAR(10) NOT NULL DEFAULT 'medium',
    assignee_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    due_date     DATE,
    target_id    UUID REFERENCES targets(id) ON DELETE SET NULL,
    vuln_id      UUID REFERENCES custom_vulns(id) ON DELETE SET NULL,
    wstg_test_id VARCHAR(50),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
  )`,
  `ALTER TABLE project_tasks DROP CONSTRAINT IF EXISTS project_tasks_status_check`,
  `ALTER TABLE project_tasks ADD CONSTRAINT project_tasks_status_check
     CHECK (status IN ('pending','in_progress','done'))`,
  `ALTER TABLE project_tasks DROP CONSTRAINT IF EXISTS project_tasks_priority_check`,
  `ALTER TABLE project_tasks ADD CONSTRAINT project_tasks_priority_check
     CHECK (priority IN ('low','medium','high'))`,
  `CREATE INDEX IF NOT EXISTS idx_project_tasks_project  ON project_tasks(project_id, status)`,
  `CREATE INDEX IF NOT EXISTS idx_project_tasks_assignee ON project_tasks(assignee_id, status)`,

  `CREATE TABLE IF NOT EXISTS task_comments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id    UUID NOT NULL REFERENCES project_tasks(id) ON DELETE CASCADE,
    user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_task_comments_task ON task_comments(task_id, created_at)`,

  // ── NOTIFICATIONS (per-user inbox) ─────────────────────────────────────
  // Deliberately generic: `type` + (entity_type, entity_id) + free-form
  // `payload`, so future event kinds (client queries, AI approvals, ...) plug
  // in without a schema change. entity_id is text, not UUID, for the same
  // reason (some entities — e.g. WSTG tests — are keyed by a string id).
  `CREATE TABLE IF NOT EXISTS notifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id  UUID REFERENCES projects(id) ON DELETE CASCADE,
    type        VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50),
    entity_id   VARCHAR(100),
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    read_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,
  `CREATE INDEX IF NOT EXISTS idx_notifications_inbox ON notifications(user_id, read_at, created_at DESC)`,

  // ── USER DISPLAY NAME ──────────────────────────────────────────────────
  // Cosmetic, free-text name shown wherever a person is rendered. Separate
  // from `username`, which stays the unique login identifier with its strict
  // charset. Nullable and not unique: the UI falls back to username.
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(50)`,

  // ── PER-CONTACT CLIENT PORTAL LINKS ────────────────────────────────────
  // One revocable, optionally expiring link per client contact, replacing the
  // single shared projects.portal_token (kept as a column, no longer used for
  // auth; backfilled into a legacy row by services/portalLinks.js). Lookup is
  // by token_hash (SHA-256 hex); token_enc is AES-256-GCM (utils/crypto.js)
  // so the owner can re-copy the link and reply emails can include it.
  `CREATE TABLE IF NOT EXISTS portal_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    label        VARCHAR(200) NOT NULL,
    email        VARCHAR(320),
    token_hash   CHAR(64) UNIQUE NOT NULL,
    token_enc    TEXT NOT NULL,
    is_legacy    BOOLEAN NOT NULL DEFAULT false,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    use_count    INT NOT NULL DEFAULT 0
  )`,
  `CREATE INDEX IF NOT EXISTS idx_portal_links_project ON portal_links(project_id)`,
  // At most one legacy row per project, so the backfill can never duplicate it.
  `CREATE UNIQUE INDEX IF NOT EXISTS uq_portal_links_legacy ON portal_links(project_id) WHERE is_legacy`,
  // Which contact's link opened a portal ticket. The FK is declared by name
  // via DROP + ADD, not inline: an inline REFERENCES on ADD COLUMN IF NOT
  // EXISTS adds a new numbered copy of the constraint on every run (same
  // problem as inline CHECKs, see the cleanup block at the end).
  `ALTER TABLE tickets ADD COLUMN IF NOT EXISTS portal_link_id UUID`,
  `ALTER TABLE tickets DROP CONSTRAINT IF EXISTS tickets_portal_link_id_fkey`,
  `ALTER TABLE tickets ADD CONSTRAINT tickets_portal_link_id_fkey
     FOREIGN KEY (portal_link_id) REFERENCES portal_links(id) ON DELETE SET NULL`,

  // ── target_endpoints: un endpoint por (target, path, method) ─────────────
  // Sin índice único, recordEndpoint (scanToolsLevel1.js) deduplicaba con
  // SELECT-y-después-INSERT, que con sub-agentes en paralelo duplicaba filas,
  // y paths como `/api//x/` vs `/api/x` contaban como distintos. Antes de
  // crear el índice se normalizan los paths existentes con la MISMA regla que
  // normalizeEndpointPath() (sin query/fragmento, `/` inicial, `//` → `/`,
  // sin `/` final salvo la raíz; sin tocar mayúsculas) y se fusionan los
  // duplicados: queda la fila más vieja, con interesting = OR de todas, las
  // notas distintas unidas y el created_at más temprano. Todo en un solo DO
  // (una transacción) y solo mientras el índice no existe: idempotente.
  `DO $$
    BEGIN
      IF to_regclass('public.uq_target_endpoints_target_path_method') IS NOT NULL THEN RETURN; END IF;

      CREATE TEMP TABLE _ep_norm ON COMMIT DROP AS
        SELECT e.id, e.target_id, e.method, e.created_at, e.interesting, e.notes, s3.npath,
               ROW_NUMBER() OVER (PARTITION BY e.target_id, s3.npath, e.method ORDER BY e.created_at, e.id) AS rn
        FROM target_endpoints e
        CROSS JOIN LATERAL (SELECT split_part(split_part(e.path, '#', 1), '?', 1) AS b) s1
        CROSS JOIN LATERAL (SELECT regexp_replace(CASE WHEN left(s1.b, 1) = '/' THEN s1.b ELSE '/' || s1.b END, '/{2,}', '/', 'g') AS c) s2
        CROSS JOIN LATERAL (SELECT CASE WHEN length(s2.c) > 1 THEN regexp_replace(s2.c, '/$', '') ELSE s2.c END AS npath) s3;

      UPDATE target_endpoints e
      SET interesting = a.interesting, notes = a.notes, created_at = a.created_at
      FROM _ep_norm k
      JOIN (
        SELECT target_id, npath, method,
               bool_or(interesting) AS interesting,
               MIN(created_at) AS created_at,
               string_agg(DISTINCT notes, E'\\n') FILTER (WHERE notes IS NOT NULL AND btrim(notes) <> '') AS notes,
               COUNT(*) AS cnt
        FROM _ep_norm GROUP BY target_id, npath, method
      ) a ON a.target_id = k.target_id AND a.npath = k.npath AND a.method = k.method
      WHERE e.id = k.id AND k.rn = 1 AND a.cnt > 1;

      DELETE FROM target_endpoints e USING _ep_norm k WHERE e.id = k.id AND k.rn > 1;

      UPDATE target_endpoints e SET path = k.npath FROM _ep_norm k WHERE e.id = k.id AND e.path <> k.npath;

      CREATE UNIQUE INDEX uq_target_endpoints_target_path_method ON target_endpoints(target_id, path, method);
    END $$`,

  // ── Integración con Claude Code (servidor MCP en /mcp) ──────────────────
  // Tokens personales para que Claude Code del pentester lea el proyecto y
  // proponga hallazgos/notas. Solo se guarda el SHA-256 (lookup) y un prefijo
  // para mostrar en la UI: el token en claro se ve una sola vez al crearlo.
  // Estos tokens autentican ÚNICAMENTE /mcp, nunca las rutas /api (ver
  // middleware/apiToken.js).
  `CREATE TABLE IF NOT EXISTS api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         VARCHAR(100) NOT NULL,
    token_prefix VARCHAR(16) NOT NULL,
    token_hash   CHAR(64) UNIQUE NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'read' CHECK (scopes IN ('read','read_propose')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
  )`,
  `CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id)`,
  // Opt-in por proyecto: los datos del cliente salen por el Claude Code del
  // usuario (y de ahí al proveedor del modelo), algo que el NDA del
  // engagement puede no permitir. Apagado = el proyecto no existe para MCP.
  `ALTER TABLE projects ADD COLUMN IF NOT EXISTS claude_code_enabled BOOLEAN NOT NULL DEFAULT false`,
  // De dónde salió el hallazgo ('manual', 'ai_agent', 'claude_code'...). Sin
  // backfill: NULL = creado antes de que existiera la columna.
  `ALTER TABLE custom_vulns ADD COLUMN IF NOT EXISTS origin TEXT`,
  // Propuestas de Claude Code pendientes de revisión humana. Tabla APARTE a
  // propósito, no un estado "borrador" en custom_vulns: reportes, portal,
  // exports y contadores leen custom_vulns, y un borrador ahí terminaría
  // filtrándose en alguno. Una propuesta recién se vuelve hallazgo (o nota)
  // cuando un writer la aprueba (services/mcp/proposals.js).
  `CREATE TABLE IF NOT EXISTS mcp_proposals (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id        UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL CHECK (kind IN ('finding','note')),
    payload           JSONB NOT NULL,
    target_id         UUID REFERENCES targets(id) ON DELETE SET NULL,
    entity_type       TEXT CHECK (entity_type IN ('target','port','endpoint','finding')),
    entity_id         UUID,
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    proposed_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    token_id          UUID REFERENCES api_tokens(id) ON DELETE SET NULL,
    reviewed_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resulting_vuln_id UUID REFERENCES custom_vulns(id) ON DELETE SET NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_mcp_proposals_project_status ON mcp_proposals(project_id, status)`,
  `CREATE INDEX IF NOT EXISTS idx_mcp_proposals_proposed_by ON mcp_proposals(proposed_by)`,
  // + 'withdrawn': quien propuso puede retirar su propuesta pendiente
  // (withdraw_proposal). Nunca se borra la fila, queda para auditoría. Mismo
  // patrón DROP + ADD con nombre explícito que el CHECK de roles: el CREATE
  // TABLE de arriba crea el inline con este mismo nombre autogenerado, así
  // que esto lo reemplaza tanto en bases nuevas como existentes.
  `ALTER TABLE mcp_proposals DROP CONSTRAINT IF EXISTS mcp_proposals_status_check`,
  `ALTER TABLE mcp_proposals ADD CONSTRAINT mcp_proposals_status_check
     CHECK (status IN ('pending','approved','rejected','withdrawn'))`,
  // Última edición (update_proposal) o retiro: el inbox muestra la versión
  // vigente y conviene saber que cambió después de proponerse.
  `ALTER TABLE mcp_proposals ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ`,
  // Capturas subidas por Claude Code (POST /mcp/uploads) para adjuntar a una
  // propuesta de hallazgo. Van por fuera de las tools porque el modelo no
  // puede transcribir los bytes de un archivo a un argumento. Sin vincular
  // vencen a las 24 h (limpieza oportunista en cada subida, sin cron). Al
  // vincularse a una propuesta quedan con ella (auditoría) y se borran si se
  // borra la propuesta. Al aprobarla se COPIAN a custom_vulns.evidence.
  `CREATE TABLE IF NOT EXISTS mcp_uploads (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_id            UUID REFERENCES api_tokens(id) ON DELETE SET NULL,
    mime                TEXT NOT NULL,
    name                VARCHAR(120) NOT NULL,
    size                INTEGER NOT NULL,
    data                BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_by_proposal_id UUID REFERENCES mcp_proposals(id) ON DELETE CASCADE
  )`,
  // Sin CHECK inline en mime a propósito (ver la limpieza de abajo): nombre
  // explícito para poder cambiar la lista sin dejar copias viejas.
  `ALTER TABLE mcp_uploads DROP CONSTRAINT IF EXISTS mcp_uploads_mime_check`,
  `ALTER TABLE mcp_uploads ADD CONSTRAINT mcp_uploads_mime_check
     CHECK (mime IN ('image/png','image/jpeg','image/webp'))`,
  `CREATE INDEX IF NOT EXISTS idx_mcp_uploads_user_unused ON mcp_uploads(user_id, created_at) WHERE used_by_proposal_id IS NULL`,
  `CREATE INDEX IF NOT EXISTS idx_mcp_uploads_proposal ON mcp_uploads(used_by_proposal_id)`,

  // ── Limpieza de CHECK constraints anónimos duplicados ──────────────────
  // Va ÚLTIMO a propósito. `ALTER TABLE ... ADD COLUMN IF NOT EXISTS x ... CHECK (...)`
  // no es idempotente para el constraint: saltea la columna pero agrega el
  // CHECK inline igual, con un nombre autogenerado nuevo (_check1, _check2...).
  // Como migrate.js re-corre TODO el array en cada arranque, esos se acumulan.
  // Mientras la lista del CHECK no cambie son solo ruido; cuando cambia (pasó
  // con ai_provider al sumar deepseek/custom/kimi) la copia vieja bloquea los
  // valores nuevos y la escritura falla con 500.
  //
  // Los constraints vigentes son los de nombre explícito, SIN sufijo numérico.
  // Esto borra únicamente las copias numeradas, así el estado converge sin
  // importar cuántas veces se haya corrido la migración.
  `DO $$
    DECLARE c record;
    BEGIN
      FOR c IN
        SELECT rel.relname AS tbl, con.conname AS name
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        JOIN pg_namespace ns ON ns.oid = rel.relnamespace
        WHERE ns.nspname = 'public'
          AND con.contype = 'c'
          AND con.conname ~ '_check[0-9]+$'
      LOOP
        EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I', c.tbl, c.name);
      END LOOP;
    END $$`,
];


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
  await backfillLegacyPortalLinks(db);
  console.log('✅ Migrations complete');
  process.exit(0);
}

migrate();