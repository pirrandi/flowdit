require('dotenv').config();
const db = require('./index');

const migrations = [

  `CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
  // ── USERS ──────────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(50)  UNIQUE NOT NULL,
    email       VARCHAR(255) UNIQUE NOT NULL,
    password    VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,

  // ── REFRESH TOKENS ─────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token       VARCHAR(512) UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  // ── PROJECTS (engagements) ─────────────────────────────────────────
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

  // ── PROJECT MEMBERS (collaboration) ────────────────────────────────
  `CREATE TABLE IF NOT EXISTS project_members (
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    role        VARCHAR(20) NOT NULL DEFAULT 'member'
                  CHECK (role IN ('owner','editor','viewer')),
    invited_by  UUID REFERENCES users(id),
    joined_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, user_id)
  )`,

  // ── INVITES ────────────────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS project_invites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    invited_by  UUID NOT NULL REFERENCES users(id),
    email       VARCHAR(255) NOT NULL,
    role        VARCHAR(20)  NOT NULL DEFAULT 'editor',
    token       VARCHAR(128) UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
  )`,

  // ── WSTG PROGRESS ──────────────────────────────────────────────────
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

  // ── WSTG ITEM CHECKS ───────────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS wstg_item_checks (
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    test_id     VARCHAR(50) NOT NULL,
    item_idx    INTEGER NOT NULL,
    checked     BOOLEAN NOT NULL DEFAULT false,
    updated_by  UUID REFERENCES users(id),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, test_id, item_idx)
  )`,

  // ── PORTSWIGGER PROGRESS ───────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS ps_progress (
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    cat_id      VARCHAR(20) NOT NULL,
    lab_idx     INTEGER NOT NULL,
    done        BOOLEAN NOT NULL DEFAULT false,
    updated_by  UUID REFERENCES users(id),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (project_id, cat_id, lab_idx)
  )`,

  // ── CUSTOM VULNERABILITIES ─────────────────────────────────────────
  `CREATE TABLE IF NOT EXISTS custom_vulns (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        VARCHAR(300) NOT NULL,
    category    VARCHAR(100) NOT NULL DEFAULT 'Custom',
    items       JSONB NOT NULL DEFAULT '[]',
    payloads    JSONB NOT NULL DEFAULT '[]',
    notes       TEXT,
    status      VARCHAR(10) CHECK (status IN ('done','fail',null)),
    checked_items JSONB NOT NULL DEFAULT '{}',
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`,

  // ── INDEXES ────────────────────────────────────────────────────────
  `CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_wstg_progress_project ON wstg_progress(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_ps_progress_project ON ps_progress(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_custom_vulns_project ON custom_vulns(project_id)`,
  `CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)`,

  // ── updated_at trigger function ─────────────────────────────────────
  `CREATE OR REPLACE FUNCTION update_updated_at()
   RETURNS TRIGGER AS $$
   BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
   $$ LANGUAGE plpgsql`,

  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_users_updated_at') THEN
      CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_projects_updated_at') THEN
      CREATE TRIGGER trg_projects_updated_at BEFORE UPDATE ON projects
        FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_custom_vulns_updated_at') THEN
      CREATE TRIGGER trg_custom_vulns_updated_at BEFORE UPDATE ON custom_vulns
        FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
  END $$`,
];

async function migrate() {
  console.log('🔄 Running migrations...');
  for (const sql of migrations) {
    try {
      await db.query(sql);
    } catch (err) {
      console.error('Migration failed:\n', sql.slice(0, 80), '\n', err.message);
      process.exit(1);
    }
  }
  console.log('✅ Migrations complete');
  process.exit(0);
}

migrate();
