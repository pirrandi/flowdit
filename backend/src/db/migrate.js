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
];

async function migrate() {
  console.log('🔄 Running migrations...');
  for (const sql of migrations) {
    try { await db.query(sql); }
    catch (err) {
      console.error('Migration failed:', sql.slice(0,80), '\n', err.message);
      process.exit(1);
    }
  }
  console.log('✅ Migrations complete');
  process.exit(0);
}

migrate();