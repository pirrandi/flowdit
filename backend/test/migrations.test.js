// Regression cover for a bug that only ever appeared on the SECOND migration
// run, which is exactly why nothing caught it: CI creates a fresh database and
// runs `npm run migrate` once, and every other test here runs against an
// already-migrated database.
//
// The bug: `ALTER TABLE ... ADD COLUMN IF NOT EXISTS x ... CHECK (...)` is not
// idempotent for the constraint. When the column already exists Postgres skips
// the COLUMN but still adds the inline CHECK as a brand new anonymous
// constraint, auto-named with an incrementing suffix (_check1, _check2, ...).
// Since migrate.js replays the whole array on every run, those pile up — each
// one frozen with whatever the value list was at the time. Postgres ANDs every
// CHECK together, so the most restrictive copy wins and any value added later
// (ai_provider='deepseek') starts failing with a 500.
//
// These tests run the real migration runner twice, as a subprocess, because
// migrate.js self-executes on require and ends with process.exit().
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { db } = require('./helpers');
const { PROVIDERS } = require('../src/services/ai');

const MIGRATE = path.join(__dirname, '..', 'src', 'db', 'migrate.js');

function runMigrate() {
  execFileSync(process.execPath, [MIGRATE], {
    env: { ...process.env, DB_NAME: process.env.DB_NAME },
    stdio: 'pipe',
  });
}

// Twice, deliberately. Once proves nothing — run 1 is the case that always
// worked, and it is the only case CI exercises.
before(() => { runMigrate(); runMigrate(); });
after(async () => { await db.pool.end(); });

test('re-running migrations leaves no duplicate anonymous CHECK constraints', async () => {
  const { rows } = await db.query(`
    SELECT rel.relname AS tbl, con.conname AS name
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
    JOIN pg_namespace ns ON ns.oid = rel.relnamespace
    WHERE ns.nspname = 'public' AND con.contype = 'c'
      AND con.conname ~ '_check[0-9]+$'
    ORDER BY 1, 2
  `);
  assert.deepEqual(
    rows, [],
    'Numbered CHECK constraints accumulated across migration runs. These are ' +
    'stale copies of an earlier value list and will silently reject values ' +
    'added later. Do not put an inline CHECK on ADD COLUMN IF NOT EXISTS — ' +
    'declare the constraint once with an explicit name via DROP+ADD.\nFound: ' +
    rows.map(r => `${r.tbl}.${r.name}`).join(', ')
  );
});

test('ai_provider accepts exactly the providers the code registers', async () => {
  const { rows: [owner] } = await db.query(
    `INSERT INTO users (username, email, password)
     VALUES ($1, $2, 'x') RETURNING id`,
    [`migtest${Date.now()}`, `migtest${Date.now()}@example.com`]
  );

  try {
    for (const provider of PROVIDERS) {
      await assert.doesNotReject(
        db.query(
          `INSERT INTO projects (name, owner_id, ai_provider) VALUES ('m', $1, $2)`,
          [owner.id, provider]
        ),
        `ai_provider='${provider}' is registered in src/services/ai but rejected ` +
        `by the database. The CHECK constraint and PROVIDERS have drifted apart.`
      );
    }

    // The constraint must still constrain — a fix that simply dropped it would
    // pass the assertions above.
    await assert.rejects(
      db.query(
        `INSERT INTO projects (name, owner_id, ai_provider) VALUES ('m', $1, 'nope')`,
        [owner.id]
      ),
      /violates check constraint/,
      'An unknown ai_provider was accepted — the CHECK constraint is missing.'
    );
  } finally {
    await db.query('DELETE FROM users WHERE id = $1', [owner.id]);
  }
});
