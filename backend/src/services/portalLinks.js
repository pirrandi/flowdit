// Per-contact client portal links. Each link is a bearer token handed to ONE
// client contact; the database only keeps its SHA-256 (for lookup) and an
// AES-256-GCM copy (utils/crypto.js) so the owner can re-copy it and reply
// emails can include it. The plaintext never sits in a column.
const crypto = require('crypto');
const { encrypt, decrypt } = require('../utils/crypto');

const LEGACY_LABEL = 'Shared link (legacy)';

function generateToken() {
  return crypto.randomBytes(24).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

// Decrypted token, or null when it can't be decrypted (key missing/rotated,
// corrupted value). Never throws: a broken row must not take down the list
// or a reply email.
function tokenOf(link) {
  if (!link?.token_enc) return null;
  try { return decrypt(link.token_enc); } catch { return null; }
}

function portalUrl(token) {
  return token ? `${process.env.FRONTEND_URL || ''}/client-login#token=${token}` : null;
}

// SQL fragment shared by every query that needs a link's state, so "active"
// means the same thing (evaluated against the DB clock) everywhere.
const STATUS_SQL = `CASE WHEN pl.revoked_at IS NOT NULL THEN 'revoked'
                         WHEN pl.expires_at IS NOT NULL AND pl.expires_at <= NOW() THEN 'expired'
                         ELSE 'active' END`;
const ACTIVE_SQL = `(pl.revoked_at IS NULL AND (pl.expires_at IS NULL OR pl.expires_at > NOW()))`;

// One-time, re-runnable backfill: every project that still has the old shared
// projects.portal_token gets a legacy portal_links row carrying that same
// token, so links already sent to clients keep working. Skips projects that
// already have a legacy row (including a revoked one — revocation sticks).
// Needs SSO_ENCRYPTION_KEY for token_enc; without it the backfill is skipped
// with a warning and retried on the next migration run.
async function backfillLegacyPortalLinks(db) {
  const { rows } = await db.query(
    `SELECT p.id, p.portal_token FROM projects p
     WHERE p.portal_token IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM portal_links pl WHERE pl.project_id = p.id AND pl.is_legacy)`
  );
  if (!rows.length) return 0;
  if (!process.env.SSO_ENCRYPTION_KEY) {
    console.warn(`  ⚠ ${rows.length} legacy client portal link(s) not migrated: SSO_ENCRYPTION_KEY is not configured. ` +
      'Those links stop working until the key is set and migrations run again.');
    return 0;
  }
  let created = 0;
  for (const { id, portal_token } of rows) {
    const { rowCount } = await db.query(
      `INSERT INTO portal_links (project_id, label, token_hash, token_enc, is_legacy)
       VALUES ($1,$2,$3,$4,true)
       ON CONFLICT DO NOTHING`,
      [id, LEGACY_LABEL, hashToken(portal_token), encrypt(portal_token)]
    );
    created += rowCount;
  }
  if (created > 0) console.log(`  ✦ Backfilled ${created} legacy client portal link(s)`);
  return created;
}

module.exports = {
  LEGACY_LABEL, generateToken, hashToken, tokenOf, portalUrl,
  STATUS_SQL, ACTIVE_SQL, backfillLegacyPortalLinks,
};
