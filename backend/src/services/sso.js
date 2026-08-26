const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../db');

// ── In-process ephemeral stores ──────────────────────────────────────
// Single PM2 fork-mode process (confirmed for this deployment), so a plain
// Map is fine — no Redis/shared-state concern. Two separate stores because
// they have very different lifetimes: the PKCE/nonce flow state has to
// survive the user's whole trip through Microsoft's login screen (~10 min),
// while the post-callback exchange code only needs to survive one redirect
// hop (~60s) before the frontend trades it for real tokens.
const ssoFlowStore     = new Map(); // state -> { codeVerifier, nonce, orgId, expiresAt }
const ssoExchangeStore = new Map(); // code  -> { accessToken, refreshToken, user, expiresAt }
const discoveryCache   = new Map(); // orgId -> { config, expiresAt }

const FLOW_TTL_MS      = 10 * 60 * 1000;
const EXCHANGE_TTL_MS  = 60 * 1000;
const DISCOVERY_TTL_MS = 60 * 60 * 1000;

function _sweep(map) {
  const now = Date.now();
  for (const [k, v] of map) if (v.expiresAt < now) map.delete(k);
}
// Reclaim entries from abandoned flows (user closes the Microsoft login tab,
// callback never arrives) so the Map can't grow unbounded.
setInterval(() => { _sweep(ssoFlowStore); _sweep(ssoExchangeStore); }, 5 * 60 * 1000).unref();

function saveFlow(state, data) {
  ssoFlowStore.set(state, { ...data, expiresAt: Date.now() + FLOW_TTL_MS });
}
function takeFlow(state) {
  const v = ssoFlowStore.get(state);
  ssoFlowStore.delete(state);
  if (!v || v.expiresAt < Date.now()) return null;
  return v;
}

function saveExchange(code, data) {
  ssoExchangeStore.set(code, { ...data, expiresAt: Date.now() + EXCHANGE_TTL_MS });
}
function takeExchange(code) {
  const v = ssoExchangeStore.get(code);
  ssoExchangeStore.delete(code);
  if (!v || v.expiresAt < Date.now()) return null;
  return v;
}

function invalidateDiscovery(orgId) {
  discoveryCache.delete(orgId);
}

// openid-client v6 is pure ESM — dynamic import() from this CJS file works
// regardless of the host Node version (unlike require(), which cannot load ESM).
async function getOidcConfig(orgId, issuerUrl, clientId, clientSecret) {
  const cached = discoveryCache.get(orgId);
  if (cached && cached.expiresAt > Date.now()) return cached.config;
  const { discovery } = await import('openid-client');
  const config = await discovery(new URL(issuerUrl), clientId, clientSecret);
  discoveryCache.set(orgId, { config, expiresAt: Date.now() + DISCOVERY_TTL_MS });
  return config;
}

const AVATAR_COLORS = ['#7c3aed','#2563eb','#059669','#dc2626','#d97706','#0891b2','#7c3aed','#be185d'];

// Pure w.r.t. network calls — only touches the DB, given already-validated
// claims. Kept separate from the openid-client/network code specifically so
// it's testable with a hand-crafted claims object.
//
// Trust boundary is domain match, not `email_verified` — Entra ID doesn't
// reliably emit that claim. The real check is "does this org's owner-
// configured domain match the email Microsoft asserts," since the org owner
// configuring client_id/tenant for that domain *is* the admin-asserted trust.
async function provisionSsoUser(claims, org) {
  const email = String(claims.email || claims.preferred_username || '').toLowerCase().trim();
  if (!email.includes('@')) throw new Error('SSO identity has no usable email claim');
  const domain = email.split('@')[1];
  if (domain !== org.email_domain)
    throw new Error(`Email domain "${domain}" does not match this organization's configured domain`);

  const { rows } = await db.query('SELECT * FROM users WHERE email=$1', [email]);
  let user = rows[0];

  if (!user) {
    const base = String(claims.name || email.split('@')[0])
      .toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 45) || 'user';
    const seed = base.length >= 2 ? base : base.padEnd(2, '0');
    let candidate = seed, n = 0;
    // resolve username collisions deterministically
    while ((await db.query('SELECT 1 FROM users WHERE username=$1', [candidate])).rows.length) {
      n++; candidate = `${seed}${n}`.slice(0, 50);
    }
    const unusablePassword = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
    const color = AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];
    const insert = await db.query(
      `INSERT INTO users (username, email, password, avatar_color) VALUES ($1,$2,$3,$4) RETURNING *`,
      [candidate, email, unusablePassword, color]
    );
    user = insert.rows[0];
  }

  const isMember = await db.query(
    'SELECT 1 FROM organization_members WHERE organization_id=$1 AND user_id=$2',
    [org.id, user.id]
  );
  if (!isMember.rows.length) {
    await db.query(
      `INSERT INTO organization_members (organization_id, user_id, role) VALUES ($1,$2,'member')`,
      [org.id, user.id]
    );
  }

  return user;
}

module.exports = {
  saveFlow, takeFlow, saveExchange, takeExchange,
  getOidcConfig, invalidateDiscovery, provisionSsoUser,
};
