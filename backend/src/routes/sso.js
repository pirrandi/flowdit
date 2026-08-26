const router = require('express').Router();
const crypto = require('crypto');
const db = require('../db');
const { decrypt } = require('../utils/crypto');
const { mintSession } = require('../utils/tokens');
const {
  saveFlow, takeFlow, saveExchange, takeExchange,
  getOidcConfig, provisionSsoUser,
} = require('../services/sso');

// No requireAuth anywhere in this file — these routes exist precisely because
// the caller doesn't have a session yet (mirrors /auth/login, /auth/register).
//
// Note: SSO login never checks users.totp_enabled — the identity provider
// (Entra ID) owns MFA policy for that leg, so a local TOTP secret (if the
// user separately opted into one) is orthogonal, not additionally enforced
// here. Only password login (/auth/login) checks it.

function apiOrigin() {
  return (process.env.PUBLIC_API_URL || '').replace(/\/$/, '');
}
function frontendOrigin() {
  return (process.env.FRONTEND_URL || '').replace(/\/$/, '');
}
function redirectUri() {
  return `${apiOrigin()}/api/auth/sso/callback`;
}
function loginErrorRedirect(res, message) {
  res.redirect(`${frontendOrigin()}/index.html?ssoError=${encodeURIComponent(message)}`);
}

// POST /auth/sso/check {email} — does an SSO-enabled org claim this domain?
router.post('/check', async (req, res, next) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const domain = email.split('@')[1];
  if (!domain) return res.json({ available: false });
  try {
    const { rows } = await db.query(
      `SELECT o.id AS org_id, o.name AS org_name
       FROM organization_sso_configs c
       JOIN organizations o ON o.id = c.organization_id
       WHERE c.email_domain = $1 AND c.enabled = true`,
      [domain]
    );
    if (!rows.length) return res.json({ available: false });
    res.json({
      available: true,
      organizationName: rows[0].org_name,
      // relative to FLOWDIT_API (which already includes /api), not the site root
      startUrl: `/auth/sso/start?oid=${rows[0].org_id}`,
    });
  } catch (err) { next(err); }
});

// GET /auth/sso/start?oid= — redirect the browser to the IdP
router.get('/start', async (req, res, next) => {
  const oid = req.query.oid;
  if (!oid) return loginErrorRedirect(res, 'Missing organization');
  try {
    const { rows } = await db.query(
      `SELECT c.*, o.is_personal FROM organization_sso_configs c
       JOIN organizations o ON o.id = c.organization_id
       WHERE c.organization_id = $1 AND c.enabled = true`,
      [oid]
    );
    if (!rows.length || rows[0].is_personal) return loginErrorRedirect(res, 'SSO is not configured for this organization');
    const cfg = rows[0];

    const clientSecret = decrypt(cfg.client_secret_enc);
    const oidcConfig = await getOidcConfig(oid, cfg.issuer_url, cfg.client_id, clientSecret);

    const { randomState, randomNonce, randomPKCECodeVerifier, calculatePKCECodeChallenge, buildAuthorizationUrl } =
      await import('openid-client');

    const state        = randomState();
    const nonce         = randomNonce();
    const codeVerifier  = randomPKCECodeVerifier();
    const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);

    saveFlow(state, { codeVerifier, nonce, orgId: oid });

    const authUrl = buildAuthorizationUrl(oidcConfig, {
      redirect_uri: redirectUri(),
      scope: 'openid profile email',
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    res.redirect(authUrl.toString());
  } catch (err) { next(err); }
});

// GET /auth/sso/callback — Microsoft redirects back here with ?code&state
router.get('/callback', async (req, res, _next) => {
  const { state } = req.query;
  if (!state) return loginErrorRedirect(res, 'Missing state');
  const flow = takeFlow(state);
  if (!flow) return loginErrorRedirect(res, 'Login session expired, please try again');

  try {
    const { rows } = await db.query(
      `SELECT * FROM organization_sso_configs WHERE organization_id = $1 AND enabled = true`,
      [flow.orgId]
    );
    if (!rows.length) return loginErrorRedirect(res, 'SSO is no longer configured for this organization');
    const cfg = rows[0];

    const clientSecret = decrypt(cfg.client_secret_enc);
    const oidcConfig = await getOidcConfig(flow.orgId, cfg.issuer_url, cfg.client_id, clientSecret);

    const { authorizationCodeGrant } = await import('openid-client');
    const currentUrl = new URL(req.originalUrl, apiOrigin());

    const tokens = await authorizationCodeGrant(oidcConfig, currentUrl, {
      pkceCodeVerifier: flow.codeVerifier,
      expectedNonce: flow.nonce,
      expectedState: state,
    });

    const claims = tokens.claims();
    const user = await provisionSsoUser(claims, { id: cfg.organization_id, email_domain: cfg.email_domain });
    const session = await mintSession(user);

    const exchangeCode = crypto.randomBytes(24).toString('hex');
    saveExchange(exchangeCode, session);

    res.redirect(`${frontendOrigin()}/sso-complete.html?xchg=${exchangeCode}`);
  } catch (err) {
    // Domain-mismatch / claims errors from provisionSsoUser, and any
    // openid-client validation failure, all land here — surface a generic
    // message to the browser, log the real one server-side.
    console.error('SSO callback error:', err.message);
    loginErrorRedirect(res, 'Sign-in failed. Please try again or contact your administrator.');
  }
});

// POST /auth/sso/exchange {code} — trade the one-time code for real tokens.
// DB-free: the tokens were already minted at callback time, this is just a
// single-use Map read, which is what keeps the JWT out of the redirect URL.
router.post('/exchange', (req, res) => {
  const code = req.body.code;
  if (!code) return res.status(400).json({ error: 'Code required' });
  const session = takeExchange(code);
  if (!session) return res.status(400).json({ error: 'Invalid or expired code' });
  res.json(session);
});

module.exports = router;
