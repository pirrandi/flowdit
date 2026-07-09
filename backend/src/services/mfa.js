const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
// otplib v13 dropped the old `authenticator` singleton for standalone async
// functions (generateSecret/generate/verify/generateURI) — no legacy shim.
const otplib = require('otplib');
const { encrypt, decrypt } = require('../utils/crypto');

// ── In-process challenge store ───────────────────────────────────────
// Bridges /auth/login (password verified, TOTP still owed) to
// /auth/mfa/verify (TOTP verified, session actually minted). Same Map+TTL
// idiom as services/sso.js's flow/exchange stores — single PM2 fork-mode
// process, no shared-state concern.
const challengeStore = new Map(); // token -> { userId, expiresAt }
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

function _sweep() {
  const now = Date.now();
  for (const [k, v] of challengeStore) if (v.expiresAt < now) challengeStore.delete(k);
}
setInterval(_sweep, 5 * 60 * 1000).unref();

function createChallenge(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  challengeStore.set(token, { userId, expiresAt: Date.now() + CHALLENGE_TTL_MS });
  return token;
}
// Deliberately not single-use on failed attempts — only consumed by the
// caller once a code actually verifies — so the user can retry a mistyped
// code within the 5-minute window without re-entering their password.
function peekChallenge(token) {
  const v = challengeStore.get(token);
  if (!v || v.expiresAt < Date.now()) { challengeStore.delete(token); return null; }
  return v;
}
function consumeChallenge(token) {
  challengeStore.delete(token);
}

// ── TOTP secret / QR ─────────────────────────────────────────────────
async function generateSecret() {
  return otplib.generateSecret();
}

async function buildQrCode(email, secret) {
  const otpauth = otplib.generateURI({ issuer: 'Flowdit', label: email, secret });
  return QRCode.toDataURL(otpauth);
}

async function verifyToken(secret, code) {
  try {
    const result = await otplib.verify({ secret, token: String(code || '').trim() });
    return !!result.valid;
  } catch {
    return false;
  }
}

function encryptSecret(secret) { return encrypt(secret); }
function decryptSecret(enc)    { return decrypt(enc); }

// ── Backup codes ──────────────────────────────────────────────────────
// 10 codes, 8 hex chars each, shown to the user exactly once at enable time.
// Only bcrypt hashes are persisted (users.totp_backup_codes JSONB array).
async function generateBackupCodes() {
  const plain = Array.from({ length: 10 }, () => crypto.randomBytes(4).toString('hex'));
  const hashed = await Promise.all(plain.map(code => bcrypt.hash(code, 10)));
  return { plain, hashed };
}

// Returns the matching array index (so the caller can remove it — single
// use) or -1 if the code doesn't match any remaining hash.
async function matchBackupCode(hashedCodes, code) {
  const candidate = String(code || '').trim().toLowerCase();
  for (let i = 0; i < hashedCodes.length; i++) {
    if (await bcrypt.compare(candidate, hashedCodes[i])) return i;
  }
  return -1;
}

module.exports = {
  createChallenge, peekChallenge, consumeChallenge,
  generateSecret, buildQrCode, verifyToken, encryptSecret, decryptSecret,
  generateBackupCodes, matchBackupCode,
};
