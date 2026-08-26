const router = require('express').Router();
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const db = require('../db');
const { requireAuth, blockDemoDestructive } = require('../middleware/auth');
const { mintSession } = require('../utils/tokens');
const {
  peekChallenge, consumeChallenge,
  generateSecret, buildQrCode, verifyToken, encryptSecret, decryptSecret,
  generateBackupCodes, matchBackupCode,
} = require('../services/mfa');

// GET /auth/mfa/status
router.get('/status', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query('SELECT totp_enabled FROM users WHERE id=$1', [req.user.id]);
    res.json({ enabled: !!rows[0]?.totp_enabled });
  } catch (err) { next(err); }
});

// POST /auth/mfa/setup — mints a new (unconfirmed) secret and returns a QR
// code + the base32 secret for manual entry. Doesn't enable 2FA yet —
// totp_enabled only flips true once /enable proves possession via a real code.
// Safe to call again before confirming (e.g. QR didn't scan) — overwrites
// the previous unconfirmed secret.
router.post('/setup', requireAuth, async (req, res, next) => {
  try {
    const secret = await generateSecret();
    await db.query('UPDATE users SET totp_secret_enc=$1 WHERE id=$2', [encryptSecret(secret), req.user.id]);
    const qrCodeDataUrl = await buildQrCode(req.user.email, secret);
    res.json({ secret, qrCodeDataUrl });
  } catch (err) { next(err); }
});

// POST /auth/mfa/enable {code} — confirms the pending secret from /setup and
// turns 2FA on. Returns the plaintext backup codes exactly once.
router.post('/enable', requireAuth, blockDemoDestructive, [
  body('code').trim().isLength({ min: 6, max: 6 }).isNumeric(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Enter the 6-digit code from your app' });

  try {
    const { rows } = await db.query('SELECT totp_secret_enc FROM users WHERE id=$1', [req.user.id]);
    const encSecret = rows[0]?.totp_secret_enc;
    if (!encSecret) return res.status(400).json({ error: 'Call /auth/mfa/setup first' });

    if (!(await verifyToken(decryptSecret(encSecret), req.body.code)))
      return res.status(400).json({ error: 'Invalid code' });

    const { plain, hashed } = await generateBackupCodes();
    await db.query(
      'UPDATE users SET totp_enabled=true, totp_backup_codes=$1 WHERE id=$2',
      [JSON.stringify(hashed), req.user.id]
    );
    res.json({ enabled: true, backupCodes: plain });
  } catch (err) { next(err); }
});

// POST /auth/mfa/disable {password} — requires re-entering the account
// password (not just an active session) since this is a security downgrade —
// same bar as changing it, deliberately higher than editing a display name.
router.post('/disable', requireAuth, [
  body('password').notEmpty(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Password required' });

  try {
    const { rows } = await db.query('SELECT password FROM users WHERE id=$1', [req.user.id]);
    if (!(await bcrypt.compare(req.body.password, rows[0].password)))
      return res.status(401).json({ error: 'Incorrect password' });

    await db.query(
      `UPDATE users SET totp_enabled=false, totp_secret_enc=NULL, totp_backup_codes='[]' WHERE id=$1`,
      [req.user.id]
    );
    res.json({ enabled: false });
  } catch (err) { next(err); }
});

// POST /auth/mfa/verify {challengeToken, code} — second step of login for
// users with 2FA enabled. Accepts either a live TOTP code or a one-time
// backup code. On success mints the same session shape as /auth/login.
router.post('/verify', [
  body('challengeToken').notEmpty(),
  body('code').trim().notEmpty(),
], async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Code required' });

  try {
    const challenge = peekChallenge(req.body.challengeToken);
    if (!challenge) return res.status(401).json({ error: 'Login session expired, please sign in again' });

    const { rows } = await db.query('SELECT * FROM users WHERE id=$1', [challenge.userId]);
    const user = rows[0];
    if (!user || !user.totp_enabled) return res.status(401).json({ error: 'Login session expired, please sign in again' });

    const code = req.body.code;
    if (await verifyToken(decryptSecret(user.totp_secret_enc), code)) {
      consumeChallenge(req.body.challengeToken);
      return res.json(await mintSession(user));
    }

    const backupIdx = await matchBackupCode(user.totp_backup_codes, code);
    if (backupIdx !== -1) {
      const remaining = user.totp_backup_codes.filter((_, i) => i !== backupIdx);
      await db.query('UPDATE users SET totp_backup_codes=$1 WHERE id=$2', [JSON.stringify(remaining), user.id]);
      consumeChallenge(req.body.challengeToken);
      return res.json(await mintSession(user));
    }

    res.status(401).json({ error: 'Invalid code' });
  } catch (err) { next(err); }
});

module.exports = router;
