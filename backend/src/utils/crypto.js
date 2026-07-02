const crypto = require('crypto');

// SSO_ENCRYPTION_KEY is a free-form string in .env — hash it to a guaranteed
// 32-byte key so operators don't need to paste an exact-length value.
function key() {
  if (!process.env.SSO_ENCRYPTION_KEY) throw new Error('SSO_ENCRYPTION_KEY is not configured');
  return crypto.createHash('sha256').update(process.env.SSO_ENCRYPTION_KEY).digest();
}

// AES-256-GCM, random 12-byte IV per call. Format: "iv:authTag:ciphertext" (hex).
function encrypt(plaintext) {
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key(), iv);
  const enc    = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

function decrypt(payload) {
  const [ivHex, tagHex, encHex] = String(payload).split(':');
  if (!ivHex || !tagHex || !encHex) throw new Error('Malformed encrypted payload');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]).toString('utf8');
}

module.exports = { encrypt, decrypt };
