const { decrypt } = require('./crypto');

// A project's own API key for a hosted provider (Groq/DeepSeek/Anthropic/
// Kimi), decrypted — or undefined if the project has none, or the stored
// value can't be decrypted (SSO_ENCRYPTION_KEY rotated, corrupted data,
// etc.). Never throws: a decrypt failure must fall back to the global
// env-var key, not break the AI call.
function resolveProjectApiKey(project, provider) {
  const enc = project?.ai_api_keys_enc?.[provider];
  if (!enc) return undefined;
  try { return decrypt(enc); } catch { return undefined; }
}

module.exports = { resolveProjectApiKey };
