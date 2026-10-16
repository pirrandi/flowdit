// Tokens personales para el servidor MCP (/mcp) — los usa Claude Code del
// pentester. Formato `fdt_` + 32 bytes aleatorios en base64url; la base solo
// guarda el SHA-256 (lookup) y un prefijo corto para reconocerlo en la UI.
// A diferencia de portal_links no hay copia cifrada: el token en claro se
// muestra una única vez al crearlo y no se puede volver a recuperar.
const crypto = require('crypto');

const TOKEN_PREFIX = 'fdt_';
const SCOPES = ['read', 'read_propose'];
// Lo que se guarda para mostrar: `fdt_` + 6 caracteres, suficiente para
// distinguir un token de otro sin acercarse a revelar el secreto.
const DISPLAY_PREFIX_LEN = TOKEN_PREFIX.length + 6;

function generateApiToken() {
  return TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
}

function hashApiToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function displayPrefix(token) {
  return token.slice(0, DISPLAY_PREFIX_LEN);
}

function looksLikeApiToken(token) {
  return typeof token === 'string' && token.startsWith(TOKEN_PREFIX);
}

module.exports = { generateApiToken, hashApiToken, displayPrefix, looksLikeApiToken, SCOPES, TOKEN_PREFIX };
