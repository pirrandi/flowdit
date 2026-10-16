const db = require('../db');
const { hashApiToken, looksLikeApiToken } = require('../services/apiTokens');

// Autenticación por token personal (fdt_...) — SOLO para /mcp. requireAuth
// (middleware/auth.js) sigue aceptando únicamente JWT, así que un token de
// Claude Code nunca abre las rutas /api: si se filtra, lo peor que permite es
// lo que exponen las tools MCP (leer y proponer), no editar ni borrar nada.
// Deja req.user con el mismo shape que requireAuth, para que findProjectForUser
// y activity.log funcionen sin cambios, y req.apiToken con el scope.
async function requireApiToken(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing API token. Send "Authorization: Bearer fdt_..."' });

  const token = header.slice(7).trim();
  if (!looksLikeApiToken(token))
    return res.status(401).json({ error: 'Invalid API token' });

  try {
    const { rows } = await db.query(
      `SELECT t.id AS token_id, t.scopes, t.revoked_at,
              (t.expires_at IS NOT NULL AND t.expires_at <= NOW()) AS expired,
              u.id, u.username, u.display_name, u.email, u.avatar_color, u.avatar_url
       FROM api_tokens t
       JOIN users u ON u.id = t.user_id
       WHERE t.token_hash = $1`,
      [hashApiToken(token)]
    );
    const row = rows[0];
    if (!row) return res.status(401).json({ error: 'Invalid API token' });
    if (row.revoked_at) return res.status(401).json({ error: 'API token revoked' });
    if (row.expired) return res.status(401).json({ error: 'API token expired' });

    // Best-effort y con throttle de un minuto: es solo informativo para la
    // UI ("último uso"), no justifica un UPDATE por cada tool call ni puede
    // tumbar el request si falla.
    db.query(
      `UPDATE api_tokens SET last_used_at = NOW()
       WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')`,
      [row.token_id]
    ).catch(err => console.error('api_tokens last_used_at update failed:', err.message));

    req.user = {
      id: row.id, username: row.username, display_name: row.display_name,
      email: row.email, avatar_color: row.avatar_color, avatar_url: row.avatar_url,
    };
    req.apiToken = { id: row.token_id, scopes: row.scopes };
    next();
  } catch (err) { next(err); }
}

module.exports = { requireApiToken };
