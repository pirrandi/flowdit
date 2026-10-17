// Capturas de pantalla que Claude Code sube por fuera de las tools MCP
// (POST /mcp/uploads, ver routes/mcp.js) y después referencia por id en
// propose_finding / update_proposal (evidence_upload_ids). El modelo no puede
// transcribir los bytes de un archivo a un argumento de tool, así que el
// archivo viaja con curl y la tool solo lleva el id.
const db = require('../../db');

const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
// Tope de subidas SIN vincular por usuario: un Claude Code en loop no debe
// poder llenar la base de imágenes huérfanas.
const MAX_UNUSED_PER_USER = 50;
const MAX_UPLOADS_PER_PROPOSAL = 10;
// Una subida sin vincular vence a las 24 h. Interval fijo del código, nunca
// input del usuario.
const UNUSED_TTL_SQL = `INTERVAL '24 hours'`;

class UploadError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// El tipo se decide por los MAGIC BYTES, nunca por la extensión ni el
// Content-Type que manda el cliente: ambos los elige quien sube. Solo
// formatos que el navegador muestra como <img> y que la UI ya maneja.
function detectImageMime(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  return null;
}

const EXT = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp' };

// El nombre termina en el inbox y en custom_vulns.evidence (alt del <img>, y
// el reporte): solo el basename, sin caracteres de control ni separadores de
// ruta, acotado. Si no queda nada usable se inventa uno.
function sanitizeName(original, mime) {
  const base = String(original || '').split(/[\\/]/).pop();
  const clean = base.replace(/[^A-Za-z0-9._ -]/g, '_').replace(/^[.\s]+/, '').trim().slice(0, 100);
  return clean || `screenshot.${EXT[mime]}`;
}

async function createUpload({ user, tokenId, buffer, originalName }) {
  if (!buffer?.length) throw new UploadError(400, 'Empty file');
  if (buffer.length > MAX_UPLOAD_BYTES) throw new UploadError(413, `File too large (max ${MAX_UPLOAD_BYTES / 1024 / 1024} MB)`);
  const mime = detectImageMime(buffer);
  if (!mime) throw new UploadError(415, 'Unsupported file: only PNG, JPEG or WebP images are accepted');
  const name = sanitizeName(originalName, mime);

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    // Limpieza oportunista (sin cron): cada subida nueva barre las huérfanas
    // vencidas de TODOS los usuarios. Las vinculadas no vencen.
    await client.query(
      `DELETE FROM mcp_uploads WHERE used_by_proposal_id IS NULL AND created_at < NOW() - ${UNUSED_TTL_SQL}`
    );
    // Lock por usuario: sin esto dos subidas simultáneas leen el mismo conteo
    // y ambas pasan el tope.
    await client.query(`SELECT pg_advisory_xact_lock(hashtext('mcp_uploads:' || $1))`, [user.id]);
    const { rows: [{ n }] } = await client.query(
      `SELECT COUNT(*)::int AS n FROM mcp_uploads WHERE user_id = $1 AND used_by_proposal_id IS NULL`,
      [user.id]
    );
    if (n >= MAX_UNUSED_PER_USER) {
      throw new UploadError(429, `You already have ${n} uploads not attached to any proposal — attach them with evidence_upload_ids or wait 24h for them to expire`);
    }
    const { rows } = await client.query(
      `INSERT INTO mcp_uploads (user_id, token_id, mime, name, size, data)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, name, size, mime`,
      [user.id, tokenId || null, mime, name, buffer.length, buffer]
    );
    await client.query('COMMIT');
    const u = rows[0];
    return { upload_id: u.id, name: u.name, size: u.size, mime: u.mime };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Valida y vincula las subidas a la propuesta DENTRO de la transacción del
// caller (`client`). Si la lista viene, REEMPLAZA a la anterior: las que se
// sacan quedan sueltas otra vez (y vencen solas). El UPDATE condicionado es
// el que gana una carrera entre dos propuestas por la misma subida: la fila
// queda lockeada y la segunda, al re-evaluar el WHERE, ya no la encuentra
// libre.
async function attachUploads(client, { proposalId, userId, uploadIds }) {
  const ids = [...new Set(uploadIds)];
  if (ids.length > MAX_UPLOADS_PER_PROPOSAL) {
    throw new UploadError(400, `At most ${MAX_UPLOADS_PER_PROPOSAL} evidence uploads per proposal`);
  }
  await client.query(
    `UPDATE mcp_uploads SET used_by_proposal_id = NULL
     WHERE used_by_proposal_id = $1 AND NOT (id = ANY($2::uuid[]))`,
    [proposalId, ids]
  );
  if (!ids.length) return [];
  const { rows } = await client.query(
    `UPDATE mcp_uploads SET used_by_proposal_id = $1
     WHERE id = ANY($2::uuid[]) AND user_id = $3
       AND (used_by_proposal_id = $1
            OR (used_by_proposal_id IS NULL AND created_at >= NOW() - ${UNUSED_TTL_SQL}))
     RETURNING id`,
    [proposalId, ids, userId]
  );
  if (rows.length !== ids.length) {
    const ok = new Set(rows.map(r => r.id));
    const bad = ids.filter(id => !ok.has(id));
    throw new UploadError(400, await explainUnusable(client, bad, userId, proposalId));
  }
  return ids;
}

// Mensaje para el modelo de por qué una subida no se puede usar. Una subida
// ajena se reporta igual que una inexistente: no se confirma que exista.
async function explainUnusable(client, ids, userId, proposalId) {
  const { rows } = await client.query(
    `SELECT id, used_by_proposal_id, (created_at < NOW() - ${UNUSED_TTL_SQL}) AS expired
     FROM mcp_uploads WHERE id = ANY($1::uuid[]) AND user_id = $2`,
    [ids, userId]
  );
  const byId = new Map(rows.map(r => [r.id, r]));
  const id = ids[0];
  const r = byId.get(id);
  if (!r) return `evidence upload "${id}" not found — upload the file first (see get_upload_instructions)`;
  if (r.used_by_proposal_id && r.used_by_proposal_id !== proposalId) {
    return `evidence upload "${id}" is already attached to another proposal — upload the file again to use it here`;
  }
  if (r.expired) return `evidence upload "${id}" expired (unattached uploads last 24h) — upload the file again`;
  return `evidence upload "${id}" cannot be used`;
}

// Metadatos livianos de las subidas de cada propuesta, para listados.
const UPLOADS_META_SQL = `
  (SELECT COALESCE(json_agg(json_build_object('id', u.id, 'name', u.name, 'mime', u.mime, 'size', u.size)
                            ORDER BY u.created_at, u.id), '[]'::json)
   FROM mcp_uploads u WHERE u.used_by_proposal_id = mp.id)`;

// Data URLs con el mismo shape que escribe la UI en custom_vulns.evidence
// (frontend/js/views/vulns.js addEvidenceFile), para el inbox y la aprobación.
async function evidenceForProposal(queryable, proposalId) {
  const { rows } = await queryable.query(
    `SELECT id, name, mime, size, data
     FROM mcp_uploads WHERE used_by_proposal_id = $1 ORDER BY created_at, id`,
    [proposalId]
  );
  return rows.map(r => ({ id: r.id, name: r.name, mime: r.mime, size: r.size, data: `data:${r.mime};base64,${r.data.toString('base64')}` }));
}

module.exports = {
  createUpload, attachUploads, evidenceForProposal, detectImageMime, sanitizeName,
  UploadError, UPLOADS_META_SQL, MAX_UPLOAD_BYTES, MAX_UNUSED_PER_USER, MAX_UPLOADS_PER_PROPOSAL,
};
