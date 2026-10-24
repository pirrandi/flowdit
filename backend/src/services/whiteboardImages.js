// Imágenes del whiteboard (tabla whiteboard_images). El blob del tablero
// solo guarda { imageId } por ítem: los bytes viven acá y se sirven con
// GET /whiteboard/images/:imageId (routes/whiteboard.js). Las suben los
// miembros desde la UI o Claude Code (add_whiteboard_items, copiando una
// subida de /mcp/uploads).
//
// Sin cron: cada alta barre las imágenes del proyecto que pasaron 24 h sin
// que el tablero las referencie (se subieron y nunca se guardó el ítem, o el
// ítem se borró). Una referenciada nunca se borra.
const db = require('../db');
const { detectImageMime, MAX_UPLOAD_BYTES } = require('./mcp/uploads');

const MAX_IMAGE_BYTES = MAX_UPLOAD_BYTES;
// Topes por proyecto: cada imagen es una fila con hasta 4 MB, y el tablero
// entero (con sus ítems de imagen) se baja en cada carga.
const MAX_PROJECT_IMAGES = 300;
const MAX_PROJECT_BYTES = 200 * 1024 * 1024;
// Interval fijo del código, nunca input del usuario.
const ORPHAN_TTL_SQL = `INTERVAL '24 hours'`;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_DIMENSION = 100000;

class WhiteboardImageError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const isUuid = v => typeof v === 'string' && UUID_RE.test(v);

// Ancho/alto leídos de la cabecera del formato (sin decodificar la imagen).
// Opcionales: si la cabecera no se entiende se devuelve null y la UI usa la
// proporción por defecto.
function imageDimensions(buf, mime) {
  try {
    let w, h;
    if (mime === 'image/png') {
      if (buf.length < 24 || buf.toString('latin1', 12, 16) !== 'IHDR') return null;
      w = buf.readUInt32BE(16); h = buf.readUInt32BE(20);
    } else if (mime === 'image/webp') {
      const chunk = buf.toString('latin1', 12, 16);
      if (chunk === 'VP8 ' && buf.length >= 30) {
        w = buf.readUInt16LE(26) & 0x3fff; h = buf.readUInt16LE(28) & 0x3fff;
      } else if (chunk === 'VP8L' && buf.length >= 25) {
        const b1 = buf[22], b2 = buf[23], b3 = buf[24];
        w = 1 + (((b1 & 0x3f) << 8) | buf[21]);
        h = 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6));
      } else if (chunk === 'VP8X' && buf.length >= 30) {
        w = 1 + buf.readUIntLE(24, 3); h = 1 + buf.readUIntLE(27, 3);
      } else return null;
    } else if (mime === 'image/jpeg') {
      // Se recorren los segmentos hasta el primer SOFn (C0..CF salvo C4, C8, CC).
      let i = 2;
      while (i + 9 < buf.length) {
        if (buf[i] !== 0xff) return null;
        const m = buf[i + 1];
        if (m === 0xff) { i++; continue; }
        if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) {
          h = buf.readUInt16BE(i + 5); w = buf.readUInt16BE(i + 7);
          break;
        }
        if (m === 0x01 || (m >= 0xd0 && m <= 0xd9)) { i += 2; continue; }
        i += 2 + buf.readUInt16BE(i + 2);
      }
    }
    const ok = v => Number.isInteger(v) && v > 0 && v <= MAX_DIMENSION;
    return ok(w) && ok(h) ? { width: w, height: h } : null;
  } catch {
    return null;
  }
}

// imageIds que el tablero guardado referencia (solo los que tienen forma de
// UUID: el resto no puede ser una fila de esta tabla). Un ítem borrado sale
// de data.images y queda como tombstone en whiteboard_state.sync: un PUT
// viejo no lo revive (whiteboardSync.js), así que sus bytes se barren.
function referencedIds(data) {
  const images = Array.isArray(data?.images) ? data.images : [];
  return [...new Set(images.map(i => i?.imageId).filter(isUuid))];
}

// Inserta una imagen dentro de la transacción del caller (`client`): barre
// las huérfanas vencidas del proyecto, controla los topes y la guarda.
// `keepIds`: las que el tablero referencia (nunca se barren). Valida los
// bytes acá también, así el MCP y la ruta pasan por el mismo control.
async function insertImage(client, { projectId, userId, buffer, source, keepIds }) {
  if (!buffer?.length) throw new WhiteboardImageError(400, 'Empty file');
  if (buffer.length > MAX_IMAGE_BYTES) throw new WhiteboardImageError(413, `File too large (max ${MAX_IMAGE_BYTES / 1024 / 1024} MB)`);
  const mime = detectImageMime(buffer);
  if (!mime) throw new WhiteboardImageError(415, 'Unsupported file: only PNG, JPEG or WebP images are accepted');

  // Lock por proyecto: sin esto dos subidas simultáneas leen el mismo
  // conteo y ambas pasan el tope.
  await client.query(`SELECT pg_advisory_xact_lock(hashtext('whiteboard_images:' || $1))`, [projectId]);
  await client.query(
    `DELETE FROM whiteboard_images
     WHERE project_id = $1 AND created_at < NOW() - ${ORPHAN_TTL_SQL} AND NOT (id = ANY($2::uuid[]))`,
    [projectId, keepIds]
  );
  const { rows: [usage] } = await client.query(
    `SELECT COUNT(*)::int AS n, COALESCE(SUM(size), 0)::bigint AS bytes FROM whiteboard_images WHERE project_id = $1`,
    [projectId]
  );
  if (usage.n >= MAX_PROJECT_IMAGES) {
    throw new WhiteboardImageError(409, `This whiteboard already has ${usage.n} images (max ${MAX_PROJECT_IMAGES})`);
  }
  if (Number(usage.bytes) + buffer.length > MAX_PROJECT_BYTES) {
    throw new WhiteboardImageError(409, `This whiteboard's images would exceed ${MAX_PROJECT_BYTES / 1024 / 1024} MB`);
  }
  const dims = imageDimensions(buffer, mime);
  const { rows } = await client.query(
    `INSERT INTO whiteboard_images (project_id, mime, bytes, size, width, height, created_by, source)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, mime, size, width, height`,
    [projectId, mime, buffer, buffer.length, dims?.width ?? null, dims?.height ?? null, userId || null, source]
  );
  return rows[0];
}

// Alta desde la UI (POST /whiteboard/images). Las referencias se leen sin
// lockear el tablero: una imagen recién referenciada no puede tener 24 h.
async function createImage({ projectId, user, buffer }) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(`SELECT data FROM whiteboard_state WHERE project_id = $1`, [projectId]);
    const row = await insertImage(client, {
      projectId, userId: user.id, buffer, source: 'user', keepIds: referencedIds(rows[0]?.data),
    });
    await client.query('COMMIT');
    return publicMeta(row);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

function publicMeta(row) {
  const out = { id: row.id, mime: row.mime, size: row.size };
  if (row.width && row.height) { out.width = row.width; out.height = row.height; }
  return out;
}

// La imagen solo si es de ESTE proyecto: un id de otro proyecto responde
// igual que uno inexistente.
async function getImage(projectId, imageId) {
  if (!isUuid(imageId)) return null;
  const { rows } = await db.query(
    `SELECT mime, bytes FROM whiteboard_images WHERE id = $1 AND project_id = $2`,
    [imageId, projectId]
  );
  return rows[0] || null;
}

module.exports = {
  createImage, insertImage, getImage, imageDimensions, referencedIds, publicMeta, isUuid,
  WhiteboardImageError, MAX_IMAGE_BYTES, MAX_PROJECT_IMAGES, MAX_PROJECT_BYTES,
};
