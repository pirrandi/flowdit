const router  = require('express').Router({ mergeParams: true });
const multer  = require('multer');
const rateLimit = require('express-rate-limit');
const db      = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, denyClientSessions } = require('../middleware/project');
const { sanitizeWhiteboardData, sanitizeSyncRequest, LIST_LIMITS, WhiteboardDataError } = require('../services/whiteboardSanitize');
const wbImages = require('../services/whiteboardImages');
const wbSync  = require('../services/whiteboardSync');
const ws      = require('../services/ws');

// Las cuentas viewer son el cliente (ver isClientSession): igual que el portal,
// no ven este material interno aunque no puedan escribirlo.
router.use(requireAuth, requireUser, requireProjectAccess, denyClientSessions); // internal-only: never exposed to client portal sessions

// Sin ?since: el tablero entero + su revisión (carga inicial; los clientes
// viejos solo leen `data`). Con ?since=N: solo lo que cambió después de N
// (ítems y borrados), para que una pestaña que reconecta se ponga al día.
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT id, project_id, data, revision, sync, updated_by, updated_at FROM whiteboard_state WHERE project_id=$1`,
      [req.params.projectId]
    );
    const row = rows[0] || { id: null, project_id: req.params.projectId, data: {}, revision: 0, sync: {}, updated_by: null, updated_at: null };
    const state = { data: row.data, revision: Number(row.revision) || 0, sync: row.sync };
    if (req.query.since !== undefined) {
      const since = /^\d{1,15}$/.test(String(req.query.since)) ? Number(req.query.since) : -1;
      return res.json({ ...wbSync.changesSince(state, since), updated_at: row.updated_at });
    }
    const { sync, ...rest } = row;
    res.json({ ...rest, revision: state.revision, initialized: wbSync.isInitialized(row.data, wbSync.normalizeSync(sync)) });
  } catch (err) { next(err); }
});

// El blob lo dibuja el navegador de cada miembro: solo se guardan los campos
// conocidos, con colores de la allowlist y números finitos (ver whiteboardSanitize).
// Nunca se pisa el tablero entero: se mezcla ítem por ítem con lo guardado
// (ver services/whiteboardSync.js). Con base_revision la respuesta trae lo que
// cambió desde esa base para que el cliente se ponga al día; sin ella
// (whiteboard.js viejo todavía abierto) responde la fila como antes.
router.put('/', requireWriter, async (req, res, next) => {
  let data, syncReq;
  try {
    data = sanitizeWhiteboardData(req.body.data ?? {});
    syncReq = sanitizeSyncRequest(req.body);
  } catch (err) {
    if (err instanceof WhiteboardDataError) return res.status(400).json({ error: err.message });
    return next(err);
  }
  try {
    const projectId = req.params.projectId;
    const { row, merged } = await wbSync.saveFromClient({
      projectId, userId: req.user.id, data,
      baseRevision: syncReq.baseRevision, removed: syncReq.removed, limits: LIST_LIMITS,
    });
    // Las otras pestañas se ponen al día con GET ?since (los ops de wb:patch
    // pueden haberse perdido). Un whiteboard.js viejo ignora este op.
    if (merged.changed) ws.broadcastWhiteboardPatch(projectId, { op: 'rev', revision: merged.revision });
    const initialized = merged.sync.initialized;
    if (syncReq.baseRevision === undefined) {
      return res.json({ ...row, revision: merged.revision, initialized });
    }
    res.json({ ...wbSync.changesSince(merged, syncReq.baseRevision), updated_at: row.updated_at });
  } catch (err) { next(err); }
});

// ── Imágenes ───────────────────────────────────────────────────────────
// POST /images — una imagen (multipart, campo "file"). Memoria y no disco:
// 4 MB tope y va directo a la base. El tipo sale de los magic bytes (ver
// services/whiteboardImages.js), nunca del nombre ni del Content-Type.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: wbImages.MAX_IMAGE_BYTES, files: 1, fields: 5, parts: 6 },
});

// Por usuario, además del global por IP de app.js: pegar/soltar muchas
// imágenes seguidas es legítimo, un script subiendo sin parar no.
const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: req => req.user.id,
  message: { error: 'Too many image uploads — retry in a minute' },
});

router.post('/images', requireWriter, uploadLimiter, (req, res, next) => {
  upload.single('file')(req, res, err => {
    if (!err) return next();
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: `File too large (max ${wbImages.MAX_IMAGE_BYTES / 1024 / 1024} MB)` });
      return res.status(400).json({ error: `Invalid upload (${err.code}) — send one image in the multipart field "file"` });
    }
    next(err);
  });
}, async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'Missing file — send one image in the multipart field "file"' });
  try {
    res.status(201).json(await wbImages.createImage({ projectId: req.params.projectId, user: req.user, buffer: req.file.buffer }));
  } catch (err) {
    if (err instanceof wbImages.WhiteboardImageError) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

// GET /images/:imageId — los bytes, con el Content-Type guardado (que salió
// de los magic bytes). nosniff + CSP sin nada permitido: aunque alguien abra
// la URL directo, el navegador no puede tratarla como HTML ni ejecutar nada.
// El id no cambia de contenido nunca, así que el caché puede ser largo.
router.get('/images/:imageId', async (req, res, next) => {
  try {
    const img = await wbImages.getImage(req.params.projectId, req.params.imageId);
    if (!img) return res.status(404).json({ error: 'Image not found' });
    res.set({
      'Content-Type': img.mime,
      'X-Content-Type-Options': 'nosniff',
      'Content-Disposition': 'inline',
      'Cache-Control': 'private, max-age=86400, immutable',
      'Content-Security-Policy': "default-src 'none'; sandbox",
    });
    res.send(img.bytes);
  } catch (err) { next(err); }
});

module.exports = router;
