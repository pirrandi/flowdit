const router  = require('express').Router({ mergeParams: true });
const multer  = require('multer');
const rateLimit = require('express-rate-limit');
const db      = require('../db');
const { requireAuth, requireUser } = require('../middleware/auth');
const { requireProjectAccess, requireWriter, denyClientSessions } = require('../middleware/project');
const { sanitizeWhiteboardData, WhiteboardDataError } = require('../services/whiteboardSanitize');
const wbImages = require('../services/whiteboardImages');

// Las cuentas viewer son el cliente (ver isClientSession): igual que el portal,
// no ven este material interno aunque no puedan escribirlo.
router.use(requireAuth, requireUser, requireProjectAccess, denyClientSessions); // internal-only: never exposed to client portal sessions

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await db.query(
      `SELECT * FROM whiteboard_state WHERE project_id=$1`,
      [req.params.projectId]
    );
    res.json(rows[0] || { id: null, project_id: req.params.projectId, data: {}, updated_by: null, updated_at: null });
  } catch (err) { next(err); }
});

router.put('/', requireWriter, async (req, res, next) => {
  // El blob lo dibuja el navegador de cada miembro: solo se guardan los campos
  // conocidos, con colores de la allowlist y números finitos (ver whiteboardSanitize).
  let data;
  try {
    data = sanitizeWhiteboardData(req.body.data ?? {});
  } catch (err) {
    if (err instanceof WhiteboardDataError) return res.status(400).json({ error: err.message });
    return next(err);
  }
  try {
    const { rows } = await db.query(
      `INSERT INTO whiteboard_state (project_id, data, updated_by)
       VALUES ($1, $2, $3)
       ON CONFLICT (project_id) DO UPDATE
         SET data=$2, updated_by=$3, updated_at=NOW()
       RETURNING *`,
      [req.params.projectId, JSON.stringify(data), req.user.id]
    );
    res.json(rows[0]);
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
