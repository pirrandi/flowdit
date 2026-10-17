// POST /mcp — servidor MCP (Streamable HTTP, stateless) para Claude Code:
//   claude mcp add --transport http flowdit https://<host>/mcp --header "Authorization: Bearer fdt_..."
// Flowdit nunca llama a la API de Anthropic: es Claude Code del pentester el
// que se conecta acá a leer y proponer. Auth por token personal (no JWT), ver
// middleware/apiToken.js.
const router    = require('express').Router();
const rateLimit = require('express-rate-limit');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { requireApiToken } = require('../middleware/apiToken');
const { buildMcpServer } = require('../services/mcp/server');
const multer    = require('multer');
const mcpUploads = require('../services/mcp/uploads');

// Stateless: no hay sesión que abrir (GET/SSE) ni que cerrar (DELETE). 405
// es la respuesta que espera el cliente MCP en ese caso.
function methodNotAllowed(req, res) {
  res.status(405).set('Allow', 'POST').json({
    jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed.' }, id: null,
  });
}
router.get('/', methodNotAllowed);
router.delete('/', methodNotAllowed);

// Por IP, ANTES de autenticar: cada request con un token inventado cuesta
// una consulta a api_tokens, y el límite por token de abajo no lo frena
// porque solo corre con un token válido. Bolsa propia (el global de app.js
// excluye /mcp) para que Claude Code no le consuma el cupo a la UI.
router.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { jsonrpc: '2.0', error: { code: -32000, message: 'Too many requests from this IP — retry later.' }, id: null },
}));

router.use(requireApiToken);

// Por token: un Claude Code en loop no debe poder martillar la base. Corre
// después de autenticar (la key es el token).
router.use(rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: req => req.apiToken.id,
  message: { jsonrpc: '2.0', error: { code: -32000, message: 'Rate limit exceeded for this API token — slow down and retry in a minute.' }, id: null },
}));

// URL pública de /mcp/uploads tal como la ve el cliente, para que
// get_upload_instructions arme el curl exacto. Con trust proxy (app.js)
// req.protocol ya sale de X-Forwarded-Proto; el host se toma de
// X-Forwarded-Host si nginx lo manda. El host lo controla quien llama y
// termina en un comando de shell: se descarta si trae algo raro.
function publicUploadsUrl(req) {
  const fwdHost = (req.get('x-forwarded-host') || '').split(',')[0].trim();
  const host = fwdHost || req.get('host') || '';
  const safeHost = /^[A-Za-z0-9.-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/.test(host) ? host : 'YOUR_FLOWDIT_HOST';
  const proto = req.protocol === 'https' ? 'https' : 'http';
  return `${proto}://${safeHost}${req.baseUrl}/uploads`;
}

// POST /mcp/uploads — capturas para adjuntar a propose_finding /
// update_proposal (evidence_upload_ids). Por fuera de JSON-RPC porque el
// modelo no puede transcribir los bytes de un archivo a un argumento: Claude
// Code lo sube con curl y la tool solo lleva el id. Hereda los dos límites y
// requireApiToken de arriba. Memoria y no disco: 4 MB tope y va directo a
// la base. nginx corta /mcp en 5M, así que el tope queda por debajo.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: mcpUploads.MAX_UPLOAD_BYTES, files: 1, fields: 5, parts: 6 },
});

router.post('/uploads', (req, res, next) => {
  // Antes de parsear: un token de solo lectura no tiene por qué hacernos
  // leer 4 MB.
  if (req.apiToken.scopes !== 'read_propose') {
    return res.status(403).json({ error: 'This API token is read-only (scope "read") — create a token with scope "read_propose" to upload evidence' });
  }
  upload.single('file')(req, res, err => {
    if (!err) return next();
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: `File too large (max ${mcpUploads.MAX_UPLOAD_BYTES / 1024 / 1024} MB)` });
      return res.status(400).json({ error: `Invalid upload (${err.code}) — send one image in the multipart field "file"` });
    }
    next(err);
  });
}, async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'Missing file — send one image in the multipart field "file"' });
  try {
    res.status(201).json(await mcpUploads.createUpload({
      user: req.user, tokenId: req.apiToken.id, buffer: req.file.buffer, originalName: req.file.originalname,
    }));
  } catch (err) {
    if (err instanceof mcpUploads.UploadError) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

router.post('/', async (req, res) => {
  // Server + transport nuevos por request: en modo stateless el transport
  // del SDK no se puede reusar (choque de ids JSON-RPC entre clientes), y así
  // cada tool cierra sobre el usuario/token de ESTE request.
  const server = buildMcpServer({ user: req.user, token: req.apiToken, uploadsUrl: publicUploadsUrl(req) });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on('close', () => {
    transport.close().catch(() => {});
    server.close().catch(() => {});
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error('MCP request failed:', err.stack || err.message);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
    }
  }
});

module.exports = router;
