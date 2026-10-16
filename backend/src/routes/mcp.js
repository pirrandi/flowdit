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

router.post('/', async (req, res) => {
  // Server + transport nuevos por request: en modo stateless el transport
  // del SDK no se puede reusar (choque de ids JSON-RPC entre clientes), y así
  // cada tool cierra sobre el usuario/token de ESTE request.
  const server = buildMcpServer({ user: req.user, token: req.apiToken });
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
