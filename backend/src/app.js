const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../..', '.env') });

const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');

const app   = express();
const isDev = process.env.NODE_ENV !== 'production';

app.set('trust proxy', 1);

// Security headers
app.use(helmet({ crossOriginEmbedderPolicy: false }));

// CORS — open in dev, strict in production
app.use(cors({
  origin: isDev
    ? true
    : (origin, cb) => {
        const allowed = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim());
        if (!origin || allowed.includes(origin)) return cb(null, true);
        cb(new Error('Not allowed by CORS'));
      },
  credentials: true,
}));

app.use(express.json({ limit: '25mb' }));

// Rate limiting (disabled in local dev)
if (process.env.NODE_ENV === 'production') {
  // RATE_LIMIT_MAX is documented in .env.example and set in docker-compose, but
  // the global limit ignored it and always used 500. The auth limits below stay
  // fixed on purpose — they guard credential stuffing, not general throughput,
  // and shouldn't loosen when an operator raises the app-wide ceiling.
  const globalMax = Number(process.env.RATE_LIMIT_MAX) || 500;
  // /mcp queda afuera: Claude Code y el navegador del pentester suelen salir
  // por la misma IP, y una sesión de tool calls agotaba esta bolsa y dejaba
  // la UI en 429. /mcp tiene sus propios límites (por IP y por token) en
  // routes/mcp.js.
  app.use(rateLimit({
    windowMs:15*60*1000, max:globalMax, standardHeaders:true, legacyHeaders:false,
    skip: req => /^\/mcp(\/|$)/.test(req.path),
  }));
  app.use('/api/auth/login',    rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many attempts' } }));
  app.use('/api/auth/register', rateLimit({ windowMs:15*60*1000, max:10, message:{ error:'Too many attempts' } }));
  app.use('/api/portal/auth',   rateLimit({ windowMs:15*60*1000, max:10, message:{ error:'Too many attempts' } }));
  app.use('/api/auth/sso/start',    rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many attempts' } }));
  app.use('/api/auth/sso/callback', rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many attempts' } }));
  app.use('/api/auth/mfa/verify',   rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many attempts' } }));
}

// Health check
app.get('/health', (_, res) => res.json({ status:'ok', ts: new Date() }));

// Top-level routes
app.use('/api/auth',      require('./routes/auth'));
app.use('/api/auth/sso',  require('./routes/sso'));
app.use('/api/auth/mfa',  require('./routes/mfa'));
app.use('/api/portal',    require('./routes/portal'));    // public — no requireAuth
app.use('/api/projects',  require('./routes/projects'));
app.use('/api/organizations', require('./routes/organizations'));
app.use('/api/templates', require('./routes/templates'));
app.use('/api/compliance', require('./routes/compliance'));
app.use('/api/report-templates', require('./routes/report-templates'));
app.use('/api/notifications', require('./routes/notifications'));
app.use('/api/me',        require('./routes/me'));

// Nested project routes — mergeParams makes :projectId available in child routers
const projectRouter = express.Router({ mergeParams: true });
projectRouter.use('/wstg',     require('./routes/wstg'));
projectRouter.use('/ps',       require('./routes/ps'));
projectRouter.use('/vulns',    require('./routes/vulns'));
projectRouter.use('/activity', require('./routes/activity'));
projectRouter.use('/targets',  require('./routes/targets'));
projectRouter.use('/tickets',    require('./routes/tickets'));
projectRouter.use('/tasks',      require('./routes/tasks'));
projectRouter.use('/whiteboard', require('./routes/whiteboard'));
projectRouter.use('/report-config', require('./routes/report-config'));
projectRouter.use('/import',    require('./routes/import'));
projectRouter.use('/ai',        require('./routes/ai'));
projectRouter.use('/ai-scan',   require('./routes/ai-scan'));
projectRouter.use('/mcp-proposals', require('./routes/mcp-proposals'));

// Ports & endpoints nested under a specific target
const targetRouter = express.Router({ mergeParams: true });
targetRouter.use('/ports',     require('./routes/ports'));
targetRouter.use('/endpoints', require('./routes/endpoints'));
projectRouter.use('/targets/:targetId', targetRouter);

app.use('/api/methodologies', require('./routes/methodologies'));
app.use('/api/export',       require('./routes/export'));
app.use('/api/projects/:projectId', projectRouter);

// Servidor MCP para Claude Code — fuera de /api a propósito: se autentica con
// tokens personales (fdt_...) que las rutas /api no aceptan.
app.use('/mcp', require('./routes/mcp'));

// 404
app.use((req, res) => res.status(404).json({ error: `Not found: ${req.method} ${req.path}` }));

// Error handler
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

module.exports = app;
