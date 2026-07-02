const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../..', '.env') });

const http      = require('http');
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');

const wsService = require('./services/ws');

const app    = express();
const server = http.createServer(app);
const PORT   = process.env.PORT || 4000;
const isDev  = process.env.NODE_ENV !== 'production';

app.set('trust proxy', 1);

// WebSocket must be attached before listen
wsService.setup(server);

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

app.use(express.json({ limit: '4mb' }));

// Rate limiting (disabled in local dev)
if (process.env.NODE_ENV === 'production') {
  app.use(rateLimit({ windowMs:15*60*1000, max:500, standardHeaders:true, legacyHeaders:false }));
  app.use('/api/auth/login',    rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many attempts' } }));
  app.use('/api/auth/register', rateLimit({ windowMs:15*60*1000, max:10, message:{ error:'Too many attempts' } }));
  app.use('/api/portal/auth',   rateLimit({ windowMs:15*60*1000, max:10, message:{ error:'Too many attempts' } }));
  app.use('/api/auth/sso/start',    rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many attempts' } }));
  app.use('/api/auth/sso/callback', rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many attempts' } }));
}

// Health check
app.get('/health', (_, res) => res.json({ status:'ok', ts: new Date() }));

// Top-level routes
app.use('/api/auth',      require('./routes/auth'));
app.use('/api/auth/sso',  require('./routes/sso'));
app.use('/api/portal',    require('./routes/portal'));    // public — no requireAuth
app.use('/api/projects',  require('./routes/projects'));
app.use('/api/organizations', require('./routes/organizations'));
app.use('/api/templates', require('./routes/templates'));

// Nested project routes — mergeParams makes :projectId available in child routers
const projectRouter = express.Router({ mergeParams: true });
projectRouter.use('/wstg',     require('./routes/wstg'));
projectRouter.use('/ps',       require('./routes/ps'));
projectRouter.use('/vulns',    require('./routes/vulns'));
projectRouter.use('/activity', require('./routes/activity'));
projectRouter.use('/targets',  require('./routes/targets'));
projectRouter.use('/tickets',    require('./routes/tickets'));
projectRouter.use('/whiteboard', require('./routes/whiteboard'));
projectRouter.use('/import',    require('./routes/import'));
projectRouter.use('/ai',        require('./routes/ai'));

// Ports & endpoints nested under a specific target
const targetRouter = express.Router({ mergeParams: true });
targetRouter.use('/ports',     require('./routes/ports'));
targetRouter.use('/endpoints', require('./routes/endpoints'));
projectRouter.use('/targets/:targetId', targetRouter);

app.use('/api/methodologies', require('./routes/methodologies'));
app.use('/api/export',       require('./routes/export'));
app.use('/api/projects/:projectId', projectRouter);

// 404
app.use((req, res) => res.status(404).json({ error: `Not found: ${req.method} ${req.path}` }));

// Error handler
app.use((err, req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Start
server.listen(PORT, () => {
  console.log(`🚀 Flowdit API  ->  http://localhost:${PORT}`);
  console.log(`🔌 WebSocket    ->  ws://localhost:${PORT}/ws`);
  console.log(`   Mode: ${isDev ? 'development (CORS open)' : 'production'}`);
});