require('dotenv').config();
const http      = require('http');
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');

const wsService = require('./services/ws');

const app    = express();
const server = http.createServer(app);

// Setup WebSocket server attached to the same HTTP server
wsService.setup(server);

const PORT = process.env.PORT || 4000;

// ── Security ──────────────────────────────────────────────────────
app.use(helmet());

const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5500,http://127.0.0.1:5500,http://localhost:3000').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

app.use(express.json({ limit: '1mb' }));

// ── Rate limiting ─────────────────────────────────────────────────
app.use(rateLimit({ windowMs:15*60*1000, max:3000, standardHeaders:true, legacyHeaders:false }));
app.use('/api/auth/login',    rateLimit({ windowMs:15*60*1000, max:20 }));
app.use('/api/auth/register', rateLimit({ windowMs:15*60*1000, max:10 }));

// ── Health ────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status:'ok', ts: new Date() }));

// ── Routes ────────────────────────────────────────────────────────
app.use('/api/auth',     require('./routes/auth'));
app.use('/api/projects', require('./routes/projects'));
app.use('/api/projects/:projectId/wstg',     require('./routes/wstg'));
app.use('/api/projects/:projectId/ps',       require('./routes/ps'));
app.use('/api/projects/:projectId/vulns',    require('./routes/vulns'));
app.use('/api/projects/:projectId/activity', require('./routes/activity'));

// ── Error handler ─────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error:'Not found' }));
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error:'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`🚀 Flowdit API on port ${PORT}`);
  console.log(`🔌 WebSocket ready at ws://localhost:${PORT}/ws`);
});
