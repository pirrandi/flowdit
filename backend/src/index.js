require('dotenv').config();
const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');

const authRoutes    = require('./routes/auth');
const projectRoutes = require('./routes/projects');
const wstgRoutes    = require('./routes/wstg');
const psRoutes      = require('./routes/ps');
const vulnsRoutes   = require('./routes/vulns');
const { requireAuth } = require('./middleware/auth');

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Security headers ─────────────────────────────────────────────────
app.use(helmet());

// ── CORS Robustecido ──────────────────────────────────────────────────
const rawOrigin = process.env.CORS_ORIGIN || 'https://wr0ng.art';
// Limpiamos posibles espacios en blanco de la lista
const allowedOrigins = rawOrigin.split(',').map(o => o.trim());

app.use(cors({
  origin: (origin, cb) => {
    // Si no hay origen (ej. herramientas de servidor) o está en la lista
    if (!origin || allowedOrigins.includes(origin)) {
      return cb(null, true);
    }
    
    // Log de seguridad para auditoría SOC
    console.error(`[CORS REJECTED] Origen: ${origin} | Permitidos: ${allowedOrigins}`);
    cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

// ── Body parsing ──────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));

// ── Rate limiting ─────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max:      parseInt(process.env.RATE_LIMIT_MAX) || 200,
  standardHeaders: true,
  legacyHeaders:   false,
});
app.use(limiter);

// Stricter limit on auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many login attempts, please try again later' },
});
app.use('/api/auth/login',    authLimiter);
app.use('/api/auth/register', authLimiter);

// ── Health check ──────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', ts: new Date() }));

// ── Routes ────────────────────────────────────────────────────────────
app.use('/api/auth',     authRoutes);
app.use('/api/projects', projectRoutes);

// Nested routes under projects
app.use('/api/projects/:projectId/wstg',  wstgRoutes);
app.use('/api/projects/:projectId/ps',    psRoutes);
app.use('/api/projects/:projectId/vulns', vulnsRoutes);

// ── 404 ───────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── Error handler ─────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS error' });
  }
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 HackList API running on port ${PORT}`);
  console.log(`   Mode: ${process.env.NODE_ENV || 'development'}`);
});
