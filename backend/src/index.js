const http = require('http');

const app  = require('./app');

// Fail before anything listens: a server signing tokens with a public
// placeholder secret must never come up in production. Runs after app.js
// because that is where .env is loaded (pm2 deployments get their env only
// from there); checking earlier sees an empty env and only warns.
require('./utils/secrets').assertSafeSecrets();

const wsService  = require('./services/ws');
const agentLoop  = require('./services/ai/agentLoop');

const server = http.createServer(app);
const PORT   = process.env.PORT || 4000;
const isDev  = process.env.NODE_ENV !== 'production';

// WebSocket must be attached before listen
wsService.setup(server);

server.listen(PORT, () => {
  console.log(`🚀 Flowdit API  ->  http://localhost:${PORT}`);
  console.log(`🔌 WebSocket    ->  ws://localhost:${PORT}/ws`);
  console.log(`   Mode: ${isDev ? 'development (CORS open)' : 'production'}`);

  // Cualquier sesión del AI Agent que haya quedado "running" en la DB de un
  // reinicio anterior (crash, deploy) no tiene ningún proceso trabajándola
  // más — advance() vive en memoria, no sobrevive un restart. Ver el
  // comentario de resumeOrphanedThreads() en agentLoop.js.
  agentLoop.resumeOrphanedThreads()
    .then(n => { if (n) console.log(`↻ ${n} sesión(es) del AI Agent retomada(s) tras el reinicio`); })
    .catch(err => console.error('resumeOrphanedThreads failed:', err.message));
});
