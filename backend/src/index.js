const http = require('http');
const app  = require('./app');

const wsService = require('./services/ws');

const server = http.createServer(app);
const PORT   = process.env.PORT || 4000;
const isDev  = process.env.NODE_ENV !== 'production';

// WebSocket must be attached before listen
wsService.setup(server);

server.listen(PORT, () => {
  console.log(`🚀 Flowdit API  ->  http://localhost:${PORT}`);
  console.log(`🔌 WebSocket    ->  ws://localhost:${PORT}/ws`);
  console.log(`   Mode: ${isDev ? 'development (CORS open)' : 'production'}`);
});
