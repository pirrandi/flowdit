// ── config.js — auto-detects environment ─────────────────────────────
// Dev:  localhost → uses localhost:4000
// Prod: any other host → same origin (nginx proxies /api and /ws)
(function() {
  const isDev = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
  if (isDev) {
    window.FLOWDIT_API = 'http://localhost:4000/api';
    window.FLOWDIT_WS  = 'ws://localhost:4000/ws';
  } else {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    window.FLOWDIT_API = '/api';
    window.FLOWDIT_WS  = `${proto}://${location.host}/ws`;
  }
})();