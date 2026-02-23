// ── ws.js — WebSocket client ─────────────────────────────────────────
const WS_BASE = window.FLOWDIT_WS || 'ws://localhost:4000/ws';

class WSClient {
  constructor() {
    this._ws         = null;
    this._projectId  = null;
    this._handlers   = {};     // eventType → [fn]
    this._reconnectN = 0;
    this._reconnectTimer = null;
  }

  connect(projectId) {
    if (this._projectId === projectId && this._ws?.readyState === WebSocket.OPEN) return;
    this.disconnect();
    this._projectId = projectId;
    this._open();
  }

  disconnect() {
    clearTimeout(this._reconnectTimer);
    if (this._ws) { this._ws.onclose = null; this._ws.close(); this._ws = null; }
    this._projectId  = null;
    this._reconnectN = 0;
  }

  _open() {
    const token = tokens.access;
    if (!token || !this._projectId) return;
    const url = `${WS_BASE}?token=${encodeURIComponent(token)}&projectId=${this._projectId}`;
    this._ws = new WebSocket(url);

    this._ws.onopen = () => {
      this._reconnectN = 0;
      this._emit('connected', {});
    };

    this._ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        this._emit(msg.type, msg);
      } catch {}
    };

    this._ws.onclose = (ev) => {
      if (ev.code === 4001 || ev.code === 4002) return; // auth error, don't retry
      this._emit('disconnected', {});
      const delay = Math.min(1000 * 2 ** this._reconnectN, 30000);
      this._reconnectN++;
      this._reconnectTimer = setTimeout(() => this._open(), delay);
    };

    this._ws.onerror = () => {};
  }

  on(type, fn) {
    if (!this._handlers[type]) this._handlers[type] = [];
    this._handlers[type].push(fn);
    return () => { this._handlers[type] = this._handlers[type].filter(h => h !== fn); };
  }

  _emit(type, data) {
    (this._handlers[type] || []).forEach(fn => { try { fn(data); } catch {} });
  }
}

window.wsClient = new WSClient();
