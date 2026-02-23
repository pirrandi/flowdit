const { WebSocketServer, WebSocket } = require('ws');
const jwt = require('jsonwebtoken');
const url  = require('url');

// projectId → Set<ws>
const rooms = new Map();

function setup(server) {
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws, req) => {
    const { query } = url.parse(req.url, true);
    const token = query.token;

    let user = null;
    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      user = { id: payload.sub, username: payload.username };
    } catch {
      ws.close(4001, 'Unauthorized');
      return;
    }

    const projectId = query.projectId;
    if (!projectId) { ws.close(4002, 'No projectId'); return; }

    // Join room
    if (!rooms.has(projectId)) rooms.set(projectId, new Set());
    const room = rooms.get(projectId);
    room.add(ws);

    ws._user      = user;
    ws._projectId = projectId;

    // Send online presence list
    broadcastPresence(projectId);

    ws.on('close', () => {
      room.delete(ws);
      if (room.size === 0) rooms.delete(projectId);
      else broadcastPresence(projectId);
    });

    ws.on('error', () => {});
  });
}

// Broadcast an activity event to all members of a project
function broadcastActivity(projectId, event) {
  const room = rooms.get(projectId);
  if (!room) return;
  const msg = JSON.stringify({ type: 'activity', ...event });
  room.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });
}

// Send online users list to the whole room
function broadcastPresence(projectId) {
  const room = rooms.get(projectId);
  if (!room) return;
  const online = [];
  room.forEach(ws => { if (ws._user) online.push(ws._user); });
  const msg = JSON.stringify({ type: 'presence', online });
  room.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });
}

module.exports = { setup, broadcastActivity };
