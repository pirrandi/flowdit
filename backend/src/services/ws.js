const { WebSocketServer, WebSocket } = require('ws');
const jwt = require('jsonwebtoken');
const url  = require('url');

// projectId → Set<ws>
const rooms = new Map();
// userId → Set<ws>  (for targeted logout)
const userSockets = new Map();

function setup(server) {
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws, req) => {
    const { query } = url.parse(req.url, true);
    const projectId = query.projectId;
    if (!projectId) { ws.close(4002, 'No projectId'); return; }

    // Auth via first message (token not in query string)
    ws.once('message', (data) => {
      try {
        const msg = JSON.parse(data);
        if (msg.type !== 'auth' || !msg.token) { ws.close(4001, 'Unauthorized'); return; }
        const payload = jwt.verify(msg.token, process.env.JWT_SECRET);
        const user = { id: payload.sub, username: payload.username };

        // Join room
        if (!rooms.has(projectId)) rooms.set(projectId, new Set());
        const room = rooms.get(projectId);
        room.add(ws);

        ws._user      = user;
        ws._projectId = projectId;

        // Track by userId for logout
        if (!userSockets.has(user.id)) userSockets.set(user.id, new Set());
        userSockets.get(user.id).add(ws);

        // Confirm auth and broadcast presence
        ws.send(JSON.stringify({ type: 'auth_ok' }));
        broadcastPresence(projectId);

        // Relay whiteboard messages to other room members
        ws.on('message', (data) => {
          try {
            const msg = JSON.parse(data);
            if (msg.type !== 'wb:cursor' && msg.type !== 'wb:patch') return;
            const room = rooms.get(projectId);
            if (!room) return;
            const out = JSON.stringify({ ...msg, userId: user.id, username: user.username });
            room.forEach(other => {
              if (other !== ws && other.readyState === WebSocket.OPEN) other.send(out);
            });
          } catch {}
        });

        ws.on('close', () => {
          room.delete(ws);
          if (room.size === 0) rooms.delete(projectId);
          else broadcastPresence(projectId);
          userSockets.get(user.id)?.delete(ws);
          if (!userSockets.get(user.id)?.size) userSockets.delete(user.id);
        });

      } catch {
        ws.close(4001, 'Unauthorized');
      }
    });

    ws.on('error', () => {});
  });
}

// Close all WebSocket connections for a given userId (e.g. on logout)
function disconnectUser(userId) {
  const sockets = userSockets.get(userId);
  if (!sockets) return;
  sockets.forEach(ws => ws.close(4003, 'Logged out'));
  userSockets.delete(userId);
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

// Send online users list to the whole room (deduplicated by user id)
function broadcastPresence(projectId) {
  const room = rooms.get(projectId);
  if (!room) return;
  const seen = new Map();
  room.forEach(ws => { if (ws._user && !seen.has(ws._user.id)) seen.set(ws._user.id, ws._user); });
  const online = [...seen.values()];
  const msg = JSON.stringify({ type: 'presence', online });
  room.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });
}

module.exports = { setup, broadcastActivity, disconnectUser };
