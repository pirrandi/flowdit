const { WebSocketServer, WebSocket } = require('ws');
const jwt = require('jsonwebtoken');
const url  = require('url');
const { userBelongsToProject } = require('./ownership');
const db = require('../db');

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
    ws.once('message', async (data) => {
      try {
        const msg = JSON.parse(data);
        if (msg.type !== 'auth' || !msg.token) { ws.close(4001, 'Unauthorized'); return; }
        const payload = jwt.verify(msg.token, process.env.JWT_SECRET);
        const user = { id: payload.sub, username: payload.username, display_name: null };

        // Bug real (ver ROADMAP.md § "WebSocket — validar membership de
        // proyecto al conectar"): el JWT solo prueba "sos un usuario válido
        // de Flowdit", nunca "sos miembro de ESTE proyecto" — cualquier
        // cuenta autenticada podía unirse a la sala de CUALQUIER proyecto
        // con solo conocer su UUID, y desde ahí leer el feed de Activity,
        // los eventos del scanner de IA, y mandar/recibir parches de
        // whiteboard como si fuera miembro real. Mismo chequeo que
        // requireProjectAccess (middleware REST) — membership directa o vía
        // owner/admin de la organización dueña.
        if (!(await userBelongsToProject(user.id, projectId))) {
          // 4001, no un código nuevo: el cliente (frontend/js/services/ws.js)
          // ya tiene una lista de códigos que NO reintenta (4001/4002/4003)
          // — un código nuevo caería en el reconnect con backoff exponencial
          // de abajo, reintentando para siempre contra un proyecto al que
          // este usuario nunca va a poder entrar.
          ws.close(4001, 'Unauthorized');
          return;
        }

        // The JWT only carries the username as of sign-in; read the current
        // username/display_name so presence and whiteboard cursors reflect
        // profile edits made since then.
        const { rows: urows } = await db.query(
          'SELECT username, display_name FROM users WHERE id=$1', [user.id]
        );
        if (!urows.length) { ws.close(4001, 'Unauthorized'); return; }
        user.username     = urows[0].username;
        user.display_name = urows[0].display_name || null;

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

        // Relay whiteboard messages to other room members (verbatim forward,
        // no server-side processing) + dispatch ai_scan:* messages to the
        // scanner agent loop (which DOES process before broadcasting — see
        // agentLoop.js and AI_PENTEST_AGENT.md).
        ws.on('message', (data) => {
          let msg;
          try { msg = JSON.parse(data); } catch { return; }

          if (msg.type === 'wb:cursor' || msg.type === 'wb:patch') {
            const room = rooms.get(projectId);
            if (!room) return;
            const out = JSON.stringify({ ...msg, userId: user.id, username: user.username, display_name: user.display_name });
            room.forEach(other => {
              if (other !== ws && other.readyState === WebSocket.OPEN) other.send(out);
            });
            return;
          }

          if (typeof msg.type === 'string' && msg.type.startsWith('ai_scan:')) {
            // require perezoso: agentLoop.js requiere este mismo módulo
            // (ws.js) para poder broadcastear — si este require estuviera
            // arriba del archivo, el ciclo capturaría el `module.exports`
            // de ws.js ANTES de que se reasigne al final (líneas de abajo),
            // dejando a agentLoop.js con una referencia vieja/vacía. Acá
            // adentro del handler, ambos módulos ya terminaron de cargar.
            const agentLoop = require('./ai/agentLoop');
            (async () => {
              try {
                // msg.session_id lo elige el cliente — sin este chequeo,
                // cualquier usuario conectado a ESTA sala (proyecto
                // `projectId`) podía operar sobre la sesión de scanner de
                // OTRO proyecto con solo conocer su UUID (encontrado en
                // revisión, ver AI_PENTEST_AGENT.md § Seguridad).
                if (!msg.session_id || !(await agentLoop.sessionBelongsToProject(msg.session_id, projectId))) return;
                switch (msg.type) {
                  case 'ai_scan:send_message':  await agentLoop.sendMessage(msg.session_id, user.id, msg.text); break;
                  case 'ai_scan:approve_action': await agentLoop.resolveGatedCall(msg.session_id, msg.call_id, 'accepted', user.id); break;
                  case 'ai_scan:reject_action':  await agentLoop.resolveGatedCall(msg.session_id, msg.call_id, 'rejected', user.id, { reason: msg.reason }); break;
                  case 'ai_scan:pause':          await agentLoop.pause(msg.session_id); break;
                  case 'ai_scan:resume':         await agentLoop.resume(msg.session_id); break;
                  case 'ai_scan:interrupt':
                    // Orden importa: interrupt() aborta la llamada en curso y
                    // hace la transición de estado de forma atómica ANTES de
                    // que sendMessage() lea el status — así sendMessage
                    // siempre ve 'idle' y retoma el loop con la instrucción
                    // nueva, sin correr en paralelo con el advance() abortado.
                    await agentLoop.interrupt(msg.session_id);
                    await agentLoop.sendMessage(msg.session_id, user.id, `[interrupt] ${msg.instruction}`);
                    break;
                }
              } catch (err) {
                console.error('ai_scan message error:', err.message);
              }
            })();
          }
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

// Broadcast an AI scanner session event to all members of a project.
// Used by agentLoop.js — see AI_PENTEST_AGENT.md. Unlike the wb:cursor/
// wb:patch relay above (which just forwards a client's own message
// verbatim), this is server-initiated: agentLoop.js processes/persists
// the event first, then calls this to push the result to everyone watching.
function broadcastScanEvent(projectId, data) {
  const room = rooms.get(projectId);
  if (!room) return;
  const msg = JSON.stringify({ type: 'ai_scan:event', ...data });
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

module.exports = { setup, broadcastActivity, broadcastScanEvent, disconnectUser };
