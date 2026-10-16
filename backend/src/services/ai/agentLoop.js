// Loop del agente de scanner de IA — ver AI_PENTEST_AGENT.md para el diseño
// completo. Es una función PURA del historial persistido en ai_scan_events
// (salvo `activeAborts`, ver más abajo) — segura de llamar desde cualquier
// disparador sin importar la iteración, y sobrevive un reinicio del server
// mientras espera una aprobación humana.
//
// Multi-agente: cada sesión tiene uno o más "threads" (ai_scan_threads). El
// thread con parent_thread_id NULL es el coordinador (el que "habla" con el
// pentester); puede delegar tareas a sub-agentes vía delegate_to_subagent,
// cada uno con su propio thread corriendo en paralelo. Un gate pendiente en
// un thread NO frena a los demás — solo `ai_scan_sessions.status='paused'`
// (acción explícita del pentester) frena todo. Fuera de ese caso,
// `ai_scan_sessions.status` es un AGREGADO de los threads, recalculado en
// cada transición (recomputeSessionStatus) — nunca escrito a mano salvo en
// pause/resume.

const db = require('../../db');
const ai = require('./index');
const ws = require('../ws');
const { scanTools }        = require('./scanTools');
const { scanToolsLevel1, normalizeEndpointPath } = require('./scanToolsLevel1');
const { scanToolsLevel2 }  = require('./scanToolsLevel2');
const { scanToolsLevel3 }  = require('./scanToolsLevel3');
const { targetBelongsToProject } = require('../ownership');
const { logUsage } = require('./usage');
const activity = require('../activity');
const mailer = require('../mailer');
const pentestKnowledge = require('./pentestKnowledge');

// Valor de arranque, ajustable — evita que un modelo (sobre todo uno local
// más débil) quede en loop infinito llamando tools sin llegar nunca a una
// respuesta final, lo cual costaría dinero y llenaría la DB de eventos.
// Subido de 40 a 80 al habilitar el modo sin restricciones — un testing
// activo real (varias variantes de payload contra el mismo endpoint, por
// ejemplo) puede necesitar más de 40 tool calls en un solo turno sin que
// eso sea un loop descontrolado. Ver más abajo: pisar el tope YA NO mata la
// sesión, así que el número exacto importa menos que antes.
const MAX_ITERATIONS_PER_TURN = 80;

// Con `ai_autonomous_requests` activo, un checkpoint (arriba) ya no espera
// a un humano — se auto-continúa. Este es el freno de última instancia:
// después de esta cantidad de checkpoints SEGUIDOS sin que un chat.message
// real interrumpa la cadena, para de verdad y avisa. 5 × 80 = 400 tool
// calls de trabajo autónomo continuo antes de necesitar a un humano.
const MAX_AUTO_CHECKPOINTS = 5;

// Freno anti-loop encontrado en vivo (2026-09-22, DeepSeek en modo
// non-thinking + autónomo): el modelo llamó fetch_endpoint sobre el MISMO
// path 570 veces seguidas, siempre con el mismo resultado, sin ningún
// progreso. El checkpoint de arriba solo cuenta VOLUMEN de tool calls, no si
// son informativamente redundantes — en modo autónomo esto podía correr
// durante el presupuesto completo de 400 tool calls antes de que alguien se
// entere. Corta la ejecución real (ahorra el costo del request también) en
// cuanto una misma tool+input se repite esta cantidad de veces dentro del
// turno actual, y le devuelve al modelo un error explícito en vez de
// silenciarla — le da la chance de corregirse solo antes del próximo
// checkpoint, en vez de descubrirlo recién 400 llamadas después.
//
// NO exige que sean consecutivas: la primera versión de este freno sí lo
// exigía, y en la misma sesión (retomada tras el aviso) el modelo esquivó
// la detección alternando fetch_endpoint/search_page_source sobre el mismo
// /js/qrcode.js — cada llamada individual no repetía a la inmediatamente
// anterior, así que nunca cortaba la racha. Contar el total en el turno
// (sin importar el orden ni qué otras tools se intercalen) cierra ese hueco.
const MAX_DUPLICATE_CALLS_PER_TURN = 3;

// JSON.stringify serializa objetos en el orden de inserción de las keys,
// pero Postgres NO preserva ese orden en columnas JSONB — el mismo input,
// leído de vuelta de ai_scan_events.payload, puede volver con las keys en
// otro orden. Sin esto, toolCallSignature() nunca matcheaba entre la call
// en memoria y las ya persistidas para cualquier tool con 2+ parámetros,
// dejando el freno anti-loop de MAX_DUPLICATE_CALLS_PER_TURN inoperante.
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function toolCallSignature(name, input) {
  return `${name}:${stableStringify(input)}`;
}

// Cuenta cuántas llamadas con esta firma ya hubo desde `start` — en
// cualquier posición, no solo las inmediatamente anteriores. `signatureOf`
// devuelve null para las llamadas que no aplican.
function countMatchingCalls(eventRows, start, signature, signatureOf = toolCallSignature) {
  let count = 0;
  for (let i = start; i < eventRows.length; i++) {
    if (eventRows[i].type !== 'tool.called') continue;
    if (signatureOf(eventRows[i].payload.name, eventRows[i].payload.input) === signature) count++;
  }
  return count;
}

// Freno anti-loop por RUTA, encontrado en vivo (2026-10-13, 1.935 tool calls
// en 3,5 h sin que el modelo concluyera nunca): el freno de firma exacta de
// arriba no lo ve porque ninguna llamada repite exactamente a otra —
// - 874 fetch_endpoint al mismo /api/... cambiando solo el cache-buster
//   `?_=` y el pageSize;
// - 512 fetch_page_source paginando un main.js.map de varios MB de a 20.000
//   caracteres (cada página con un `offset` distinto).
// Agrupa las lecturas por target + path, ignorando query string, fragmento y
// paginación, y corta pasado el tope dentro de la corrida autónoma.
// search_page_source queda afuera a propósito: buscar distintos patrones
// en un mismo bundle es justamente el uso correcto, y es la salida que se le
// sugiere al modelo cuando lo frena este tope.
const PATH_READ_TOOLS = new Set(['fetch_endpoint', 'fetch_page_source']);
const MAX_PATH_READS_PER_RUN = 15;

function pathReadSignature(name, input) {
  if (!PATH_READ_TOOLS.has(name) || typeof input?.path !== 'string') return null;
  return `${input.target_id}:${normalizeEndpointPath(input.path)}`;
}

// Tools de Nivel 0-3 (sin gate hasta tier 2). delegate_to_subagent (abajo)
// se suma aparte porque solo el thread coordinador puede usarla.
const BASE_TOOL_REGISTRY = [...scanTools, ...scanToolsLevel1, ...scanToolsLevel2, ...scanToolsLevel3];

// Pedido explícito: poder configurar una sesión para un CTF o un laboratorio
// tipo HTB/THM, no solo un pentest de cliente real — cambia el ENFOQUE del
// agente (qué priorizar, cuánto arriesgar), la config de IA (provider/model)
// ya cubre el "con qué" corre, esto cubre el "para qué". `null`/'pentest' =
// comportamiento actual sin cambios (el prompt no gana texto nuevo). El
// toolset sigue siendo puramente HTTP (sin shell/SSH/privesc) en los 3
// casos — 'lab' lo dice explícito para que el agente no finja haber corrido
// un comando que no puede correr.
const PROFILE_GUIDANCE = {
  ctf: 'This session is a CTF (Capture The Flag) challenge, not a client engagement — there is no real victim and no polished report expected at the end. Prioritize finding and reporting the flag itself over writing remediation advice: flags are commonly formatted like flag{...} or similar, and commonly hidden in HTML comments, JS bundles/source maps, HTTP response headers, cookies, backup/hidden endpoints, robots.txt, or exposed config/env files — check all of those. The moment you find a flag, say it plainly in your response, and also call propose_finding so it is on record. Since this is a designed challenge environment with no real victim, be more willing to try unconventional or aggressive payloads than you would against production infrastructure — the scope boundary above still applies, but within it, favor creative exploitation over caution.',
  lab: "This session is a practice lab (HTB/THM-style machine), not a client engagement. Treat it like a full box: thoroughly enumerate everything reachable over HTTP first (endpoints, subdomains, exposed source, version banners in headers/responses), then look for known vulnerabilities matching any specific software/version you identify. Prioritize finding flag files if reachable through what you have (commonly named user.txt/root.txt/flag.txt, e.g. via an LFI or an exposed static path). Be upfront about the limits of your toolset here: you only have HTTP-level tools — no shell, no SSH, no privilege-escalation tooling. If the next real step would require a shell, say so plainly instead of pretending you ran a command you cannot actually run, and hand it off as a clear next step for the pentester.",
};

// AbortController de la llamada al proveedor en curso, por THREAD (antes
// era por sesión — con multi-agente, varios threads pueden tener cada uno
// su propia llamada en vuelo al mismo tiempo).
const activeAborts = new Map(); // threadId → AbortController

// Generación de corrida por thread. interrupt/pause/retomar con mensaje la
// incrementan; cada advance() captura la suya al arrancar y abandona (sin
// persistir ni recursar) si cambió. Sin esto, un interrupt durante la
// ejecución de una tool dejaba dos loops vivos sobre el mismo thread: el
// viejo terminaba la tool y seguía recursando junto al nuevo. En memoria
// alcanza: hay un solo proceso, y tras un reinicio no queda ningún loop viejo.
const runGenerations = new Map(); // threadId → número
function currentGeneration(threadId) { return runGenerations.get(threadId) || 0; }
function bumpGeneration(threadId) { runGenerations.set(threadId, currentGeneration(threadId) + 1); }

// Cuántas cadenas de advance() lanzadas por advanceSafely() siguen vivas por
// thread — retry() lo usa para relanzar solo los threads `running` que no
// tienen ningún loop (los que quedaron trabados), sin duplicar uno sano.
const activeLoops = new Map(); // threadId → cantidad

// Solo para resolveGatedCall: busca en el registro completo porque la tool
// ya pasó por el filtro de `tools` ofrecidas cuando advance() la persistió.
function findTool(name) {
  if (name === 'delegate_to_subagent') return DELEGATE_TOOL;
  return BASE_TOOL_REGISTRY.find(t => t.name === name);
}

// Topes de fan-out de delegate_to_subagent, por sesión.
const MAX_ACTIVE_SUBAGENTS = 5;
const MAX_TOTAL_SUBAGENTS = 20;

// tier 2 (acción activa contra el target) y tier 3 (propose_finding,
// escribe al reporte) están gated por defecto, pero un proyecto puede optar
// por saltear AMBOS con `ai_autonomous_requests` — "modo sin restricciones",
// pedido explícito del usuario ("chipe libre absoluto en todo"). El toggle
// es reversible desde Settings sin tocar código. Nota: la descripción de
// cada tool ("requires approval...") queda desactualizada para un proyecto
// con el toggle en true — es texto estático compartido por todos los
// proyectos, no vale la pena hacerlo dinámico solo por esto.
function needsGate(tool, project) {
  return tool.tier >= 2 && !project.ai_autonomous_requests;
}

async function persistEvent(sessionId, threadId, type, payload, createdBy = null) {
  const { rows } = await db.query(
    `INSERT INTO ai_scan_events (session_id, thread_id, type, payload, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [sessionId, threadId, type, JSON.stringify(payload), createdBy]
  );
  return rows[0];
}

async function getSession(sessionId) {
  const { rows } = await db.query(`SELECT * FROM ai_scan_sessions WHERE id=$1`, [sessionId]);
  return rows[0];
}

async function getThread(threadId) {
  const { rows } = await db.query(`SELECT * FROM ai_scan_threads WHERE id=$1`, [threadId]);
  return rows[0];
}

async function getPrimaryThread(sessionId) {
  const { rows } = await db.query(`SELECT * FROM ai_scan_threads WHERE session_id=$1 AND parent_thread_id IS NULL`, [sessionId]);
  return rows[0];
}

// activity.log() exige un `user` completo ({id, username, avatar_color}),
// no solo un id — hace falta para atribuir acciones que dispara el agente
// por su cuenta (crear un hallazgo en modo autónomo, avisar que necesita
// atención) a quien arrancó la sesión, igual que ya se hace con
// created_by/approvedBy en otros lados de este archivo.
async function getUserRow(userId) {
  const { rows } = await db.query(`SELECT id, username, display_name, avatar_color, email FROM users WHERE id=$1`, [userId]);
  return rows[0];
}

// Estos avisos los lee el pentester (Activity + email), así que van en el
// idioma que eligió para la sesión, no siempre en español.
const ATTENTION_MESSAGES = {
  es: {
    budget: p => `El AI Agent llegó al límite de trabajo autónomo continuo (~${p.calls} tool calls) y necesita que revises la sesión.`,
    cost: p => `El AI Agent paró: se alcanzó el tope de gasto de la sesión ($${p.cap}, gastado $${p.spent}).`,
    approval: p => `El AI Agent quiere ejecutar "${p.tool}" y necesita tu aprobación.`,
  },
  en: {
    budget: p => `The AI Agent reached its continuous autonomous work limit (~${p.calls} tool calls) and needs you to review the session.`,
    cost: p => `The AI Agent stopped: the session's cost cap was reached ($${p.cap}, spent $${p.spent}).`,
    approval: p => `The AI Agent wants to run "${p.tool}" and needs your approval.`,
  },
};

function attentionMessage(session, key, params) {
  return (ATTENTION_MESSAGES[session.response_language] || ATTENTION_MESSAGES.es)[key](params);
}

// El único momento del modo autónomo que amerita sacar al pentester de lo
// que esté haciendo: se quedó sin presupuesto de auto-continues y de
// verdad necesita que alguien mire. Reusa el feed de Activity que ya
// existe (visible en vivo en la columna derecha de cualquier página) en
// vez de construir un sistema de notificaciones nuevo — pedido explícito:
// "lo que sí puede hacer es mandar una notificación, avisando que hará
// algo importante".
async function notifyNeedsAttention(session, project, message) {
  const starter = await getUserRow(session.started_by);
  if (!starter) return;
  activity.log({
    projectId: session.project_id, user: starter,
    action: 'ai_scan_needs_attention', entityType: 'ai_scan_session',
    entityId: session.id, entityName: project.name, meta: { message },
  });
  // ROADMAP.md § "Notificación al celular..." — el feed de Activity de
  // arriba es solo in-app/WS, nada llega afuera del navegador si el
  // pentester no tiene la pestaña abierta. Email vía la infra de mailer.js
  // que ya existe (SMTP configurable, no-op silencioso si no está seteado)
  // — mismo criterio que sendTicketReplyNotification en tickets.js.
  // Fire-and-forget: nunca debe romper el loop del agente si el mail falla.
  mailer.sendAiScanNeedsAttentionNotification({
    toEmail: starter.email,
    toName: starter.display_name || starter.username,
    projectName: project.name,
    message,
    appUrl: process.env.FRONTEND_URL ? `${process.env.FRONTEND_URL.replace(/\/$/, '')}/ai-agent?pid=${session.project_id}` : null,
  }).catch(err => console.error('sendAiScanNeedsAttentionNotification failed:', err.message));
}

// Toda función pública de este módulo toma un `sessionId` desnudo, elegido
// por el CLIENTE (viene del payload del mensaje WS, o del body de un POST
// /vulns) — nunca hay que asumir que ese sessionId pertenece al proyecto
// del caller. Sin este chequeo, cualquier usuario autenticado en CUALQUIER
// proyecto podía mandar/aprobar/rechazar/pausar/interrumpir la sesión de
// OTRO proyecto con solo conocer su UUID (encontrado en revisión, ver
// AI_PENTEST_AGENT.md). Los dos callers (ws.js, vulns.js) deben llamar esto
// antes de invocar cualquier otra función de acá con un sessionId ajeno.
async function sessionBelongsToProject(sessionId, projectId) {
  const session = await getSession(sessionId);
  return !!session && session.project_id === projectId;
}

// Nombre corto derivado de un mensaje — sin llamar a ningún provider, puro
// string handling. Se usa como nombre inicial de una sesión (instrucción de
// arranque o primer chat.message) hasta que el pentester la renombre a mano
// vía PATCH /sessions/:id (ver ai-scan.js) — una vez seteado, nunca se
// vuelve a pisar automáticamente (ver el guard `if (!session.name)` en
// sendMessage más abajo).
function deriveSessionName(text) {
  const clean = text.replace(/\s+/g, ' ').trim();
  if (clean.length <= 60) return clean;
  const cut = clean.slice(0, 60);
  const lastSpace = cut.lastIndexOf(' ');
  return (lastSpace > 20 ? cut.slice(0, lastSpace) : cut) + '…';
}

// Crea la sesión Y su thread primario en un solo paso — usado por la ruta
// POST /sessions (ver ai-scan.js). Ningún caller debería crear una sesión
// sin thread primario: advance() no tiene sentido sin uno.
async function createSessionWithPrimaryThread(projectId, targetId, startedBy, responseLanguage = 'es', instruction = null, aiOverrides = {}) {
  const name = instruction ? deriveSessionName(instruction) : null;
  const { rows: sessionRows } = await db.query(
    `INSERT INTO ai_scan_sessions (project_id, target_id, status, started_by, response_language, name, ai_provider, ai_model, ai_tool_mode, ai_autonomous_requests, ai_single_agent, ai_profile, ai_max_cost_usd)
     VALUES ($1,$2,'running',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
    [
      projectId, targetId, startedBy, responseLanguage, name,
      aiOverrides.ai_provider || null, aiOverrides.ai_model || null, aiOverrides.ai_tool_mode || null,
      aiOverrides.ai_autonomous_requests ?? null, aiOverrides.ai_single_agent ?? null, aiOverrides.ai_profile || null,
      aiOverrides.ai_max_cost_usd || null,
    ]
  );
  const session = sessionRows[0];
  const { rows: threadRows } = await db.query(
    `INSERT INTO ai_scan_threads (session_id, parent_thread_id, status) VALUES ($1,NULL,'running') RETURNING *`,
    [session.id]
  );
  return { session, primaryThread: threadRows[0] };
}

async function setThreadStatus(threadId, status) {
  await db.query(
    `UPDATE ai_scan_threads SET status=$2${status === 'completed' ? ', completed_at=NOW()' : ''} WHERE id=$1`,
    [threadId, status]
  );
}

async function setSessionStatus(sessionId, status) {
  await db.query(
    `UPDATE ai_scan_sessions SET status=$2${status === 'completed' ? ', completed_at=NOW()' : ''} WHERE id=$1`,
    [sessionId, status]
  );
}

// Recalcula ai_scan_sessions.status a partir de TODOS los threads de la
// sesión — se llama después de cualquier transición de estado de un
// thread. No pisa un `paused` (override explícito del pentester).
//
// `error` ya no es pegajoso, y solo lo produce el coordinador: antes un
// sub-agente en error dejaba la sesión en `error` con el primario idle, y
// como advance() no corría sesiones en `error`, el primario despertado por
// el reporte de otro sub-agente quedaba `running` sin loop para siempre. El
// error de un sub-agente ahora le llega al coordinador como reporte (ver
// failThread), que decide qué hacer.
async function recomputeSessionStatus(sessionId) {
  const session = await getSession(sessionId);
  if (!session || session.status === 'paused') return;

  const { rows: threads } = await db.query(`SELECT status, parent_thread_id FROM ai_scan_threads WHERE session_id=$1`, [sessionId]);
  if (!threads.length) return;
  const primary = threads.find(t => !t.parent_thread_id);

  let next;
  if (threads.some(t => t.status === 'waiting_approval')) next = 'waiting_approval';
  else if (threads.some(t => t.status === 'running'))      next = 'running';
  else if (primary?.status === 'error')                    next = 'error';
  else if (threads.every(t => t.status === 'completed'))   next = 'completed';
  else next = 'idle';

  if (next !== session.status) await setSessionStatus(sessionId, next);
}

function broadcast(projectId, sessionId, status, event) {
  ws.broadcastScanEvent(projectId, {
    session_id: sessionId,
    status,
    event: { id: event.id, type: event.type, payload: event.payload, thread_id: event.thread_id, created_at: event.created_at },
  });
}

// Reconstruye el historial de UN thread (no de toda la sesión) en el
// formato canónico que entienden los adaptadores por proveedor.
// ── Compactación del historial ──────────────────────────────────────────
// Encontrado en vivo (retest de EncuestaQR): advance() mandaba el historial
// COMPLETO del thread en cada llamada — 479 eventos, ~610K caracteres
// (~150K tokens) por mensaje, 2/3 de eso respuestas viejas de tools. Caro
// (se quedó sin fondos) y el modelo seguía peor las instrucciones nuevas
// ("SOLO UN PÁRRAFO") enterradas al final de semejante contexto.
//
// Política: los mensajes del pentester nunca se tocan. De las tool calls,
// solo las más recientes viajan completas; las de antes viajan como un
// resumen corto, y las muy viejas se omiten (llamada + resultado juntos,
// para no dejar un tool_result huérfano, que la API rechaza). Las respuestas
// viejas del propio agente se recortan.
//
// Los cortes avanzan en saltos de COMPACTION_STEP tool calls, no de a una:
// así el prefijo del historial queda idéntico entre llamadas consecutivas y
// el prompt caching del proveedor (DeepSeek/Anthropic) lo sigue
// aprovechando, en vez de invalidarse en cada turno.
const FULL_TOOL_CALLS = 15;            // las últimas N tool calls viajan completas
const SUMMARIZED_TOOL_CALLS = 60;      // las N anteriores a esas, resumidas
const COMPACTION_STEP = 10;
const MAX_TOOL_RESULT_CHARS = 16000;   // tope incluso para una tool call reciente
const SUMMARY_PREVIEW_CHARS = 300;
const KEEP_FULL_ASSISTANT_MESSAGES = 6;
const OLD_ASSISTANT_MESSAGE_CHARS = 1500;

function clip(text, max) {
  return text.length > max ? `${text.slice(0, max)}… [truncated, ${text.length - max} more chars]` : text;
}

function compactToolResult(payload, maxChars) {
  const json = JSON.stringify(payload);
  if (json.length <= maxChars) return payload;
  return { call_id: payload.call_id, name: payload.name, truncated: true, preview: clip(json, maxChars) };
}

function compactToolInput(input) {
  const json = JSON.stringify(input ?? {});
  return json.length <= SUMMARY_PREVIEW_CHARS ? input : { truncated_input: clip(json, SUMMARY_PREVIEW_CHARS) };
}

// Índice (en orden de tool calls) desde el cual cada tramo arranca —
// redondeado hacia abajo a COMPACTION_STEP para que sea estable.
function compactionCutoffs(totalToolCalls) {
  const stable = n => Math.max(0, Math.floor(n / COMPACTION_STEP) * COMPACTION_STEP);
  const fullFrom = stable(totalToolCalls - FULL_TOOL_CALLS);
  const summarizedFrom = stable(fullFrom - SUMMARIZED_TOOL_CALLS);
  return { fullFrom, summarizedFrom };
}

function eventsToMessages(events) {
  const callOrder = new Map(); // id de tool.called → posición entre todas las tool calls
  events.forEach(ev => { if (ev.type === 'tool.called') callOrder.set(String(ev.id), callOrder.size); });
  const { fullFrom, summarizedFrom } = compactionCutoffs(callOrder.size);
  const tierOf = callId => {
    const i = callOrder.get(String(callId));
    if (i === undefined || i >= fullFrom) return 'full';
    return i >= summarizedFrom ? 'summary' : 'omitted';
  };

  const assistantTotal = events.filter(e => e.type === 'chat.message' && e.payload.role === 'assistant').length;
  let assistantSeen = 0;
  let omittedNoted = false;

  // Ambos proveedores exigen que cada tool_use vaya seguido INMEDIATAMENTE
  // de su tool_result (400 si no). Pero un chat.message o subagent.reported
  // puede persistirse mientras una tool está ejecutando, quedando entre la
  // llamada y su resultado — esos mensajes se difieren hasta después del
  // resultado. Y una llamada sin resultado (crash o interrupt a mitad de la
  // tool) recibe un resultado sintético de error, en vez de dejar un
  // tool_use huérfano que rompe el historial para siempre. Solo advance()
  // arma mensajes, y solo con el thread `running` — una llamada que espera
  // aprobación (thread `waiting_approval`) nunca pasa por acá, así que toda
  // llamada pendiente que se ve acá es realmente huérfana.
  const messages = [];
  let pending = null;   // call_id (string) del tool_use emitido que espera su resultado
  let pendingName = null;
  let deferred = [];

  const emit = msg => (pending ? deferred.push(msg) : messages.push(msg));
  const closePending = () => {
    if (!pending) return;
    messages.push({ role: 'tool', toolCallId: pending, name: pendingName, result: { error: 'interrupted, no result — this call did not complete (it may or may not have reached the target). Re-run it if you still need it.' } });
    pending = null;
    messages.push(...deferred);
    deferred = [];
  };

  for (const ev of events) {
    if (ev.type === 'chat.message') {
      let text = ev.payload.text;
      if (ev.payload.role === 'assistant') {
        assistantSeen++;
        if (assistantTotal - assistantSeen >= KEEP_FULL_ASSISTANT_MESSAGES) text = clip(text || '', OLD_ASSISTANT_MESSAGE_CHARS);
        // El asistente no habla con una tool a medio responder: la llamada
        // pendiente quedó huérfana.
        closePending();
        messages.push({ role: 'assistant', content: text });
      } else {
        emit({ role: ev.payload.role, content: text });
      }
    } else if (ev.type === 'tool.called') {
      // Las llamadas son secuenciales dentro de un loop: si llega otra con
      // una pendiente, la anterior nunca va a tener resultado.
      closePending();
      const tier = tierOf(ev.id);
      if (tier === 'omitted') {
        if (!omittedNoted) {
          omittedNoted = true;
          messages.push({ role: 'user', content: `[system note]: ${summarizedFrom} earlier tool calls were omitted from this history to save context. Their effects (findings, data) still exist — re-run a read-only tool if you need that information again.` });
        }
        continue;
      }
      const msg = { role: 'assistant', toolCalls: [{ id: String(ev.id), name: ev.payload.name, input: tier === 'full' ? ev.payload.input : compactToolInput(ev.payload.input) }] };
      // Modelos con "thinking" (DeepSeek, Kimi...) exigen recibir de vuelta
      // el reasoning_content de sus turnos con tool calls.
      if (typeof ev.payload.reasoning_content === 'string') {
        msg.reasoningContent = tier === 'full' ? ev.payload.reasoning_content : clip(ev.payload.reasoning_content, SUMMARY_PREVIEW_CHARS);
      }
      messages.push(msg);
      pending = String(ev.id);
      pendingName = ev.payload.name;
    } else if (ev.type === 'tool.result') {
      const callId = String(ev.payload.call_id);
      const tier = tierOf(callId);
      if (tier === 'omitted') continue;
      // Un resultado que no responde a la llamada pendiente (ya respondida con
      // el sintético, o de otro thread) sería un tool_result sin tool_use.
      if (callId !== pending) continue;
      const result = compactToolResult(ev.payload, tier === 'full' ? MAX_TOOL_RESULT_CHARS : SUMMARY_PREVIEW_CHARS);
      messages.push({ role: 'tool', toolCallId: callId, name: ev.payload.name, result });
      pending = null;
      messages.push(...deferred);
      deferred = [];
    } else if (ev.type === 'thread.started') {
      emit({ role: 'user', content: `[task assigned by lead]: ${ev.payload.task}` });
    } else if (ev.type === 'subagent.reported') {
      emit({ role: 'user', content: `[sub-agent "${ev.payload.label}" reported back]: ${ev.payload.summary}` });
    } else if (ev.type === 'turn.checkpoint') {
      emit({ role: 'user', content: ev.payload.auto
        ? `[system checkpoint]: ${ev.payload.calls} tool calls in a row — continuing automatically, no need to acknowledge this, just keep working.`
        : `[system checkpoint]: you were automatically paused after ${ev.payload.calls} tool calls in a row, to avoid an unbounded loop — not because anything went wrong. If asked to continue, pick up exactly where you left off.` });
    }
  }
  closePending();

  // Bug real encontrado en vivo: una sesión arrancada SIN instrucción
  // inicial (campo vacío al hacer "Iniciar scan") deja `session.started`
  // como único evento, que no genera ningún mensaje — `messages` queda []
  // en el primer advance(). Con Groq/DeepSeek (OpenAI-compatible) esto
  // pasaba desapercibido porque el system prompt viaja como el primer
  // ítem DENTRO del array de mensajes (ver openaiCompatible.js), así que
  // igual llegaba con 1 elemento. Con Anthropic el system prompt va en un
  // parámetro separado (`system`), así que `messages` quedaba realmente
  // vacío — la API lo rechazó con 400: "messages: at least one message is
  // required". El guard va acá (no en un caso especial de session.started
  // arriba) para no duplicar mensajes cuando SÍ hay una instrucción real
  // — solo actúa si, después de todo el historial, no quedó nada.
  if (!messages.length) {
    messages.push({ role: 'user', content: 'Begin the engagement — check scope and any existing findings/recon first, then start working.' });
  }

  return messages;
}

// Nombre del idioma en INGLÉS a propósito — el system prompt entero está en
// inglés (más confiable con modelos chicos/locales que seguir instrucciones
// en otro idioma), esta línea solo le pide que el TEXTO QUE ESCRIBE (chat,
// reportes de sub-agente, hallazgos) sea en el idioma elegido por el
// pentester — nombres de tool y JSON quedan como están siempre.
const RESPONSE_LANGUAGE_NAMES = { es: 'Spanish (Español)', en: 'English' };

function buildSystemPrompt(project, thread, session, scopedTargetId = null) {
  const base = [
    'You are a senior penetration testing assistant working inside Flowdit, a pentest reporting tool.',
    `Current project: "${project.name}".`,
    // Sin esto el modelo no sabía que la sesión/sub-agente tenía un target
    // asignado — las tools ahora rechazan cualquier otro (ver assertTargetInScope).
    ...(scopedTargetId ? [`This ${thread.parent_thread_id ? 'sub-agent' : 'session'} is scoped to a single target: target_id "${scopedTargetId}". Only act against that target — tools refuse any other target_id.`] : []),
    `Always write your responses — chat messages, sub-agent reports, and every text field inside a proposed finding (name, description, remediation) — in ${RESPONSE_LANGUAGE_NAMES[session?.response_language] || RESPONSE_LANGUAGE_NAMES.es}. Tool names and JSON keys are never translated.`,
    'Always call get_targets_in_scope before proposing or attempting any action against a target — never act outside the authorized engagement scope. This is a hard boundary, not a matter of judgment, and it applies in every mode below.',
    'Call get_existing_findings and search_vuln_templates before writing up a new finding, to avoid duplicating existing work and to reuse standard descriptions/remediation text.',
    'Prefer reading the actual client-side source (fetch_page_source, search_page_source) over blind black-box probing when possible — understanding real code finds things pattern-matching against raw HTTP responses alone misses.',
    // Nivel 0/1 (lectura, recon pasivo) nunca requiere aprobación, con o sin
    // autonomous mode — esto vale siempre, para evitar que el modelo se
    // frene a preguntar por algo que ya puede hacer solo (encontrado en
    // revisión: el modelo se detuvo a esperar al pentester ante un target
    // mal configurado, en vez de investigar/reintentar por su cuenta).
    'For anything read-only or passive-recon (checking existing data, port scanning, fetching/reading page source, DNS enumeration) you never need to stop and ask — investigate, retry with a different approach, and self-correct obvious obstacles on your own before reporting back. Only pause to report when you are genuinely blocked with no remaining path forward, not merely because something is inconvenient or your first attempt failed.',
    // Encontrado en vivo (retest de EncuestaQR): "SOLO UN PÁRRAFO" devolvía
    // encabezado + negritas + un párrafo gigante + notas que nadie pidió, y
    // cada pedido de texto se respondía como una sección de informe entera.
    'Communication with the pentester: answer their LATEST message directly and concisely. When they specify a format, length or scope ("only one paragraph", "only finding B1", "just the Markdown text", "no explanations"), follow it literally — output exactly that and nothing else: no extra headings, status lines, notes, caveats, pending items or follow-up offers they did not ask for. A later instruction overrides an earlier one about format; a standing restriction (e.g. "do not edit anything") stays in force until the pentester lifts it explicitly.',
    // Mismo incidente: el agente pisó la remediación de 9 hallazgos con
    // evidencia del retest — no sabía qué era cada campo ni qué decía antes.
    'Editing findings: update_finding REPLACES each text field you pass. Before changing description, remediation or retest_notes, read the finding in full with get_existing_findings(finding_id) and only change what you were asked to. Field meaning: description = the issue; remediation = the fix recommendation for the client; retest results/verification evidence = retest_notes, plus remediation_status (open | remediated | not_remediated | verified_closed) and retest_date. Never put retest evidence in remediation or description.',
  ];

  // Patrones aprendidos de pentests reales anteriores (ver pentestKnowledge.js)
  // — crece con el tiempo a medida que se curan casos donde el agente se
  // salteó algo, independiente del provider usado en cada scan.
  if (pentestKnowledge.length) {
    base.push(
      'Additionally, proactively check for these patterns learned from past real engagements:\n' +
      pentestKnowledge.map(k => `- ${k.title}: ${k.check}`).join('\n')
    );
  }

  if (session?.ai_profile && PROFILE_GUIDANCE[session.ai_profile]) {
    base.push(PROFILE_GUIDANCE[session.ai_profile]);
  }

  if (project.ai_autonomous_requests) {
    base.push('Autonomous mode is ON for this project: active testing (send_http_request, test_payload, run_exploit_poc) and proposing findings (propose_finding) run immediately, with no human approval step — the pentester made this explicit trade-off knowingly. Work like an independent senior pentester conducting the engagement solo: keep going across many steps, try different approaches when one fails, and do not stop to ask permission for anything within the authorized scope. This does not relax the scope boundary above.');
  } else {
    base.push('You collaborate with a human pentester who reviews and approves your work — active testing (send_http_request, test_payload, run_exploit_poc) and every finding you propose or edit (propose_finding, update_finding) require their explicit approval before taking effect. That approval requirement is the only thing that should make you stop — it never applies to read-only/recon work.');
  }

  if (thread.parent_thread_id) {
    base.push('You are a sub-agent working on one task delegated to you by the lead. Focus only on that task, then give a clear final summary in plain text — that summary is the only thing the lead sees, so make it count.');
  } else if (project.ai_single_agent) {
    // delegate_to_subagent ni siquiera está en `tools` en este modo (ver
    // advance()) — se lo avisa igual acá para que no pierda tiempo
    // planeando delegar algo que no puede hacer.
    base.push('Single-agent mode is ON for this project: you work completely solo, one task at a time, with no sub-agent delegation available — the pentester chose this to stay within a low rate-limit/concurrency budget on the current AI provider. Break down and work through everything sequentially yourself instead.');
  } else {
    base.push('You can delegate independent, well-scoped tasks to sub-agent threads via delegate_to_subagent — use this when work naturally splits into parallel pieces (e.g. one thread per target). Sub-agents report back when done; you are not blocked waiting for them unless you choose to be.');
  }
  return base.join('\n');
}

// ── El loop ──────────────────────────────────────────────────────────────
// Se auto-invoca (recursión) mientras el modelo siga pidiendo tools sin
// gate; se detiene sola cuando responde con texto (turno terminado) o pide
// una tool que necesita gate (tier >= 2) — ahí queda esperando a
// resolveGatedCall(). Opera sobre UN thread; sesión y thread son guards
// independientes (ver el chequeo doble al principio).
async function advance(sessionId, threadId) {
  const gen = currentGeneration(threadId);
  const stale = () => currentGeneration(threadId) !== gen;

  // `error` de sesión ya no frena: lo que manda es el status del propio
  // thread (ver recomputeSessionStatus).
  const session = await getSession(sessionId);
  if (!session || session.status === 'paused' || session.status === 'completed') return;

  const thread = await getThread(threadId);
  if (!thread || thread.status !== 'running') return;

  const { rows: projectRows } = await db.query(`SELECT * FROM projects WHERE id=$1`, [session.project_id]);
  const project = projectRows[0];

  // Config de IA resuelta — la sesión pisa al proyecto campo por campo si
  // trae su propio valor (NULL = "usá lo del proyecto"). Booleans con `??`,
  // nunca `||`: un override explícito a `false` no puede perderse contra
  // un default `true` del proyecto. De acá para abajo, todo lo que antes
  // leía `project.ai_*` lee `effective.ai_*`.
  const effective = {
    ...project,
    ai_provider: session.ai_provider || project.ai_provider,
    ai_model: session.ai_model || project.ai_model,
    ai_tool_mode: session.ai_tool_mode || project.ai_tool_mode,
    ai_autonomous_requests: session.ai_autonomous_requests ?? project.ai_autonomous_requests,
    ai_single_agent: session.ai_single_agent ?? project.ai_single_agent,
  };

  const { rows: eventRows } = await db.query(
    `SELECT * FROM ai_scan_events WHERE session_id=$1 AND thread_id=$2 ORDER BY created_at, id`,
    [sessionId, threadId]
  );

  // "Por turno" = desde el último límite de turno (mensaje de chat de
  // cualquiera de los dos lados, checkpoint anterior, inicio del thread, o
  // reporte de un sub-agente) hasta ahora — NO desde el principio del
  // thread. Bug real encontrado junto con el fix de abajo: antes contaba
  // TODO el historial acumulado, así que una vez pisado el tope, el
  // checkpoint-resume de abajo hubiera vuelto a dispararse de inmediato
  // para siempre, sin dejar avanzar nunca más.
  let turnStart = 0;
  for (let i = eventRows.length - 1; i >= 0; i--) {
    const t = eventRows[i].type;
    if (t === 'chat.message' || t === 'turn.checkpoint' || t === 'thread.started' || t === 'subagent.reported') {
      turnStart = i + 1;
      break;
    }
  }
  const iterationsThisTurn = eventRows.slice(turnStart).filter(e => e.type === 'tool.called').length;

  // "Corrida" = igual que el turno pero SIN cortar en los checkpoints: en modo
  // autónomo los checkpoints se auto-continúan, así que si los frenos
  // anti-loop se reiniciaran en cada uno, la misma llamada podía repetirse
  // 3 veces cada 80 — hasta 18 veces seguidas antes de que alguien se entere.
  // Solo un mensaje del PENTESTER (o el inicio del sub-thread) abre corrida
  // nueva: un reporte de sub-agente o una respuesta del propio agente no,
  // si no el coordinador reiniciaba los topes con cada reporte que recibía.
  let runStart = 0;
  for (let i = eventRows.length - 1; i >= 0; i--) {
    const ev = eventRows[i];
    if ((ev.type === 'chat.message' && ev.payload.role === 'user') || ev.type === 'thread.started') {
      runStart = i + 1;
      break;
    }
  }
  const snapshotMaxId = eventRows.reduce((max, e) => Math.max(max, Number(e.id)), 0);

  if (iterationsThisTurn >= MAX_ITERATIONS_PER_TURN) {
    // Pedido explícito: "eso de decirle continuá también me parece
    // ridículo... la idea es que trabaje de manera autónoma mientras el
    // pentester hace sus cosas". Con `ai_autonomous_requests` activo, el
    // checkpoint YA NO espera a un humano — se cuenta a sí mismo y sigue de
    // largo solo. `MAX_AUTO_CHECKPOINTS` es el freno de última instancia
    // (evita que un modelo trabado en loop corra literalmente para
    // siempre sin que nadie se entere) — 5 checkpoints × 80 tool calls =
    // 400 tool calls de trabajo autónomo continuo antes de necesitar de
    // verdad un humano. En modo gated (default) el comportamiento no
    // cambió: siempre para y espera un mensaje de chat.
    let consecutiveCheckpoints = 0;
    for (let i = eventRows.length - 1; i >= 0; i--) {
      const t = eventRows[i].type;
      if (t === 'turn.checkpoint') { consecutiveCheckpoints++; continue; }
      // Mismos límites de turno que arriba — un mensaje real, un reporte de
      // sub-agente, o el inicio del thread cortan la cadena: es trabajo
      // nuevo, no el mismo loop repitiéndose.
      if (t === 'chat.message' || t === 'subagent.reported' || t === 'thread.started') break;
    }

    const willAutoContinue = effective.ai_autonomous_requests && consecutiveCheckpoints < MAX_AUTO_CHECKPOINTS;
    if (stale()) return;
    const ev = await persistEvent(sessionId, threadId, 'turn.checkpoint', { calls: iterationsThisTurn, auto: willAutoContinue });

    if (willAutoContinue) {
      // Sigue de largo — mismo thread, mismo status (`running`), sin
      // esperar a nadie. Nada que notificar acá: no es "importante",
      // es el agente pausando un instante para no acumular un turno
      // interminable en el historial.
      broadcast(session.project_id, sessionId, session.status, ev);
      if (stale()) return;
      return advance(sessionId, threadId);
    }

    // Para de verdad — modo gated, o se acabó el presupuesto de
    // auto-continues. Esto SÍ amerita avisar: es el único momento donde el
    // modo autónomo deja de trabajar solo y necesita que alguien mire.
    await setThreadStatus(threadId, 'idle');
    await recomputeSessionStatus(sessionId);
    const after = await getSession(sessionId);
    broadcast(session.project_id, sessionId, after.status, ev);

    if (thread.parent_thread_id) {
      // Sub-agente — nadie le manda chat directo para despertarlo (gap
      // documentado antes). En vez de dejarlo `idle` para siempre sin que
      // nadie se entere, reporta al padre como si hubiera terminado, con
      // una nota de que se quedó sin presupuesto — cierra el gap con el
      // mismo mecanismo que ya existe para un final normal.
      await reportToParent(session, thread, `[ran out of autonomous budget after ${consecutiveCheckpoints + 1} checkpoints (~${(consecutiveCheckpoints + 1) * MAX_ITERATIONS_PER_TURN} tool calls) before finishing — report what was found/attempted so far, the lead should review and decide whether to delegate more work]`);
    } else {
      await notifyNeedsAttention(session, project, attentionMessage(session, 'budget', { calls: (consecutiveCheckpoints + 1) * MAX_ITERATIONS_PER_TURN }));
    }
    return;
  }

  // Tope de gasto REAL en $ (ai_max_cost_usd) — a diferencia del checkpoint
  // de arriba (que frena por CANTIDAD de tool calls), esto frena por COSTO
  // ya incurrido (logUsage() en usage.js). Sin concepto de "auto-continue":
  // un tope en dinero es una decisión explícita del pentester al arrancar la
  // sesión, no algo que tenga sentido saltarse solo porque el modo autónomo
  // está prendido — a diferencia del checkpoint de iteraciones, que sí es
  // solo un freno de seguridad contra loops. `session.ai_max_cost_usd` (no
  // `effective`): es un override de sesión sin fallback a nivel proyecto,
  // igual que `ai_profile` más arriba.
  if (session.ai_max_cost_usd != null) {
    const { rows: costRows } = await db.query(
      `SELECT COALESCE(SUM(cost_usd), 0) AS spent FROM ai_usage WHERE session_id=$1`,
      [sessionId]
    );
    const spent = Number(costRows[0].spent) || 0;
    const cap = Number(session.ai_max_cost_usd);
    if (spent >= cap) {
      if (stale()) return;
      const ev = await persistEvent(sessionId, threadId, 'session.cost_cap_reached', { cap, spent });
      await setThreadStatus(threadId, 'idle');
      await recomputeSessionStatus(sessionId);
      const after = await getSession(sessionId);
      broadcast(session.project_id, sessionId, after.status, ev);
      if (thread.parent_thread_id) {
        await reportToParent(session, thread, `[stopped: this session's $${cap.toFixed(2)} cost cap was reached (spent $${spent.toFixed(4)}) — report what was found/attempted so far, the lead should review]`);
      } else {
        await notifyNeedsAttention(session, project, attentionMessage(session, 'cost', { cap: cap.toFixed(2), spent: spent.toFixed(4) }));
      }
      return;
    }
  }

  // Sub-agentes no ven delegate_to_subagent — un solo nivel de delegación.
  // Tampoco el coordinador si `ai_single_agent` está activo — sin esta
  // tool nunca se crea un segundo thread, así que nunca hay más de uno
  // `running` en toda la sesión (un thread solo ya es estrictamente
  // secuencial: cada advance() espera al proveedor antes de la próxima
  // tool call). Pedido explícito tras encontrar en vivo que Kimi K3 en
  // tier gratuito tiene Concurrency: 1 — sub-agentes en paralelo rompen eso
  // sin importar el RPM.
  const allowDelegation = !thread.parent_thread_id && !effective.ai_single_agent;
  const tools = allowDelegation ? [...BASE_TOOL_REGISTRY, DELEGATE_TOOL] : BASE_TOOL_REGISTRY;

  const scopedTargetId = scopedTargetIdFor(session, eventRows);

  const controller = new AbortController();
  activeAborts.set(threadId, controller);

  let result;
  try {
    result = await ai.chatWithTools(effective.ai_provider, {
      systemPrompt: buildSystemPrompt(effective, thread, session, scopedTargetId),
      messages: eventsToMessages(eventRows),
      tools,
      model: effective.ai_model || undefined,
      toolMode: effective.ai_tool_mode || 'native',
      project: effective,
      signal: controller.signal,
    });
  } catch (err) {
    // 'AbortError' (fetch nativo) / 'APIUserAbortError' (posible nombre del
    // SDK de Anthropic, no verificado) — cancelación intencional vía
    // interrupt(), que ya hizo la transición de estado; no tocar nada más.
    if (err.name === 'AbortError' || err.name === 'APIUserAbortError') return;
    // Otro loop ya tomó este thread — este error no es de él.
    if (stale()) return;
    console.error('agentLoop error:', err.message);
    // anthropic.js encadena el error real vía `{ cause: err }` — antes esto
    // solo leía err.message y lo perdía. openaiCompatible.js ya mete el
    // detalle directo en el mensaje, pero leer .cause acá también cubre
    // cualquier otro adaptador que use el patrón "correcto" de Node.
    const reason = err.cause?.message ? `${err.message}: ${err.cause.message}` : err.message;
    await failThread(session, thread, reason);
    return;
  } finally {
    if (activeAborts.get(threadId) === controller) activeAborts.delete(threadId);
  }

  // El scanner nunca logueaba su consumo — solo /ai/generate y /ai/chat lo
  // hacían (ver routes/ai.js). Encontrado en vivo: con el modo autónomo
  // haciendo muchos tool calls seguidos, sin esto no había forma de ver el
  // gasto acumulado en la tarjeta "AI Usage" de Settings, solo en la cuenta
  // real del proveedor. No await — no debe frenar ni poder tumbar el loop
  // (logUsage() ya es defensiva, nunca tira, pero mejor no depender de eso).
  logUsage({
    projectId: session.project_id, userId: session.started_by,
    provider: effective.ai_provider, model: result.model, action: 'scan',
    inputTokens: result.usage?.inputTokens || 0, outputTokens: result.usage?.outputTokens || 0,
    sessionId,
  });

  // Interrumpido/pausado mientras esperaba al proveedor: la respuesta ya no
  // corresponde a este loop.
  if (stale()) return;

  if (result.type === 'text') {
    const ev = await persistEvent(sessionId, threadId, 'chat.message', { role: 'assistant', text: result.text });
    if (thread.parent_thread_id) {
      // Sub-agente terminó su tarea delegada — reporta al padre y se cierra
      // (a diferencia del coordinador, que queda `idle` esperando más).
      await setThreadStatus(threadId, 'completed');
      await recomputeSessionStatus(sessionId);
      broadcast(session.project_id, sessionId, 'completed', ev);
      await reportToParent(session, thread, result.text);
    } else {
      await setThreadStatus(threadId, 'idle');
      await recomputeSessionStatus(sessionId);
      broadcast(session.project_id, sessionId, 'idle', ev);
      // Un reporte de sub-agente (o un mensaje del pentester) que llegó
      // mientras el proveedor respondía no despertó a nadie — el thread
      // estaba `running` — y esta respuesta no lo vio. Si quedó alguno
      // posterior al historial que se mandó, se sigue. El claim atómico evita
      // duplicar el loop si reportToParent/sendMessage también lo despiertan.
      const { rows: unseen } = await db.query(
        `SELECT 1 FROM ai_scan_events
         WHERE thread_id=$1 AND id > $2
           AND (type='subagent.reported' OR (type='chat.message' AND payload->>'role'='user'))
         LIMIT 1`,
        [threadId, snapshotMaxId]
      );
      if (unseen.length && await claimIdleThread(threadId)) {
        await recomputeSessionStatus(sessionId);
        if (stale()) return;
        return advance(sessionId, threadId);
      }
    }
    return;
  }

  const ctx = { projectId: session.project_id, startedBy: session.started_by, sessionId, threadId, scopedTargetId };
  const toolNames = tools.map(t => t.name).join(', ');

  for (const [callIndex, call] of result.toolCalls.entries()) {
    if (stale()) return;
    // Solo las tools OFRECIDAS en esta llamada: delegate_to_subagent no
    // existe para un sub-agente ni en modo single-agent aunque el modelo la
    // nombre igual (en modo texto lo puede escribir sin que se la ofrezcan).
    const tool = tools.find(t => t.name === call.name);
    const input = call.invalidArguments !== undefined
      ? { _invalid_arguments: clip(String(call.invalidArguments), 500) }
      : (call.input ?? {});

    const calledPayload = { name: call.name, input, tier: tool ? tool.tier : null };
    // reasoning_content va una sola vez por respuesta (en la primera
    // llamada); las demás llevan '' para que el campo siga presente.
    if (typeof result.reasoningContent === 'string') calledPayload.reasoning_content = callIndex === 0 ? result.reasoningContent : '';
    const calledEv = await persistEvent(sessionId, threadId, 'tool.called', calledPayload);
    eventRows.push(calledEv);

    // `calledEv` ya está en eventRows, así que los conteos incluyen esta
    // llamada: la firma exacta se bloquea en la 3ra, la ruta en la 16ta.
    // También aplica a tools desconocidas y argumentos inválidos: si no,
    // un modelo trabado repitiendo la misma llamada rota no frenaría nunca.
    const duplicateCount = countMatchingCalls(eventRows, runStart, toolCallSignature(call.name, input));
    const pathSig = pathReadSignature(call.name, input);
    const pathReads = pathSig ? countMatchingCalls(eventRows, runStart, pathSig, pathReadSignature) : 0;
    let blockedReason = null;
    if (duplicateCount >= MAX_DUPLICATE_CALLS_PER_TURN) {
      blockedReason = `Blocked: you already called ${call.name} with these exact same arguments ${duplicateCount} times in this run (not necessarily back to back — alternating with other calls does not reset this), always with the same result. Repeating it again will not produce new information — try a materially different approach (a different path, parameter, or technique), or if you've exhausted what this avenue has to offer, move on to something else or conclude with a summary of what you found.`;
    } else if (pathReads > MAX_PATH_READS_PER_RUN) {
      blockedReason = `Blocked: you already read ${normalizeEndpointPath(input.path)} on this target ${pathReads - 1} times in this run (query-string variants and pagination offsets count as the same path). Changing cache-busters, page sizes or offsets is not new attack surface. To look for something specific in a large file (JS bundle, source map), use search_page_source with a regex instead of paging through it. Otherwise move on to other paths, or conclude with a summary of what you found.`;
    } else if (!tool) {
      // Antes era un session.error fatal: un solo nombre mal escrito mataba
      // el thread. Como resultado de error, el modelo se corrige solo.
      blockedReason = `unknown tool "${call.name}" — it is not available to you here. Available tools: ${toolNames}`;
    } else if (call.invalidArguments !== undefined) {
      blockedReason = `invalid JSON arguments for ${call.name} — the arguments must be a single valid JSON object matching the tool's input schema. Call it again with valid JSON.`;
    } else if (tool.name === 'propose_finding') {
      // Antes de pedir aprobación: un duplicado no debería ni llegar al gate.
      const dup = await findDuplicateFinding(session.project_id, input);
      if (dup) blockedReason = `A finding named "${dup.name}" already exists for this target (id ${dup.id}) — it was not created again. Use update_finding with finding_id "${dup.id}" to add evidence or refine it.`;
    }
    if (blockedReason) {
      // Bloqueado antes de ejecutar — ni gasta el request real ni espera
      // aprobación de un gate para algo que ya sabemos que es un loop.
      broadcast(session.project_id, sessionId, session.status, calledEv);
      const resultEv = await persistEvent(sessionId, threadId, 'tool.result', {
        call_id: calledEv.id, name: call.name,
        result: { error: blockedReason },
      });
      eventRows.push(resultEv);
      broadcast(session.project_id, sessionId, session.status, resultEv);
      continue;
    }

    if (needsGate(tool, effective)) {
      await setThreadStatus(threadId, 'waiting_approval');
      await recomputeSessionStatus(sessionId);
      const after = await getSession(sessionId);
      broadcast(session.project_id, sessionId, after.status, calledEv);
      // "Está a punto de hacer algo importante" — el caso más directo:
      // literalmente se frenó a pedir permiso. No hace falta await, no
      // debe demorar el frenado real (ya pasó arriba).
      if (!thread.parent_thread_id) {
        notifyNeedsAttention(session, project, attentionMessage(session, 'approval', { tool: tool.name }))
          .catch(err => console.error('notifyNeedsAttention failed:', err.message));
      }
      return; // frena este thread — se retoma vía resolveGatedCall()
    }

    broadcast(session.project_id, sessionId, session.status, calledEv);

    let output;
    if (tool.name === 'propose_finding' || tool.name === 'update_finding') {
      // propose_finding/update_finding.execute() son stubs defensivos (solo
      // pensados para pasar por resolveGatedCall) — con ai_autonomous_requests
      // activo llegan directo hasta acá sin gate, así que la escritura se
      // hace acá mismo, con el mismo shape { decision, created_vuln_id } que
      // produce resolveGatedCall, para que cualquier consumidor futuro del
      // evento (o vos leyéndolo) lo entienda igual sea gated o autónomo.
      try {
        const vulnId = tool.name === 'propose_finding'
          ? await createFindingFromProposal(session.project_id, input, session.started_by, session.id)
          : await updateFindingFromProposal(session.project_id, input, session.started_by);
        output = { decision: 'accepted', created_vuln_id: vulnId };
      } catch (err) {
        output = { decision: 'accepted', error: `failed to ${tool.name === 'propose_finding' ? 'create' : 'update'} finding: ${err.message}` };
      }
    } else {
      try {
        output = await tool.execute(input, ctx);
      } catch (err) {
        output = { error: err.message };
      }
    }
    // El resultado se persiste aunque este loop haya quedado viejo: la tool
    // YA corrió (el request llegó al target) y el log es también auditoría.
    // Si otro loop ya tomó el thread, eventsToMessages ubica o descarta este
    // resultado sin romper el pareo; lo que no se hace es seguir el loop.
    const resultEv = await persistEvent(sessionId, threadId, 'tool.result', { call_id: calledEv.id, name: tool.name, result: output });
    broadcast(session.project_id, sessionId, session.status, resultEv);
    if (stale()) return;
  }

  if (stale()) return;
  return advance(sessionId, threadId);
}

// Thread idle → running de forma atómica; true si este caller lo despertó.
// Varios disparadores (reporte de sub-agente, mensaje del pentester, el
// propio loop al terminar) pueden intentar despertarlo a la vez.
async function claimIdleThread(threadId) {
  const { rows } = await db.query(
    `UPDATE ai_scan_threads SET status='running' WHERE id=$1 AND status='idle' RETURNING id`,
    [threadId]
  );
  return rows.length > 0;
}

// Target al que está acotado un thread: el del sub-agente (thread.started)
// o, si no tiene, el de la sesión. null = todo el scope del proyecto.
function scopedTargetIdFor(session, eventRows) {
  const started = eventRows.find(e => e.type === 'thread.started');
  return started?.payload?.target_id || session.target_id || null;
}

async function loadScopedTargetId(session, threadId) {
  const { rows } = await db.query(
    `SELECT * FROM ai_scan_events WHERE thread_id=$1 AND type='thread.started' ORDER BY id LIMIT 1`,
    [threadId]
  );
  return scopedTargetIdFor(session, rows);
}

// Un thread que muere en error. Si es un sub-agente, el coordinador se
// entera por un reporte (si no, lo esperaba para siempre) y decide.
async function failThread(session, thread, reason) {
  const ev = await persistEvent(session.id, thread.id, 'session.error', { reason });
  await setThreadStatus(thread.id, 'error');
  await recomputeSessionStatus(session.id);
  const after = await getSession(session.id);
  broadcast(session.project_id, session.id, after?.status || 'error', ev);
  if (thread.parent_thread_id) {
    await reportToParent(session, thread, `[failed: this sub-agent stopped with an error before finishing — ${reason}. Whatever it did before the error is still recorded (findings, recon); decide whether to delegate the task again or move on]`);
  }
}

// Todo advance() que no se awaitea pasa por acá: un throw fuera del
// try/catch del proveedor (DB caída, bug) antes era una promesa rechazada
// sin atrapar, que puede tumbar el proceso. Marca el thread en error, salvo
// que otro loop ya lo haya tomado.
function advanceSafely(sessionId, threadId) {
  const gen = currentGeneration(threadId);
  activeLoops.set(threadId, (activeLoops.get(threadId) || 0) + 1);
  return advance(sessionId, threadId)
    .catch(async err => {
      console.error('agentLoop.advance failed:', err.message);
      try {
        if (currentGeneration(threadId) !== gen) return;
        const [session, thread] = await Promise.all([getSession(sessionId), getThread(threadId)]);
        if (session && thread && thread.status === 'running') await failThread(session, thread, `internal error: ${err.message}`);
      } catch (e) {
        console.error('agentLoop: could not mark thread as error:', e.message);
      }
    })
    .finally(() => {
      const n = (activeLoops.get(threadId) || 1) - 1;
      if (n > 0) activeLoops.set(threadId, n); else activeLoops.delete(threadId);
    });
}

function launchAdvance(sessionId, threadId) {
  advanceSafely(sessionId, threadId); // no await — corre en background, errores ya atrapados
}

// Cuando un sub-agente termina, deja un evento en el thread PADRE contando
// qué encontró (no comparten historial completo — el padre solo ve este
// resumen, igual que un lead que recibe el reporte de un pentester del
// equipo, no la transcripción entera de su trabajo). Si el padre estaba
// `idle` esperando, lo despierta. Persiste ANTES de mirar el status del
// padre: si el padre está terminando su turno justo ahora, o ve este
// reporte al pasar a idle (ver advance()), o lo ve idle acá.
async function reportToParent(session, thread, summary) {
  const parent = await getThread(thread.parent_thread_id);
  if (!parent) return;
  const ev = await persistEvent(session.id, parent.id, 'subagent.reported', { label: thread.label, thread_id: thread.id, summary });
  const after = await getSession(session.id);
  broadcast(session.project_id, session.id, after.status, ev);

  if (await claimIdleThread(parent.id)) {
    await recomputeSessionStatus(session.id);
    launchAdvance(session.id, parent.id);
  }
}

// ── delegate_to_subagent ─────────────────────────────────────────────────
// Vive acá, no en un scanTools*.js, porque necesita orquestar (crear un
// thread, arrancar su propio loop) — no solo hacer una query. tier: 1,
// delegar en sí no es destructivo; lo que el sub-agente haga después sigue
// pasando por sus propios gates de Nivel 2/3, de forma independiente.
const DELEGATE_TOOL = {
  name: 'delegate_to_subagent',
  tier: 1,
  description:
    'Delegate an independent, well-scoped task to a new sub-agent thread ' +
    'that works in parallel with you — like assigning it to another ' +
    'pentester on your team. Use this when work naturally splits into ' +
    'independent pieces (e.g. one thread per target, or "recon this while I ' +
    'analyze that"). The sub-agent has the same tools you do and reports ' +
    'back when it finishes — you are not blocked waiting for it, keep ' +
    'working on other things. Only available to you as the lead; sub-agents ' +
    'cannot delegate further (one level only). Give it a clear, ' +
    'self-contained task description — it does not see your conversation, ' +
    'only what you write here.',
  input_schema: {
    type: 'object',
    properties: {
      task: { type: 'string', description: 'A clear, self-contained task description' },
      target_id: { type: 'string', description: 'Optional — scope the sub-agent to one target' },
    },
    required: ['task'],
  },
  async execute(input, ctx) {
    const caller = await getThread(ctx.threadId);
    if (caller.parent_thread_id) {
      return { error: 'sub-agent threads cannot delegate further (one level of delegation only)' };
    }
    if (typeof input.task !== 'string' || !input.task.trim()) {
      return { error: 'task is required' };
    }
    // Un sub-agente no puede salirse del target de la sesión, y su target
    // tiene que existir en el proyecto (si no, quedaba "acotado" a nada).
    let targetId = input.target_id || null;
    if (targetId) {
      if (ctx.scopedTargetId && targetId !== ctx.scopedTargetId) {
        return { error: `this session is scoped to target_id "${ctx.scopedTargetId}" — a sub-agent cannot be assigned another target` };
      }
      if (!(await targetBelongsToProject(targetId, ctx.projectId))) {
        return { error: 'target_id does not belong to this project' };
      }
    } else {
      targetId = ctx.scopedTargetId || null;
    }
    // Tope de fan-out: sin esto un modelo podía crear sub-agentes sin límite,
    // cada uno con su propio loop pagando llamadas al proveedor en paralelo.
    const { rows: counts } = await db.query(
      `SELECT COUNT(*) FILTER (WHERE status IN ('running','waiting_approval'))::int AS active, COUNT(*)::int AS total
       FROM ai_scan_threads WHERE session_id=$1 AND parent_thread_id IS NOT NULL`,
      [ctx.sessionId]
    );
    if (counts[0].active >= MAX_ACTIVE_SUBAGENTS) {
      return { error: `too many active sub-agents (${counts[0].active}, max ${MAX_ACTIVE_SUBAGENTS}) — wait for some to report back before delegating more, or do this task yourself` };
    }
    if (counts[0].total >= MAX_TOTAL_SUBAGENTS) {
      return { error: `sub-agent limit reached for this session (${MAX_TOTAL_SUBAGENTS} in total) — do the remaining work yourself` };
    }
    const { rows } = await db.query(
      `INSERT INTO ai_scan_threads (session_id, parent_thread_id, label, status) VALUES ($1,$2,$3,'running') RETURNING *`,
      [ctx.sessionId, ctx.threadId, input.task.slice(0, 200)]
    );
    const newThread = rows[0];
    const session = await getSession(ctx.sessionId);
    const ev = await persistEvent(ctx.sessionId, newThread.id, 'thread.started', { task: input.task, target_id: targetId });
    broadcast(session.project_id, ctx.sessionId, session.status, ev);
    launchAdvance(ctx.sessionId, newThread.id); // corre en paralelo al caller
    return { thread_id: newThread.id, status: 'started' };
  },
};

// ── Gates (Nivel 2/3) ────────────────────────────────────────────────────
// Crea el hallazgo real a partir de los campos que la IA propuso vía
// propose_finding. Duplica a propósito el shape del INSERT que usa
// POST /vulns (evita acoplar agentLoop.js a la capa HTTP).
// client_visible is deliberately never written here (nor in
// updateFindingFromProposal): publishing to the client portal is a lead-only
// action (owner/editor) done by a human, so an agent run by a pentester — or by
// anyone — can never publish a finding. New rows get the column default (false).
// Encontrado en vivo: el agente proponía el mismo hallazgo varias veces (en
// turnos distintos, o desde sub-agentes en paralelo). Mismo nombre ignorando
// mayúsculas y espacios, mismo proyecto y mismo target = el mismo hallazgo.
async function findDuplicateFinding(projectId, input) {
  if (typeof input?.name !== 'string' || !input.name.trim()) return null;
  const targetId = await targetBelongsToProject(input.target_id || null, projectId);
  const { rows } = await db.query(
    `SELECT id, name FROM custom_vulns
     WHERE project_id=$1 AND target_id IS NOT DISTINCT FROM $2
       AND lower(btrim(regexp_replace(name, '\\s+', ' ', 'g'))) = lower(btrim(regexp_replace($3, '\\s+', ' ', 'g')))
     ORDER BY created_at LIMIT 1`,
    [projectId, targetId, input.name]
  );
  return rows[0] || null;
}

async function createFindingFromProposal(projectId, input, approvedBy, sessionId = null) {
  const validTargetId = await targetBelongsToProject(input.target_id || null, projectId);
  const { rows } = await db.query(
    `INSERT INTO custom_vulns
       (project_id, name, category, severity, description, remediation, cwe, cvss_vector, cvss_score, http_proofs, target_id, created_by, updated_by, ai_generated, session_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,true,$13) RETURNING id`,
    [
      projectId, input.name, input.category || 'Custom', input.severity || 'medium',
      input.description || '', input.remediation || '', input.cwe || null,
      input.cvss_vector || null, input.cvss_score || null, JSON.stringify(input.http_proofs || []),
      validTargetId, approvedBy || null, sessionId,
    ]
  );

  // Mismo evento de Activity que ya dispara POST /vulns al crear un
  // hallazgo a mano, PERO con meta.ai_generated para que el feed lo marque
  // distinto — pedido explícito: en un entorno colaborativo, que el feed
  // diga "dvalencia added custom vuln X" sin más hace parecer que X lo
  // escribió a mano, cuando lo encontró el agente y dvalencia solo aprobó.
  // El actor sigue siendo quien aprobó (ese dato sigue importando en un
  // equipo), el badge de acá al lado es lo que distingue el origen — ver
  // actionLabel() en utils.js. No await: no debe demorar ni poder tumbar
  // el flujo que llamó a esta función (resolveGatedCall / el auto-exec de
  // advance()).
  if (approvedBy) {
    getUserRow(approvedBy).then(actor => {
      if (!actor) return;
      activity.log({
        projectId, user: actor, action: 'vuln_created', entityType: 'custom_vuln',
        entityId: rows[0].id, entityName: input.name, meta: { severity: input.severity, ai_generated: true },
      });
    }).catch(err => console.error('activity.log (finding del agente) failed:', err.message));
  }

  return rows[0].id;
}

// Contraparte de createFindingFromProposal para update_finding — edita un
// hallazgo YA existente en vez de crear uno nuevo (ver el tool para el
// porqué: sin esto, "agregale los proofs" solo podía resolverse duplicando
// el hallazgo). Solo toca los campos que vinieron en `input`; http_proofs
// se agrega a lo que ya tenía la fila, nunca lo reemplaza — el modelo no
// tiene forma confiable de saber qué proofs ya existen (get_existing_findings
// no los devuelve), así que "reemplazar" perdería evidencia por las dudas.
const REMEDIATION_STATUSES = ['open', 'remediated', 'not_remediated', 'verified_closed'];

async function updateFindingFromProposal(projectId, input, approvedBy) {
  const { rows: existing } = await db.query(
    `SELECT http_proofs, remediation_status, name FROM custom_vulns WHERE id=$1 AND project_id=$2`,
    [input.finding_id, projectId]
  );
  if (!existing.length) throw new Error('finding not found in this project');

  // Explicit allowlist — client_visible must never be added here (see
  // createFindingFromProposal).
  const fields = ['name', 'category', 'severity', 'description', 'remediation', 'cwe', 'cvss_vector', 'cvss_score', 'retest_date', 'retest_notes'];
  const sets = [], values = [];
  fields.forEach(f => {
    if (input[f] !== undefined) { values.push(input[f]); sets.push(`${f}=$${values.length}`); }
  });
  if (input.http_proofs?.length) {
    const merged = [...(existing[0].http_proofs || []), ...input.http_proofs];
    values.push(JSON.stringify(merged));
    sets.push(`http_proofs=$${values.length}`);
  }

  // Pedido explícito: en un retest el agente decía "no puedo marcarlo como
  // remediado, update_finding no expone remediation_status". Misma lógica de
  // auditoría que PATCH /vulns/:id/remediation (routes/vulns.js) — los
  // timestamps solo se tocan si el estado realmente cambia, y
  // `verified_by` es quien aprobó el gate: el cierre lo sigue firmando un
  // humano, no el agente.
  let statusChanged = false;
  if (input.remediation_status !== undefined) {
    if (!REMEDIATION_STATUSES.includes(input.remediation_status)) {
      throw new Error(`invalid remediation_status: ${input.remediation_status}`);
    }
    values.push(input.remediation_status);
    sets.push(`remediation_status=$${values.length}`);
    statusChanged = existing[0].remediation_status !== input.remediation_status;
    if (statusChanged) {
      if (input.remediation_status === 'remediated') {
        sets.push(`remediated_at=NOW()`, `verified_at=NULL`, `verified_by=NULL`);
      } else if (input.remediation_status === 'verified_closed') {
        values.push(approvedBy || null);
        sets.push(`verified_at=NOW()`, `verified_by=$${values.length}`);
      } else {
        sets.push(`remediated_at=NULL`, `verified_at=NULL`, `verified_by=NULL`);
      }
    }
  }
  if (!sets.length) return input.finding_id; // nada que cambiar

  values.push(approvedBy || null);
  sets.push(`updated_by=$${values.length}`);
  values.push(input.finding_id);
  await db.query(`UPDATE custom_vulns SET ${sets.join(', ')}, updated_at=NOW() WHERE id=$${values.length}`, values);

  // Mismo evento de Activity que el cambio manual, marcado como del agente
  // (ver createFindingFromProposal). No await — mismo motivo que allá.
  if (statusChanged && approvedBy) {
    getUserRow(approvedBy).then(actor => {
      if (!actor) return;
      activity.log({
        projectId, user: actor, action: 'remediation_status_changed', entityType: 'custom_vuln',
        entityId: input.finding_id, entityName: input.name || existing[0].name,
        meta: { remediation_status: input.remediation_status, ai_generated: true },
      });
    }).catch(err => console.error('activity.log (remediación del agente) failed:', err.message));
  }
  return input.finding_id;
}

// Se llama cuando el pentester aprueba/rechaza una tool call en gate. El
// thread se deriva del propio evento tool.called (calledEv.thread_id) — el
// caller (ws.js) no necesita saber a qué thread pertenece un call_id.
// Idempotente: ignora si ese call_id ya tiene un tool.result, o si no es la
// llamada que el thread está esperando.
async function resolveGatedCall(sessionId, callId, decision, userId, extra = {}) {
  const { rows: callRows } = await db.query(
    `SELECT * FROM ai_scan_events WHERE id=$1 AND session_id=$2 AND type='tool.called'`,
    [callId, sessionId]
  );
  const calledEv = callRows[0];
  if (!calledEv) return;

  const threadId = calledEv.thread_id;
  const { rows: existingResult } = await db.query(
    `SELECT 1 FROM ai_scan_events WHERE session_id=$1 AND type='tool.result' AND payload->>'call_id'=$2`,
    [sessionId, String(callId)]
  );
  if (existingResult.length) return;
  // Solo la ÚLTIMA llamada del thread puede ser la que espera aprobación —
  // una más vieja sin resultado quedó huérfana, aprobarla no corresponde.
  const { rows: laterCalls } = await db.query(
    `SELECT 1 FROM ai_scan_events WHERE thread_id=$1 AND type='tool.called' AND id > $2 LIMIT 1`,
    [threadId, calledEv.id]
  );
  if (laterCalls.length) return;

  // Claim atómico: antes era chequear-y-después-actuar, y dos aprobaciones
  // casi simultáneas (doble click, dos pestañas, dos pentesters) ejecutaban
  // la tool dos veces. Solo quien pasa el thread de waiting_approval a
  // running sigue; el thread ya queda `running` mientras la tool corre.
  const { rows: claimed } = await db.query(
    `UPDATE ai_scan_threads SET status='running' WHERE id=$1 AND status='waiting_approval' RETURNING id`,
    [threadId]
  );
  if (!claimed.length) return;
  await recomputeSessionStatus(sessionId);

  const session = await getSession(sessionId);
  const tool = findTool(calledEv.payload.name);
  let output;
  if (decision === 'rejected') {
    output = { decision: 'rejected', reason: extra.reason || null };
  } else if (tool.tier === 3) {
    if (extra.created_vuln_id) {
      // Vino de "Editar y agregar" — ya se creó por POST /vulns, solo confirmamos.
      // (Solo existe para propose_finding — update_finding no tiene un flujo
      // de edición previa propio, se acepta o se rechaza tal cual.)
      output = { decision: 'accepted', created_vuln_id: extra.created_vuln_id };
    } else {
      // Pudo crearse uno igual mientras esperaba aprobación.
      const dup = calledEv.payload.name === 'propose_finding' ? await findDuplicateFinding(session.project_id, calledEv.payload.input) : null;
      if (dup) {
        output = { decision: 'accepted', error: `A finding named "${dup.name}" already exists for this target (id ${dup.id}) — it was not created again. Use update_finding with finding_id "${dup.id}" to add evidence or refine it.` };
      } else {
        try {
          const vulnId = calledEv.payload.name === 'propose_finding'
            ? await createFindingFromProposal(session.project_id, calledEv.payload.input, userId, session.id)
            : await updateFindingFromProposal(session.project_id, calledEv.payload.input, userId);
          output = { decision: 'accepted', created_vuln_id: vulnId };
        } catch (err) {
          output = { decision: 'accepted', error: `failed to ${calledEv.payload.name === 'propose_finding' ? 'create' : 'update'} finding: ${err.message}` };
        }
      }
    }
  } else {
    try {
      const scopedTargetId = await loadScopedTargetId(session, threadId);
      output = { decision: 'accepted', result: await tool.execute(calledEv.payload.input, { projectId: session.project_id, startedBy: session.started_by, sessionId, threadId, scopedTargetId }) };
    } catch (err) {
      output = { decision: 'accepted', error: err.message };
    }
  }

  const resultEv = await persistEvent(sessionId, threadId, 'tool.result', { call_id: callId, name: calledEv.payload.name, ...output }, userId || null);
  const after = await getSession(sessionId);
  broadcast(session.project_id, sessionId, after.status, resultEv);
  return advanceSafely(sessionId, threadId);
}

// ── Pause / resume / interrupt / chat ───────────────────────────────────
// pause/resume son a nivel SESIÓN (afectan a todos los threads a la vez).
// interrupt/sendMessage apuntan al thread primario — el que "habla" con el
// pentester; los sub-agentes no reciben mensajes directos del humano en
// esta versión, solo del thread que los delegó, vía reportToParent().

async function interrupt(sessionId) {
  const primary = await getPrimaryThread(sessionId);
  if (!primary) return;
  // Bump antes de abortar: el loop en curso (esperando al proveedor o
  // ejecutando una tool) abandona en su próximo chequeo.
  bumpGeneration(primary.id);
  const controller = activeAborts.get(primary.id);
  if (controller) controller.abort();
  // Transición atómica — mismo motivo que en la versión de un solo thread:
  // evita que dos advance() terminen corriendo en paralelo para el mismo
  // thread si el catch(AbortError) y esto se pisan en el orden equivocado.
  await db.query(`UPDATE ai_scan_threads SET status='idle' WHERE id=$1 AND status='running'`, [primary.id]);
  await recomputeSessionStatus(sessionId);
}

async function pause(sessionId) {
  const session = await getSession(sessionId);
  if (!session || session.status === 'paused') return;
  await setSessionStatus(sessionId, 'paused');
  // Aborta cualquier llamada al proveedor en vuelo, en TODOS los threads de
  // la sesión. Sin esto, pause() solo cambia el status — el guard de
  // `advance()` se chequea una vez al principio, no a mitad de una llamada
  // ya en curso, así que esa llamada seguía terminando sola. Si el
  // pentester pausaba y reanudaba rápido, `resume()` volvía a llamar
  // `advance()` sobre el mismo thread mientras la llamada original todavía
  // podía estar en vuelo — dos `advance()` corriendo en paralelo sobre el
  // mismo thread (encontrado en revisión). El thread queda con su status
  // tal cual estaba (típicamente `running`) — abortar no lo cambia, así
  // que `resume()` lo retoma solo, leyendo el historial ya persistido.
  const { rows: threads } = await db.query(`SELECT id FROM ai_scan_threads WHERE session_id=$1`, [sessionId]);
  threads.forEach(t => { bumpGeneration(t.id); activeAborts.get(t.id)?.abort(); });
  broadcast(session.project_id, sessionId, 'paused', { type: 'session.paused', payload: {}, created_at: new Date().toISOString() });
}

async function resume(sessionId) {
  const session = await getSession(sessionId);
  if (!session || session.status !== 'paused') return;
  // Bug real: recomputeSessionStatus() se niega a tocar una sesión 'paused'
  // (guard pensado para que un thread terminando en simultáneo no pise un
  // pause explícito) — pero acá es EXACTAMENTE lo que resume() necesita
  // forzar. Sin este set previo, recomputeSessionStatus vuelve a leer la
  // sesión, la ve todavía 'paused', y no hace nada — la sesión quedaba
  // 'paused' para siempre, y de ahí en más tanto advance() como
  // sendMessage() la bloqueaban (return inmediato en su guard de arriba):
  // "resume" no reanudaba nada, ni dejaba mandar un mensaje de chat.
  await setSessionStatus(sessionId, 'idle');
  await recomputeSessionStatus(sessionId); // ahora sí recalcula desde los threads reales (running/waiting_approval/idle/error)
  const after = await getSession(sessionId);
  broadcast(session.project_id, sessionId, after.status, { type: 'session.resumed', payload: {}, created_at: new Date().toISOString() });
  const { rows: runningThreads } = await db.query(`SELECT id FROM ai_scan_threads WHERE session_id=$1 AND status='running'`, [sessionId]);
  runningThreads.forEach(t => launchAdvance(sessionId, t.id));
}

// Bug real (retest de EncuestaQR): la API se quedó sin fondos, la llamada
// al proveedor falló, el thread pasó a `error` y la sesión quedó muerta
// para siempre — recargar fondos no servía de nada. `error` solo nace de
// un fallo al hablar con el proveedor (fondos, rate limit, red, key), y
// advance() es una función pura del historial persistido: reintentar es
// simplemente volver a llamarla. Revive TODOS los threads en `error`: el
// primario pasa a `primaryStatus`, los sub-agentes directo a `running`.
// No lanza nada — cada caller relanza lo que corresponde. Devuelve cuántos
// threads revivió.
async function reviveErroredThreads(session, primaryId, primaryStatus) {
  const { rows: revived } = await db.query(
    `UPDATE ai_scan_threads SET status = CASE WHEN id=$2 THEN $3 ELSE 'running' END
     WHERE session_id=$1 AND status='error' RETURNING id, status`,
    [session.id, primaryId, primaryStatus]
  );
  if (!revived.length) return 0;
  await recomputeSessionStatus(session.id);
  return revived.length;
}

// Threads `running` sin ningún loop vivo — los revividos recién, o los que
// quedaron trabados (p.ej. despertados mientras la sesión estaba en error).
async function relaunchStalledThreads(sessionId) {
  const { rows } = await db.query(`SELECT id FROM ai_scan_threads WHERE session_id=$1 AND status='running'`, [sessionId]);
  const stalled = rows.filter(t => !activeLoops.has(t.id));
  stalled.forEach(t => launchAdvance(sessionId, t.id));
  return stalled.length;
}

// Botón "Reintentar" — mismo revive que un mensaje de chat, pero sin
// mensaje nuevo: el primario vuelve directo a `running` y retoma el turno
// que falló, leyendo el historial ya persistido. Relanza TODO thread que
// debería estar corriendo, el primario incluido, no solo los revividos.
async function retry(sessionId) {
  const session = await getSession(sessionId);
  if (!session || session.status === 'paused') return;
  const primary = await getPrimaryThread(sessionId);
  if (!primary) return;
  const revived = await reviveErroredThreads(session, primary.id, 'running');
  const relaunched = await relaunchStalledThreads(sessionId);
  if (!revived && !relaunched) return;
  const after = await getSession(sessionId);
  broadcast(session.project_id, sessionId, after.status, { type: 'session.resumed', payload: {}, created_at: new Date().toISOString() });
}

// Mensaje de chat del pentester — siempre al thread primario. Bloqueado si
// la sesión está `paused`, o si el thread primario específicamente está
// `waiting_approval` (resolver ESE gate es la prioridad) — un gate en un
// sub-agente no bloquea seguir hablando con el coordinador.
async function sendMessage(sessionId, userId, text) {
  let session = await getSession(sessionId);
  if (!session || session.status === 'paused') return false;

  let primary = await getPrimaryThread(sessionId);
  if (!primary || primary.status === 'waiting_approval') return false;

  // El primario vuelve a `idle` — el camino de abajo lo pone en `running`
  // junto con el mensaje nuevo.
  if (await reviveErroredThreads(session, primary.id, 'idle')) {
    session = await getSession(sessionId);
    primary = await getPrimaryThread(sessionId);
  }

  // Sesión arrancada sin instrucción inicial (name sigue NULL) — se
  // auto-nombra recién con el primer chat real. El guard hace que esto
  // solo corra una vez; de ahí en más solo un rename manual lo cambia.
  if (!session.name) {
    await db.query(`UPDATE ai_scan_sessions SET name=$2 WHERE id=$1`, [sessionId, deriveSessionName(text)]);
  }

  const ev = await persistEvent(sessionId, primary.id, 'chat.message', { role: 'user', text }, userId);

  // Persistir ANTES de despertar, con claim atómico: si el primario está
  // terminando su turno justo ahora, o ve este mensaje al pasar a idle (ver
  // advance()) o lo despierta este claim — el mensaje nunca se pierde.
  const wakesPrimary = await claimIdleThread(primary.id);
  if (wakesPrimary) {
    bumpGeneration(primary.id);
    await recomputeSessionStatus(sessionId);
  }
  // Broadcast DESPUÉS de pasar a `running` — antes salía con el status viejo
  // (`idle`), y la burbuja de "escribiendo..." del frontend recién aparecía
  // con el primer evento del agente, no al mandar el mensaje.
  const after = await getSession(sessionId);
  broadcast(session.project_id, sessionId, after.status, ev);
  if (wakesPrimary) launchAdvance(sessionId, primary.id);
  // Sub-agentes revividos arriba (o trabados) — el primario ya se lanzó.
  await relaunchStalledThreads(sessionId);
  return true;
}

// Bug real encontrado en vivo: un `advance()` en curso vive PURO en memoria
// — se auto-invoca por recursión (`return advance(...)`), no hay
// setInterval ni cola persistente manejándolo desde afuera. Si el backend
// se reinicia a mitad de un turno (crash, deploy, `docker compose restart`),
// esa cadena recursiva muere con el proceso, pero el thread queda con
// status='running' en la DB para siempre — nada la vuelve a mover. La
// sesión se ve "CORRIENDO" en la UI indefinidamente aunque no haya ningún
// proceso trabajándola. Se llama una sola vez al arrancar el server (ver
// index.js). Es seguro relanzar advance() así porque es una función pura
// del historial persistido (ver el comentario al principio del archivo) —
// no se perdió ningún estado en memoria aparte del propio call stack, así
// que retomar es simplemente volver a llamarla.
async function resumeOrphanedThreads() {
  const { rows } = await db.query(
    `SELECT t.id AS thread_id, t.session_id
     FROM ai_scan_threads t
     JOIN ai_scan_sessions s ON s.id = t.session_id
     WHERE t.status = 'running' AND s.status NOT IN ('paused', 'completed')`
  );
  for (const row of rows) launchAdvance(row.session_id, row.thread_id);
  return rows.length;
}

module.exports = {
  eventsToMessages, launchAdvance,
  advance, resolveGatedCall, pause, resume, retry, sendMessage, interrupt,
  createSessionWithPrimaryThread, getPrimaryThread, sessionBelongsToProject,
  resumeOrphanedThreads,
  // exported for tests (client_visible can't be set through the agent)
  createFindingFromProposal, updateFindingFromProposal,
};
