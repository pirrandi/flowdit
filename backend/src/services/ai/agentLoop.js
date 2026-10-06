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
const { scanToolsLevel1 }  = require('./scanToolsLevel1');
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

// Cuenta cuántas llamadas con esta firma exacta ya hubo en el turno actual
// (desde `turnStart`, no desde el principio del thread) — en cualquier
// posición, no solo las inmediatamente anteriores.
function countDuplicatesInTurn(eventRows, turnStart, signature) {
  let count = 0;
  for (let i = turnStart; i < eventRows.length; i++) {
    if (eventRows[i].type !== 'tool.called') continue;
    if (toolCallSignature(eventRows[i].payload.name, eventRows[i].payload.input) === signature) count++;
  }
  return count;
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

function findTool(name) {
  if (name === 'delegate_to_subagent') return DELEGATE_TOOL;
  return BASE_TOOL_REGISTRY.find(t => t.name === name);
}

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
// thread. No pisa un `paused` (override explícito del pentester) ni un
// `error` a nivel sesión.
async function recomputeSessionStatus(sessionId) {
  const session = await getSession(sessionId);
  if (!session || session.status === 'paused' || session.status === 'error') return;

  const { rows: threads } = await db.query(`SELECT status FROM ai_scan_threads WHERE session_id=$1`, [sessionId]);
  if (!threads.length) return;

  let next;
  if (threads.some(t => t.status === 'waiting_approval')) next = 'waiting_approval';
  else if (threads.some(t => t.status === 'running'))      next = 'running';
  else if (threads.some(t => t.status === 'error'))        next = 'error';
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

  const messages = [];
  for (const ev of events) {
    if (ev.type === 'chat.message') {
      let text = ev.payload.text;
      if (ev.payload.role === 'assistant') {
        assistantSeen++;
        if (assistantTotal - assistantSeen >= KEEP_FULL_ASSISTANT_MESSAGES) text = clip(text || '', OLD_ASSISTANT_MESSAGE_CHARS);
      }
      messages.push({ role: ev.payload.role, content: text });
    } else if (ev.type === 'tool.called') {
      const tier = tierOf(ev.id);
      if (tier === 'omitted') {
        if (!omittedNoted) {
          omittedNoted = true;
          messages.push({ role: 'user', content: `[system note]: ${summarizedFrom} earlier tool calls were omitted from this history to save context. Their effects (findings, data) still exist — re-run a read-only tool if you need that information again.` });
        }
        continue;
      }
      messages.push({ role: 'assistant', toolCalls: [{ id: String(ev.id), name: ev.payload.name, input: tier === 'full' ? ev.payload.input : compactToolInput(ev.payload.input) }] });
    } else if (ev.type === 'tool.result') {
      const tier = tierOf(ev.payload.call_id);
      if (tier === 'omitted') continue;
      const result = compactToolResult(ev.payload, tier === 'full' ? MAX_TOOL_RESULT_CHARS : SUMMARY_PREVIEW_CHARS);
      messages.push({ role: 'tool', toolCallId: String(ev.payload.call_id), name: ev.payload.name, result });
    } else if (ev.type === 'thread.started') {
      messages.push({ role: 'user', content: `[task assigned by lead]: ${ev.payload.task}` });
    } else if (ev.type === 'subagent.reported') {
      messages.push({ role: 'user', content: `[sub-agent "${ev.payload.label}" reported back]: ${ev.payload.summary}` });
    } else if (ev.type === 'turn.checkpoint') {
      messages.push({ role: 'user', content: ev.payload.auto
        ? `[system checkpoint]: ${ev.payload.calls} tool calls in a row — continuing automatically, no need to acknowledge this, just keep working.`
        : `[system checkpoint]: you were automatically paused after ${ev.payload.calls} tool calls in a row, to avoid an unbounded loop — not because anything went wrong. If asked to continue, pick up exactly where you left off.` });
    }
  }

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

function buildSystemPrompt(project, thread, session) {
  const base = [
    'You are a senior penetration testing assistant working inside Flowdit, a pentest reporting tool.',
    `Current project: "${project.name}".`,
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
  const session = await getSession(sessionId);
  if (!session || session.status === 'paused' || session.status === 'error' || session.status === 'completed') return;

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
    const ev = await persistEvent(sessionId, threadId, 'turn.checkpoint', { calls: iterationsThisTurn, auto: willAutoContinue });

    if (willAutoContinue) {
      // Sigue de largo — mismo thread, mismo status (`running`), sin
      // esperar a nadie. Nada que notificar acá: no es "importante",
      // es el agente pausando un instante para no acumular un turno
      // interminable en el historial.
      broadcast(session.project_id, sessionId, session.status, ev);
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
      await notifyNeedsAttention(session, project, `El AI Agent llegó al límite de trabajo autónomo continuo (~${(consecutiveCheckpoints + 1) * MAX_ITERATIONS_PER_TURN} tool calls) y necesita que revises la sesión.`);
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
      const ev = await persistEvent(sessionId, threadId, 'session.cost_cap_reached', { cap, spent });
      await setThreadStatus(threadId, 'idle');
      await recomputeSessionStatus(sessionId);
      const after = await getSession(sessionId);
      broadcast(session.project_id, sessionId, after.status, ev);
      if (thread.parent_thread_id) {
        await reportToParent(session, thread, `[stopped: this session's $${cap.toFixed(2)} cost cap was reached (spent $${spent.toFixed(4)}) — report what was found/attempted so far, the lead should review]`);
      } else {
        await notifyNeedsAttention(session, project, `El AI Agent paró: se alcanzó el tope de gasto de la sesión ($${cap.toFixed(2)}, gastado $${spent.toFixed(4)}).`);
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

  const controller = new AbortController();
  activeAborts.set(threadId, controller);

  let result;
  try {
    result = await ai.chatWithTools(effective.ai_provider, {
      systemPrompt: buildSystemPrompt(effective, thread, session),
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
    console.error('agentLoop error:', err.message);
    // anthropic.js encadena el error real vía `{ cause: err }` — antes esto
    // solo leía err.message y lo perdía. openaiCompatible.js ya mete el
    // detalle directo en el mensaje, pero leer .cause acá también cubre
    // cualquier otro adaptador que use el patrón "correcto" de Node.
    const reason = err.cause?.message ? `${err.message}: ${err.cause.message}` : err.message;
    const ev = await persistEvent(sessionId, threadId, 'session.error', { reason });
    await setThreadStatus(threadId, 'error');
    await recomputeSessionStatus(sessionId);
    broadcast(session.project_id, sessionId, 'error', ev);
    return;
  } finally {
    activeAborts.delete(threadId);
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
    }
    return;
  }

  for (const call of result.toolCalls) {
    const tool = findTool(call.name);
    if (!tool) {
      const ev = await persistEvent(sessionId, threadId, 'session.error', { reason: `unknown tool: ${call.name}` });
      await setThreadStatus(threadId, 'error');
      await recomputeSessionStatus(sessionId);
      broadcast(session.project_id, sessionId, 'error', ev);
      return;
    }

    const calledEv = await persistEvent(sessionId, threadId, 'tool.called', { name: tool.name, input: call.input, tier: tool.tier });
    eventRows.push(calledEv);

    const duplicateCount = countDuplicatesInTurn(eventRows, turnStart, toolCallSignature(tool.name, call.input));
    if (duplicateCount >= MAX_DUPLICATE_CALLS_PER_TURN) {
      // Bloqueado antes de ejecutar — ni gasta el request real ni espera
      // aprobación de un gate para algo que ya sabemos que es un loop.
      broadcast(session.project_id, sessionId, session.status, calledEv);
      const resultEv = await persistEvent(sessionId, threadId, 'tool.result', {
        call_id: calledEv.id, name: tool.name,
        result: { error: `Blocked: you already called ${tool.name} with these exact same arguments ${duplicateCount} times this turn (not necessarily back to back — alternating with other calls does not reset this), always with the same result. Repeating it again will not produce new information — try a materially different approach (a different path, parameter, or technique), or if you've exhausted what this avenue has to offer, move on to something else or conclude with a summary of what you found.` },
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
        notifyNeedsAttention(session, project, `El AI Agent quiere ejecutar "${tool.name}" y necesita tu aprobación.`)
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
          ? await createFindingFromProposal(session.project_id, call.input, session.started_by, session.id)
          : await updateFindingFromProposal(session.project_id, call.input, session.started_by);
        output = { decision: 'accepted', created_vuln_id: vulnId };
      } catch (err) {
        output = { decision: 'accepted', error: `failed to ${tool.name === 'propose_finding' ? 'create' : 'update'} finding: ${err.message}` };
      }
    } else {
      try {
        output = await tool.execute(call.input, { projectId: session.project_id, startedBy: session.started_by, sessionId, threadId });
      } catch (err) {
        output = { error: err.message };
      }
    }
    const resultEv = await persistEvent(sessionId, threadId, 'tool.result', { call_id: calledEv.id, name: tool.name, result: output });
    broadcast(session.project_id, sessionId, session.status, resultEv);
  }

  return advance(sessionId, threadId);
}

// Cuando un sub-agente termina, deja un evento en el thread PADRE contando
// qué encontró (no comparten historial completo — el padre solo ve este
// resumen, igual que un lead que recibe el reporte de un pentester del
// equipo, no la transcripción entera de su trabajo). Si el padre estaba
// `idle` esperando, lo despierta.
async function reportToParent(session, thread, summary) {
  const parent = await getThread(thread.parent_thread_id);
  if (!parent) return;
  const ev = await persistEvent(session.id, parent.id, 'subagent.reported', { label: thread.label, thread_id: thread.id, summary });
  const after = await getSession(session.id);
  broadcast(session.project_id, session.id, after.status, ev);

  if (parent.status === 'idle') {
    await setThreadStatus(parent.id, 'running');
    await recomputeSessionStatus(session.id);
    advance(session.id, parent.id);
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
    const { rows } = await db.query(
      `INSERT INTO ai_scan_threads (session_id, parent_thread_id, label, status) VALUES ($1,$2,$3,'running') RETURNING *`,
      [ctx.sessionId, ctx.threadId, input.task.slice(0, 200)]
    );
    const newThread = rows[0];
    const session = await getSession(ctx.sessionId);
    const ev = await persistEvent(ctx.sessionId, newThread.id, 'thread.started', { task: input.task, target_id: input.target_id || null });
    broadcast(session.project_id, ctx.sessionId, session.status, ev);
    advance(ctx.sessionId, newThread.id); // no await — corre en paralelo al caller
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
// Idempotente: ignora si ese call_id ya tiene un tool.result.
async function resolveGatedCall(sessionId, callId, decision, userId, extra = {}) {
  const { rows: callRows } = await db.query(
    `SELECT * FROM ai_scan_events WHERE id=$1 AND session_id=$2 AND type='tool.called'`,
    [callId, sessionId]
  );
  const calledEv = callRows[0];
  if (!calledEv) return;

  const threadId = calledEv.thread_id;
  const thread = await getThread(threadId);
  if (!thread || thread.status !== 'waiting_approval') return;

  const { rows: existingResult } = await db.query(
    `SELECT 1 FROM ai_scan_events WHERE session_id=$1 AND type='tool.result' AND payload->>'call_id'=$2`,
    [sessionId, String(callId)]
  );
  if (existingResult.length) return;

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
      try {
        const vulnId = calledEv.payload.name === 'propose_finding'
          ? await createFindingFromProposal(session.project_id, calledEv.payload.input, userId, session.id)
          : await updateFindingFromProposal(session.project_id, calledEv.payload.input, userId);
        output = { decision: 'accepted', created_vuln_id: vulnId };
      } catch (err) {
        output = { decision: 'accepted', error: `failed to ${calledEv.payload.name === 'propose_finding' ? 'create' : 'update'} finding: ${err.message}` };
      }
    }
  } else {
    try {
      output = { decision: 'accepted', result: await tool.execute(calledEv.payload.input, { projectId: session.project_id, startedBy: session.started_by, sessionId, threadId }) };
    } catch (err) {
      output = { decision: 'accepted', error: err.message };
    }
  }

  const resultEv = await persistEvent(sessionId, threadId, 'tool.result', { call_id: callId, name: calledEv.payload.name, ...output }, userId || null);
  await setThreadStatus(threadId, 'running');
  await recomputeSessionStatus(sessionId);
  const after = await getSession(sessionId);
  broadcast(session.project_id, sessionId, after.status, resultEv);
  return advance(sessionId, threadId);
}

// ── Pause / resume / interrupt / chat ───────────────────────────────────
// pause/resume son a nivel SESIÓN (afectan a todos los threads a la vez).
// interrupt/sendMessage apuntan al thread primario — el que "habla" con el
// pentester; los sub-agentes no reciben mensajes directos del humano en
// esta versión, solo del thread que los delegó, vía reportToParent().

async function interrupt(sessionId) {
  const primary = await getPrimaryThread(sessionId);
  if (!primary) return;
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
  threads.forEach(t => activeAborts.get(t.id)?.abort());
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
  runningThreads.forEach(t => advance(sessionId, t.id));
}

// Bug real (retest de EncuestaQR): la API se quedó sin fondos, la llamada
// al proveedor falló, el thread pasó a `error` y la sesión quedó muerta
// para siempre — recargar fondos no servía de nada. `error` solo nace de
// un fallo al hablar con el proveedor (fondos, rate limit, red, key), y
// advance() es una función pura del historial persistido: reintentar es
// simplemente volver a llamarla. Revive TODOS los threads en `error`: el
// primario pasa a `primaryStatus`, los sub-agentes directo a `running`.
// Relanza advance() en todo thread que quede `running`. Devuelve cuántos
// threads revivió.
async function reviveErroredThreads(session, primaryId, primaryStatus) {
  const { rows: revived } = await db.query(
    `UPDATE ai_scan_threads SET status = CASE WHEN id=$2 THEN $3 ELSE 'running' END
     WHERE session_id=$1 AND status='error' RETURNING id, status`,
    [session.id, primaryId, primaryStatus]
  );
  if (!revived.length) return 0;
  // Mismo truco que resume(): recomputeSessionStatus() no toca una sesión
  // en `error`, así que hay que sacarla de ahí antes de recalcular.
  if (session.status === 'error') await setSessionStatus(session.id, 'idle');
  await recomputeSessionStatus(session.id);
  revived.filter(t => t.status === 'running').forEach(t => advance(session.id, t.id));
  return revived.length;
}

// Botón "Reintentar" — mismo revive que un mensaje de chat, pero sin
// mensaje nuevo: el primario vuelve directo a `running` y retoma el turno
// que falló, leyendo el historial ya persistido.
async function retry(sessionId) {
  const session = await getSession(sessionId);
  if (!session || session.status === 'paused') return;
  const primary = await getPrimaryThread(sessionId);
  if (!primary) return;
  if (!(await reviveErroredThreads(session, primary.id, 'running'))) return;
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

  const wakesPrimary = primary.status === 'idle';
  if (wakesPrimary) {
    await setThreadStatus(primary.id, 'running');
    await recomputeSessionStatus(sessionId);
  }
  // Broadcast DESPUÉS de pasar a `running` — antes salía con el status viejo
  // (`idle`), y la burbuja de "escribiendo..." del frontend recién aparecía
  // con el primer evento del agente, no al mandar el mensaje.
  const after = await getSession(sessionId);
  broadcast(session.project_id, sessionId, after.status, ev);
  if (wakesPrimary) advance(sessionId, primary.id); // no await — corre en background
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
     WHERE t.status = 'running' AND s.status NOT IN ('paused', 'error', 'completed')`
  );
  for (const row of rows) {
    advance(row.session_id, row.thread_id).catch(err => console.error('resumeOrphanedThreads: advance failed:', err.message));
  }
  return rows.length;
}

module.exports = {
  eventsToMessages,
  advance, resolveGatedCall, pause, resume, retry, sendMessage, interrupt,
  createSessionWithPrimaryThread, getPrimaryThread, sessionBelongsToProject,
  resumeOrphanedThreads,
  // exported for tests (client_visible can't be set through the agent)
  createFindingFromProposal, updateFindingFromProposal,
};
