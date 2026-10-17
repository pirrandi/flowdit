// ── AI Agent — vista del scanner de IA ──────────────────────────────────
// Página dedicada (no un panel flotante) para el agente de pentest, ver
// AI_PENTEST_AGENT.md. Se conecta con el resto del proyecto vía `state`
// (targets, customVulns) que `page.js` ya pobló antes de que pageInit()
// corra, y con el WS ya conectado (`wsClient`), suscribiéndose al tipo de
// mensaje `ai_scan:event`.
//
// Cada evento en vivo se agrega incrementalmente (`appendLiveEvent()`),
// nunca reconstruye el DOM entero — ver esa función para el porqué.
// `renderTranscript()` (rebuild completo) queda solo para cargar/cambiar
// de sesión y para un cambio de modo simple/avanzado.

let _scanSession  = null;  // sesión activa que se está mirando (o null)
let _scanEvents   = [];    // eventos de _scanSession (de TODOS sus threads), en orden
let _scanThreads  = [];    // threads de _scanSession — el primario (parent_thread_id null) es el coordinador
let _scanSessions = [];    // lista de sesiones del proyecto (para el picker)
let _scanEditCallId = null; // call_id de la propuesta que se está editando en el modal
let _sessionSearchQuery = ''; // buscador del dropdown de sesiones (>6 sesiones) — persiste entre renders en vivo
let _renamingSessionId  = null; // sesión con el input de rename abierto ahora mismo, si hay alguna

// Rediseño 2026-09-22 (design_handoff_ai_agent/): el panel central se
// organiza en pestañas en vez del viejo toggle Resumen/Detalle. Chat es
// SIEMPRE la vista filtrada (equivalente a lo que antes era el modo
// "simple" — tools de Nivel 0/1 escondidas, conversación real siempre
// visible); Detalle es el feed completo de acciones de la IA, incluyendo
// cada tool call individual con su detalle técnico expandible. La
// separación en sí reemplaza al toggle — no quedó ningún modo "avanzado"
// alternativo para el chat porque Detalle ya cubre exactamente ese caso.
let _scanActiveTab = 'chat'; // 'chat' | 'detalle' | 'resumen'
let _expandedDetailIds = new Set(); // ids de tool.called expandidos en Detalle — se preserva entre re-renders
let _scanCounterPopoverOpen = null; // 'endpoints' | 'review' | null — cuál popover del status strip está abierto

// V1.5 — sin vista multi-columna todavía (ver AI_PENTEST_AGENT.md, gap
// conocido): el transcript sigue siendo una sola lista lineal, pero los
// eventos de sub-agentes se etiquetan (thread.started/subagent.reported)
// para que no se confundan con la conversación del coordinador.

// ── Idioma de la interfaz + del propio agente (ES/EN) ────────────────────
// Pedido explícito: "quiero que esté en spanish, o bueno... demos la opción
// de configurar tanto en spanish como english". Acotado a esta página (no
// toda la app — decisión explícita), guardado en localStorage (cambia al
// instante, sin pegarle al backend). También viaja como `lang` al crear una
// sesión nueva (ver scanStartSession()) para que el agente mismo responda
// en ese idioma — ver buildSystemPrompt() en agentLoop.js. Fijo por sesión:
// no tiene sentido reconfigurar a mitad de un historial ya en curso.
const AI_LANG_KEY = 'fd_ai_lang';
function getAiLang() { return localStorage.getItem(AI_LANG_KEY) === 'en' ? 'en' : 'es'; }

function t(key, vars) {
  const dict = AI_I18N[getAiLang()] || AI_I18N.es;
  let str = dict[key] ?? AI_I18N.es[key] ?? key;
  if (vars) for (const k in vars) str = str.split(`{${k}}`).join(vars[k]);
  return str;
}

// Solo strings de ESTA página — no un i18n global de la app (fuera de
// alcance, ver AI_PENTEST_AGENT.md). `status_*` reemplaza el viejo
// SESSION_STATUS_LABELS: mismas 6 claves, ahora en los dos idiomas.
const AI_I18N = {
  es: {
    subtitle: '// scanner de pentest autónomo — conectado con este proyecto',
    status_idle: 'inactiva', status_running: 'corriendo', status_waiting_approval: 'esperando aprobación',
    status_paused: 'pausada', status_completed: 'completada', status_error: 'error',
    inScope: 'en scope', inProject: 'en el proyecto',
    finding_one: 'hallazgo', finding_other: 'hallazgos',
    noSession: 'Ninguna sesión', newSession: 'Nueva sesión', deleteSessionTooltip: 'Eliminar sesión',
    renameSessionTooltip: 'Renombrar sesión', sessionNamePlaceholder: 'Nombre de la sesión',
    searchSessionsPlaceholder: 'Buscar sesiones...',
    cantDeleteRunning: 'No se puede borrar una sesión corriendo — pausala primero',
    confirmDeleteText: '¿Borrar la sesión del {date}? Esto borra todo su historial, no se puede deshacer.',
    sessionDeleted: 'Sesión borrada',
    coordinator: 'Coordinador', subAgent: 'Sub-agente',
    tabChat: 'Chat', tabDetalle: 'Detalle', tabResumen: 'Resumen',
    inScopeLabel: 'target en scope', inScopeLabel_other: 'targets en scope',
    findingsLabel: 'hallazgos', endpointsLabel: 'endpoints', reviewLabel: 'para revisar',
    detailHeading: 'Qué está haciendo la IA ahora', detailEmpty: 'Sin actividad todavía en esta sesión.',
    resumenHeading: 'Hallazgos por severidad', resumenEmpty: 'Sin hallazgos todavía en este proyecto.',
    rem_open: 'Abierto', rem_remediated: 'Remediado', rem_not_remediated: 'No Remediado', rem_verified_closed: 'Verificado',
    retestNotesLabel: 'Notas de retest',
    newSessionShort: 'Nueva sesión', sessionsDropdownHeader: 'SESIONES DE AI AGENT',
    summaryView: 'Resumen', detailView: 'Detalle',
    waitingApprovalFor: 'Esperando tu aprobación para {tool}...', executingTool: 'Ejecutando {tool}...',
    waitingApproval: 'Esperando tu aprobación...', thinking: 'Pensando en el próximo paso...',
    catPorts: 'Puertos abiertos', catEndpoints: 'Endpoints', catSubdomains: 'Subdominios',
    catFindings: 'Hallazgos propuestos', catReview: 'Para revisar',
    notResponding: 'no responde', unnamed: '(sin nombre)',
    noHighlightsYet: 'Sin novedades todavía — el agente está trabajando, mirá "{detail}" para seguirlo en vivo.',
    waitingApprovalReview: 'Esperando aprobación: {name}',
    emptyStateDesc: 'Ningún scan corriendo. El agente arranca ya conectado a este proyecto — puede leer los targets en scope y los hallazgos existentes, y con tu aprobación, escanear y proponer hallazgos nuevos.',
    targetLabel: 'Target', targetOptionalNote: '(opcional — vacío = todo el proyecto)',
    wholeProjectOption: '— Todo el proyecto —',
    initialInstructionLabel: 'Instrucción inicial', instructionOptionalNote: '(opcional)',
    instructionPlaceholder: 'ej: Enfocate en la API de autenticación',
    advancedOptions: 'Opciones avanzadas', advancedOptionsNote: '(esta sesión puede usar un proveedor/config distinto al del proyecto)',
    providerLabel: 'Proveedor de IA', modelLabel: 'Modelo', modelPlaceholder: 'Predeterminado (.env)',
    profileLabel: 'Tipo de sesión', profilePentest: 'Pentest estándar', profileCtf: 'CTF', profileLab: 'Laboratorio (HTB/THM)',
    costCapLabel: 'Tope de gasto', costCapPlaceholder: 'Sin tope (ej: 5.00)',
    costCapReachedLine: 'Se alcanzó el tope de gasto de la sesión ({cap}) — gastado {spent}',
    raiseCostCapBtn: 'Subir tope', costCapRaised: 'Tope actualizado — mandá un mensaje para seguir',
    autonomousModeLabel: 'Modo sin restricciones para esta sesión',
    singleAgentLabel: 'Un agente a la vez para esta sesión',
    startScanBtn: 'Iniciar scan', scanStarted: 'Scan iniciado',
    pause: 'Pausar', interrupt: 'Interrumpir', resume: 'Reanudar', retry: 'Reintentar',
    sessionEndedPlaceholder: 'Esta sesión terminó — iniciá una nueva para seguir',
    sessionErrorPlaceholder: 'El agente falló al hablar con el proveedor — tocá Reintentar o mandá un mensaje...',
    resolveApprovalPlaceholder: 'Resolvé la aprobación pendiente para seguir hablando...',
    resumeToChatPlaceholder: 'Reanudá la sesión para seguir hablando...',
    chatPlaceholder: 'Hablale al agente — preguntale algo o dale una instrucción... (Shift+Enter: nueva línea)',
    tier0Title: 'Nivel 0 — solo lectura de datos de Flowdit, sin gate',
    tier1Title: 'Nivel 1 — recon pasivo contra el target, sin gate',
    tier2Title: 'Nivel 2 — acción activa contra el target, gate por defecto',
    tier3Title: 'Nivel 3 — propone un hallazgo, gate por defecto',
    approveAsIs: 'Aceptar tal cual', editAndAdd: 'Editar y agregar', reject: 'Rechazar',
    requiresApproval: ' — tier {tier}, requiere tu aprobación',
    staleGateNote: 'La sesión terminó antes de que esto se resolviera — sin efecto, iniciá una nueva sesión.',
    approved: 'Aprobado', rejectedPrefix: 'Rechazado',
    findingAddedNote: ' — hallazgo agregado al proyecto', findingUpdatedNote: ' — hallazgo actualizado', errorNotePrefix: ' — error: ',
    showRemediation: 'Ver remediación', proofLabel: 'Proof {n}', confidenceLabel: 'Confianza', requestFailed: 'Falló',
    sessionStarted: 'Sesión iniciada', errorLine: 'Error: {reason}',
    pausedLine: 'Pausado', resumedLine: 'Reanudado',
    subagentDelegated: 'Sub-agente delegado: {task}',
    checkpointAuto: '{calls} tool calls seguidos — sigue solo',
    checkpointManual: 'Pausa tras {calls} tool calls seguidos — decile "continuá" para seguir',
    checkpointNoProgress: 'El agente encadenó muchos intentos sin resultados nuevos. Revisá el rumbo o dale una indicación.',
    agentLabel: 'Agente', you: 'Vos', pentester: 'Pentester',
    newMessages: 'Nuevos mensajes',
    rejectReasonPrompt: 'Motivo del rechazo (opcional):',
    interruptPrompt: '¿Qué querés que haga en vez de lo que está haciendo ahora?',
    findingAdded: 'Hallazgo agregado', nameRequired: 'El nombre es obligatorio',
    editFindingTitle: 'Editar hallazgo propuesto',
    labelName: 'Nombre *', labelCategory: 'Categoría', labelSeverity: 'Severidad',
    labelDescription: 'Descripción', labelRemediation: 'Remediación',
    labelCwe: 'CWE <span class="aa-opt">(opcional)</span>',
    createdViaEndpoint: 'Se crea vía el mismo endpoint que "Add Vulnerability"',
    cancel: 'Cancelar', addFinding: 'Agregar hallazgo', deleteSessionLabel: 'Borrar sesión',
    // Rediseño 2026-10 — `send` faltaba (el botón mostraba la clave cruda "send").
    send: 'Enviar', noSessionsMatch: 'Ninguna sesión coincide',
    newSessionTitle: 'Nueva sesión del agente', langName: 'español',
    startLangHint: 'El agente va a responder en {lang} — queda fijo para esta sesión',
    gatesOnChip: 'Lo activo pasa por tu aprobación', autonomousOnChip: 'Modo sin restricciones activo',
    autonomousModeHint: 'Las acciones de Nivel 2/3 corren sin pedir aprobación',
    singleAgentHint: 'Sin sub-agentes trabajando en paralelo',
    gatePendingTitle: 'Esperando tu aprobación', gatePendingHint: 'Revisá la evidencia antes de aprobar',
    gateAccepted: 'Aprobado', gateRejected: 'Rechazado', gateStale: 'Sin resolver',
    gateAuto: 'Ejecutado sin aprobación', gateFailed: 'Falló',
    evidenceLabel: 'Evidencia', requestLabel: 'Request', responseLabel: 'Response',
    inputLabel: 'Entrada', outputLabel: 'Salida', payloadLabel: 'Payload', notRunYet: 'sin ejecutar',
    linesLabel: '{n} líneas', copy: 'Copiar', copied: 'Copiado', copyFailed: 'No se pudo copiar',
    showAll: 'Ver todo', showLess: 'Contraer',
    errorTitle: 'El agente se detuvo por un error', checkpointTitle: 'Pausa de control',
    noProgressTitle: 'Pausado — sin progreso', costCapTitle: 'Tope de gasto alcanzado',
    detailCountActions: '{n} acciones', detailCountRunning: '{n} en curso', detailCountErrors: '{n} con error',
    sessionStatsHeading: 'Esta sesión', statActions: 'Acciones', statEndpoints: 'Endpoints',
    statPorts: 'Puertos', statSubdomains: 'Subdominios', statCost: 'Gasto',
    statCostCap: 'tope {cap}', statNoCap: 'sin tope', statHosts: 'abiertos en {n} host(s)', statUnreachable: '{n} no resuelven',
    pctOfTotal: '{pct}% del total', openInVulns: 'Abrir en My Vulns',
  },
  en: {
    subtitle: '// autonomous pentest scanner — connected to this project',
    status_idle: 'idle', status_running: 'running', status_waiting_approval: 'waiting approval',
    status_paused: 'paused', status_completed: 'completed', status_error: 'error',
    inScope: 'in scope', inProject: 'in the project',
    finding_one: 'finding', finding_other: 'findings',
    noSession: 'No session', newSession: 'New session', deleteSessionTooltip: 'Delete session',
    renameSessionTooltip: 'Rename session', sessionNamePlaceholder: 'Session name',
    searchSessionsPlaceholder: 'Search sessions...',
    cantDeleteRunning: "Can't delete a running session — pause it first",
    confirmDeleteText: 'Delete the session from {date}? This deletes its entire history, cannot be undone.',
    sessionDeleted: 'Session deleted',
    coordinator: 'Coordinator', subAgent: 'Sub-agent',
    tabChat: 'Chat', tabDetalle: 'Detail', tabResumen: 'Summary',
    inScopeLabel: 'target in scope', inScopeLabel_other: 'targets in scope',
    findingsLabel: 'findings', endpointsLabel: 'endpoints', reviewLabel: 'needs review',
    detailHeading: 'What the AI is doing now', detailEmpty: 'No activity yet in this session.',
    resumenHeading: 'Findings by severity', resumenEmpty: 'No findings yet in this project.',
    rem_open: 'Open', rem_remediated: 'Remediated', rem_not_remediated: 'Not Remediated', rem_verified_closed: 'Verified Closed',
    retestNotesLabel: 'Retest notes',
    newSessionShort: 'New session', sessionsDropdownHeader: 'AI AGENT SESSIONS',
    summaryView: 'Summary', detailView: 'Detail',
    waitingApprovalFor: 'Waiting for your approval for {tool}...', executingTool: 'Running {tool}...',
    waitingApproval: 'Waiting for your approval...', thinking: 'Thinking about the next step...',
    catPorts: 'Open ports', catEndpoints: 'Endpoints', catSubdomains: 'Subdomains',
    catFindings: 'Proposed findings', catReview: 'Needs review',
    notResponding: 'not responding', unnamed: '(unnamed)',
    noHighlightsYet: 'Nothing yet — the agent is working, check "{detail}" to follow it live.',
    waitingApprovalReview: 'Waiting for approval: {name}',
    emptyStateDesc: 'No scan running. The agent starts already connected to this project — it can read the in-scope targets and existing findings, and with your approval, scan and propose new findings.',
    targetLabel: 'Target', targetOptionalNote: '(optional — empty = whole project)',
    wholeProjectOption: '— Whole project —',
    initialInstructionLabel: 'Initial instruction', instructionOptionalNote: '(optional)',
    instructionPlaceholder: 'e.g.: Focus on the authentication API',
    advancedOptions: 'Advanced options', advancedOptionsNote: "(this session can use a different provider/config than the project's)",
    providerLabel: 'AI Provider', modelLabel: 'Model', modelPlaceholder: 'Default (.env)',
    profileLabel: 'Session type', profilePentest: 'Standard pentest', profileCtf: 'CTF', profileLab: 'Lab (HTB/THM)',
    costCapLabel: 'Cost cap', costCapPlaceholder: 'No cap (e.g. 5.00)',
    costCapReachedLine: "This session's cost cap ({cap}) was reached — spent {spent}",
    raiseCostCapBtn: 'Raise cap', costCapRaised: 'Cap updated — send a message to continue',
    autonomousModeLabel: 'Unrestricted mode for this session',
    singleAgentLabel: 'Single agent at a time for this session',
    startScanBtn: 'Start scan', scanStarted: 'Scan started',
    pause: 'Pause', interrupt: 'Interrupt', resume: 'Resume', retry: 'Retry',
    sessionEndedPlaceholder: 'This session ended — start a new one to continue',
    sessionErrorPlaceholder: 'The agent failed to reach the provider — click Retry or send a message...',
    resolveApprovalPlaceholder: 'Resolve the pending approval to keep chatting...',
    resumeToChatPlaceholder: 'Resume the session to keep chatting...',
    chatPlaceholder: 'Talk to the agent — ask something or give it an instruction... (Shift+Enter: new line)',
    tier0Title: 'Level 0 — read-only Flowdit data, no gate',
    tier1Title: 'Level 1 — passive recon against the target, no gate',
    tier2Title: 'Level 2 — active action against the target, gated by default',
    tier3Title: 'Level 3 — proposes a finding, gated by default',
    approveAsIs: 'Accept as-is', editAndAdd: 'Edit and add', reject: 'Reject',
    requiresApproval: ' — tier {tier}, requires your approval',
    staleGateNote: 'The session ended before this was resolved — no effect, start a new session.',
    approved: 'Approved', rejectedPrefix: 'Rejected',
    findingAddedNote: ' — finding added to the project', findingUpdatedNote: ' — finding updated', errorNotePrefix: ' — error: ',
    showRemediation: 'Show remediation', proofLabel: 'Proof {n}', confidenceLabel: 'Confidence', requestFailed: 'Failed',
    sessionStarted: 'Session started', errorLine: 'Error: {reason}',
    pausedLine: 'Paused', resumedLine: 'Resumed',
    subagentDelegated: 'Sub-agent delegated: {task}',
    checkpointAuto: '{calls} tool calls in a row — continuing on its own',
    checkpointManual: 'Paused after {calls} tool calls in a row — tell it "continue" to keep going',
    checkpointNoProgress: 'The agent chained many attempts with no new results. Review its direction or give it a hint.',
    agentLabel: 'Agent', you: 'You', pentester: 'Pentester',
    newMessages: 'New messages',
    rejectReasonPrompt: 'Reason for rejection (optional):',
    interruptPrompt: 'What do you want it to do instead of what it’s doing now?',
    findingAdded: 'Finding added', nameRequired: 'Name is required',
    editFindingTitle: 'Edit proposed finding',
    labelName: 'Name *', labelCategory: 'Category', labelSeverity: 'Severity',
    labelDescription: 'Description', labelRemediation: 'Remediation',
    labelCwe: 'CWE <span class="aa-opt">(optional)</span>',
    createdViaEndpoint: 'Created via the same endpoint as "Add Vulnerability"',
    cancel: 'Cancel', addFinding: 'Add Finding', deleteSessionLabel: 'Delete session',
    send: 'Send', noSessionsMatch: 'No sessions match',
    newSessionTitle: 'New agent session', langName: 'English',
    startLangHint: 'The agent will reply in {lang} — fixed for this session',
    gatesOnChip: 'Active actions need your approval', autonomousOnChip: 'Unrestricted mode on',
    autonomousModeHint: 'Level 2/3 actions run without asking for approval',
    singleAgentHint: 'No sub-agents working in parallel',
    gatePendingTitle: 'Waiting for your approval', gatePendingHint: 'Review the evidence before approving',
    gateAccepted: 'Approved', gateRejected: 'Rejected', gateStale: 'Unresolved',
    gateAuto: 'Ran without approval', gateFailed: 'Failed',
    evidenceLabel: 'Evidence', requestLabel: 'Request', responseLabel: 'Response',
    inputLabel: 'Input', outputLabel: 'Output', payloadLabel: 'Payload', notRunYet: 'not run yet',
    linesLabel: '{n} lines', copy: 'Copy', copied: 'Copied', copyFailed: 'Could not copy',
    showAll: 'Show all', showLess: 'Collapse',
    errorTitle: 'The agent stopped on an error', checkpointTitle: 'Control pause',
    noProgressTitle: 'Paused — no progress', costCapTitle: 'Cost cap reached',
    detailCountActions: '{n} actions', detailCountRunning: '{n} running', detailCountErrors: '{n} failed',
    sessionStatsHeading: 'This session', statActions: 'Actions', statEndpoints: 'Endpoints',
    statPorts: 'Ports', statSubdomains: 'Subdomains', statCost: 'Spend',
    statCostCap: 'cap {cap}', statNoCap: 'no cap', statHosts: 'open on {n} host(s)', statUnreachable: '{n} unresolved',
    pctOfTotal: '{pct}% of total', openInVulns: 'Open in My Vulns',
  },
};

function statusLabel(status) { return t(`status_${status}`); }

// ── Helpers de presentación (rediseño 2026-10) ──────────────────────────
// Íconos de esta página que no están en icons.js (mismo trazo lucide,
// 24x24) — se arman acá para no tocar el set compartido de toda la app.
const _AA_ICONS = {
  target: '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
  shield: '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
  bot: '<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>',
  coins: '<circle cx="8" cy="8" r="6"/><path d="M18.09 10.37A6 6 0 1 1 10.34 18"/><path d="M7 6h1v4"/><path d="m16.71 13.88.7.71-2.82 2.82"/>',
  network: '<rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/><path d="M12 12V8"/>',
  copy: '<rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>',
};
function _aaIcon(name, size = 14) {
  const body = _AA_ICONS[name];
  if (!body) return icon(name, { size });
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="fd-icon">${body}</svg>`;
}

// Hora local corta (HH:MM) — la fecha completa queda en el title. Reemplaza
// a timeAgo() en esta vista ("1h ago" quedaba en inglés en una página en ES).
function _aaClock(iso) {
  const d = iso ? new Date(iso) : null;
  if (!d || isNaN(d)) return '';
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
function _aaWhen(iso) {
  const c = _aaClock(iso);
  return c ? `<span class="aa-when" title="${esc(new Date(iso).toLocaleString())}">${esc(c)}</span>` : '';
}

function _aaDuration(fromIso, toIso) {
  const ms = new Date(toIso) - new Date(fromIso);
  if (!isFinite(ms) || ms < 0) return null;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(ms < 10000 ? 1 : 0)}s`;
  const m = Math.floor(ms / 60000), s = Math.round((ms % 60000) / 1000);
  if (m < 60) return `${m}m ${String(s).padStart(2, '0')}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function _aaTierChip(tier) {
  const n = Number(tier) || 0;
  return `<span class="aa-chip aa-tier-${n}" title="${esc(tierTitle(n))}">T${n}</span>`;
}

// Chip de status HTTP coloreado por familia (2xx/3xx/4xx/5xx).
function _aaHttpChip(res) {
  if (!res) return `<span class="aa-chip aa-chip-plain">${esc(t('notRunYet'))}</span>`;
  if (res.error) return `<span class="aa-chip aa-http-err">${esc(t('requestFailed'))}</span>`;
  const code = Number(res.status);
  const cls = code >= 200 && code < 600 ? `aa-http-${Math.floor(code / 100)}` : 'aa-chip-plain';
  return `<span class="aa-chip ${cls}">HTTP ${esc(String(res.status ?? '?'))}</span>`;
}

function _aaCvssTone(score) {
  const n = Number(score);
  if (n >= 9) return 'aa-http-5';
  if (n >= 7) return 'aa-tier-3';
  if (n >= 4) return 'aa-http-4';
  return n > 0 ? 'aa-http-2' : 'aa-chip-plain';
}

// Bloque de código numerado (request/response, input/output). Texto
// SIEMPRE escapado. Los largos arrancan plegados con "Ver todo"; `key`
// identifica el bloque para recordar si quedó expandido entre re-renders
// (Detalle se reconstruye entero en cada evento en vivo).
const AA_CODE_FOLD_LINES = 16;
let _aaFullCode = new Set();

function _aaCode(label, text, key, opts = {}) {
  const str = text == null ? '' : String(text);
  const lines = str.split('\n');
  const long = lines.length > AA_CODE_FOLD_LINES || str.length > 2400;
  const full = long && _aaFullCode.has(key);
  return `
    <div class="aa-code${full ? ' is-full' : ''}${opts.error ? ' aa-code-err' : ''}">
      <div class="aa-code-head">
        <span>${esc(label)}</span><span class="aa-code-meta">${esc(t('linesLabel', { n: lines.length }))}</span>
        <span class="aa-code-btns">
          ${long ? `<button type="button" class="aa-code-btn" onclick="event.stopPropagation();aaToggleCode(this,'${esc(String(key))}')">${esc(t(full ? 'showLess' : 'showAll'))}</button>` : ''}
          <button type="button" class="aa-code-btn" title="${esc(t('copy'))}" aria-label="${esc(t('copy'))}" onclick="event.stopPropagation();aaCopyCode(this)">${_aaIcon('copy', 11)}</button>
        </span>
      </div>
      <pre class="aa-code-pre">${lines.map(l => `<span>${esc(l)}</span>`).join('')}</pre>
    </div>`;
}

function aaToggleCode(btn, key) {
  const box = btn.closest('.aa-code');
  if (!box) return;
  const full = !box.classList.contains('is-full');
  box.classList.toggle('is-full', full);
  if (full) _aaFullCode.add(key); else _aaFullCode.delete(key);
  btn.textContent = t(full ? 'showLess' : 'showAll');
}

async function aaCopyCode(btn) {
  const text = btn.closest('.aa-code')?.querySelector('.aa-code-pre')?.innerText ?? '';
  try {
    await navigator.clipboard.writeText(text);
    showToast(t('copied'), 'success');
  } catch {
    showToast(t('copyFailed'), 'error');
  }
}

function _aaJson(v) { return v === undefined ? '' : JSON.stringify(v, null, 2); }

function setAiLang(lang) {
  if (lang !== 'es' && lang !== 'en') return;
  localStorage.setItem(AI_LANG_KEY, lang);
  document.documentElement.lang = lang;
  applyStaticI18n();
  renderLangToggle();
  renderSessionPicker();
  renderThreadsStrip();
  renderTabsBar();
  renderStatusStrip();
  renderInputRow();
  // El transcript y las pestañas dependen del idioma (labels de sistema,
  // gates, "Agente"/"Vos"...) — rebuild completo, no un evento en vivo.
  if (_scanSession) { renderTranscript(); renderActiveTabPanel(); }
  else if (document.getElementById('scan-transcript')) renderEmptyState();
}

function renderLangToggle() {
  const el = document.getElementById('scan-lang-toggle');
  if (!el) return;
  const lang = getAiLang();
  el.innerHTML = `
    <button class="scan-lang-btn ${lang === 'es' ? 'active' : ''}" onclick="setAiLang('es')" title="Español">ES</button>
    <button class="scan-lang-btn ${lang === 'en' ? 'active' : ''}" onclick="setAiLang('en')" title="English">EN</button>
  `;
}

// Textos que viven como markup estático en ai-agent.html (no generados por
// ningún render*() de acá) — títulos de modal, labels de formulario,
// botones fijos. `innerHTML` a propósito: mismo nivel de confianza que el
// resto del archivo (strings armados por nosotros, nunca contenido de
// usuario/target) y hace falta para labelCwe (trae un <span> anidado).
function applyStaticI18n() {
  document.querySelectorAll('[data-i18n]').forEach(el => { el.innerHTML = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
}

async function initAiAgent() {
  if (window.marked) window.marked.setOptions({ breaks: true }); // mismo ajuste que whiteboard.js, para saltos de línea consistentes
  document.documentElement.lang = getAiLang();
  applyStaticI18n();
  renderLangToggle();
  wsClient.on('ai_scan:event', handleScanEvent);

  try {
    _scanSessions = await api.aiScan.listSessions(state.currentProject.id);
  } catch {
    _scanSessions = [];
  }

  renderSessionPicker();

  const active = _scanSessions.find(s => ['running', 'idle', 'waiting_approval', 'paused'].includes(s.status));
  if (active) {
    await loadSession(active.id);
  } else {
    _scanSession = null;
    _scanThreads = [];
    renderEmptyState();
    renderInputRow();
    renderThreadsStrip();
    renderTabsBar();
    renderStatusStrip();
  }
}

// ── Contexto del proyecto — el punto central de "conectado con todo" ────
// El picker de sesiones era un <select> nativo sin ningún estilo propio
// (reportado como feo) — reemplazado por el mismo patrón de dropdown que
// ya usa el menú de usuario (.user-dropdown/.dropdown-item, page.js), con
// estados traducidos y un botón de borrar por fila. Después mejorado a
// pedido ("mejorá harto la gestión de sesiones"): nombre (auto-generado o
// a mano), target/duración por fila, y buscador si hay muchas sesiones.
function _sessionLabel(s) { return s.name || new Date(s.started_at).toLocaleString(); }

function _sessionDuration(s) {
  if (!s.completed_at) return null;
  const mins = Math.round((new Date(s.completed_at) - new Date(s.started_at)) / 60000);
  if (mins < 1) return '<1m';
  if (mins < 60) return `${mins}m`;
  return `${Math.floor(mins / 60)}h ${mins % 60}m`;
}

function _sessionTargetLabel(s) {
  if (!s.target_id) return null;
  return (state.targets || []).find(t => t.id === s.target_id)?.host || null;
}

// Mismo criterio que fmt$ en settings.js (4 decimales — el gasto por
// llamada suele ser fracción de centavo) — se omite directamente si no
// hubo gasto, no tiene sentido mostrar "$0.0000" en una sesión sin uso real.
function _sessionCostLabel(s) {
  const cost = Number(s.total_cost) || 0;
  return cost > 0 ? `$${cost.toFixed(4)}` : null;
}

function _sessionFindingsLabel(s) {
  const n = Number(s.findings_count) || 0;
  return n > 0 ? `${n} ${t(n === 1 ? 'finding_one' : 'finding_other')}` : null;
}

// 'pentest'/null es el default — no vale la pena mostrarlo en cada fila,
// solo cuando la sesión es algo distinto (CTF/lab) vale la pena que se note
// de un vistazo en el picker.
function _sessionProfileLabel(s) {
  if (s.ai_profile === 'ctf') return t('profileCtf');
  if (s.ai_profile === 'lab') return t('profileLab');
  return null;
}

// Pill con dot de estado + nombre truncado (190px, ver CSS) + chevron —
// abre el dropdown de gestión de sesiones completo (crear, buscar,
// renombrar, borrar). Sigue siendo la MISMA lógica de siempre, restyleada
// a los tokens del rediseño; los contadores que antes vivían acá al lado
// (target en scope/hallazgos) se movieron a renderStatusStrip().
function renderSessionPicker() {
  const el = document.getElementById('scan-session-picker-wrap');
  if (!el) return;
  // handleScanEvent() llama a esto en CADA evento en vivo — sin preservar
  // esto, el dropdown de sesiones se cerraba solo apenas llegaba cualquier
  // evento de un scan activo (mismo tipo de bug que ya arreglamos para los
  // <details> del transcript). El buscador y el input de rename son el
  // mismo problema de nuevo: un rebuild completo de innerHTML mientras el
  // pentester está escribiendo le mataría foco, cursor y lo que sea que
  // haya tipeado (todavía sin guardar) — se captura y se restaura abajo.
  const wasOpen = document.getElementById('scan-session-dropdown')?.classList.contains('open');
  const active = document.activeElement;
  const activeId = active?.id;
  const activeVal = active?.value;
  const activeSelStart = active?.selectionStart;

  if (!_scanSessions.length) { el.innerHTML = ''; return; }

  const triggerLabel = _scanSession ? _sessionLabel(_scanSession) : t('noSession');
  const triggerStatus = _scanSession ? _scanSession.status : 'idle';

  const q = _sessionSearchQuery.trim().toLowerCase();
  const visibleSessions = q ? _scanSessions.filter(s => _sessionLabel(s).toLowerCase().includes(q)) : _scanSessions;

  el.innerHTML = `
    <span class="scan-session-picker">
      <button class="scan-session-trigger" title="${esc(triggerLabel)}" onclick="event.stopPropagation();toggleScanSessionMenu()">
        <span class="dot aa-st-${esc(triggerStatus)}"></span>
        <span class="name">${esc(triggerLabel)}</span>
        <span class="chev">${icon('chevron-down', { size: 13 })}</span>
      </button>
      <div class="scan-session-dropdown" id="scan-session-dropdown">
        <div class="scan-session-dropdown-head"><span>${esc(t('sessionsDropdownHeader'))}</span><span>${_scanSessions.length}</span></div>
        ${_scanSessions.length > 6 ? `
          <input type="text" class="scan-session-search" id="scan-session-search" autocomplete="off"
            placeholder="${esc(t('searchSessionsPlaceholder'))}" value="${esc(_sessionSearchQuery)}"
            onclick="event.stopPropagation()" oninput="_scanSessionSearchInput(this.value)">
        ` : ''}
        ${!visibleSessions.length ? `<div class="aa-session-none">${esc(t('noSessionsMatch'))}</div>` : ''}
        ${visibleSessions.map(s => {
          const target = _sessionTargetLabel(s);
          const dur = _sessionDuration(s);
          const cost = _sessionCostLabel(s);
          const findingsLabel = _sessionFindingsLabel(s);
          const profileLabel = _sessionProfileLabel(s);
          const meta = [profileLabel, target, dur, cost, findingsLabel].filter(Boolean).join(' · ');
          return _renamingSessionId === s.id ? `
          <div class="scan-session-row active">
            <input type="text" class="scan-session-name-input" id="scan-session-rename-input" autocomplete="off"
              value="${esc(s.name || '')}" placeholder="${esc(t('sessionNamePlaceholder'))}"
              onclick="event.stopPropagation()"
              onkeydown="if(event.key==='Enter'){this.blur();}else if(event.key==='Escape'){cancelRenameSession();}"
              onblur="saveRenameSession('${s.id}', this.value)">
          </div>` : `
          <div class="scan-session-row ${_scanSession && _scanSession.id === s.id ? 'active' : ''}">
            <button class="scan-session-row-btn" onclick="switchScanSession('${s.id}');closeScanSessionMenu()">
              <span class="scan-session-dot aa-st-${esc(s.status)}"></span>
              <span class="scan-session-main">
                <span class="scan-session-name">${esc(_sessionLabel(s))}</span>
                ${meta ? `<span class="scan-session-meta">${esc(meta)}</span>` : ''}
              </span>
              <span class="scan-session-status ${esc(s.status)}">${esc(statusLabel(s.status))}</span>
            </button>
            <button class="scan-session-rename" title="${esc(t('renameSessionTooltip'))}" onclick="event.stopPropagation();startRenameSession('${s.id}')">${icon('square-pen', { size: 12 })}</button>
            <button class="scan-session-delete" title="${esc(t('deleteSessionTooltip'))}" onclick="event.stopPropagation();scanDeleteSession('${s.id}')">${icon('x', { size: 12 })}</button>
          </div>`;
        }).join('')}
        <button class="scan-session-new" onclick="switchScanSession('');closeScanSessionMenu()">${icon('plus', { size: 13 })} ${esc(t('newSessionShort'))}</button>
      </div>
    </span>
  `;
  if (wasOpen) document.getElementById('scan-session-dropdown')?.classList.add('open');
  if (activeId === 'scan-session-search' || activeId === 'scan-session-rename-input') {
    const restored = document.getElementById(activeId);
    if (restored) {
      restored.value = activeVal;
      restored.focus();
      if (activeSelStart != null) restored.setSelectionRange(activeSelStart, activeSelStart);
    }
  }
}

// El color de estado (dot de la sesión, píldora del status strip) sale de
// las clases .aa-st-<status> del CSS de la página — antes era un style
// inline con los viejos tokens --scan-*.

function toggleScanSessionMenu() { document.getElementById('scan-session-dropdown')?.classList.toggle('open'); }
function closeScanSessionMenu()  { document.getElementById('scan-session-dropdown')?.classList.remove('open'); }
document.addEventListener('click', e => { if (!e.target.closest('.scan-session-picker')) closeScanSessionMenu(); });

function _scanSessionSearchInput(value) { _sessionSearchQuery = value; renderSessionPicker(); }

function startRenameSession(id) {
  _renamingSessionId = id;
  renderSessionPicker();
  const input = document.getElementById('scan-session-rename-input');
  input?.focus();
  input?.select();
}

function cancelRenameSession() {
  // Se pone en null ANTES de re-renderizar a propósito: sacar el <input>
  // del DOM (vía innerHTML) le dispara un blur solo — con esto ya en null,
  // el guard de saveRenameSession() de abajo lo detecta y no guarda nada.
  _renamingSessionId = null;
  renderSessionPicker();
}

async function saveRenameSession(id, value) {
  if (_renamingSessionId !== id) return; // ya se salió por Escape — no pisar
  _renamingSessionId = null;
  const name = value.trim();
  const s = _scanSessions.find(x => x.id === id);
  if (!name || !s || name === s.name) { renderSessionPicker(); return; }
  try {
    await api.aiScan.renameSession(state.currentProject.id, id, name);
    s.name = name;
    if (_scanSession && _scanSession.id === id) _scanSession.name = name;
  } catch (e) { showToast(e.message, 'error'); }
  renderSessionPicker();
}

let _scanDeleteTargetId = null; // sesión pendiente de confirmar en #scan-delete-confirm-modal

// Reemplaza el confirm() nativo por el modal propio — pedido explícito
// ("acorde a la estética"). Ver #scan-delete-confirm-modal en ai-agent.html.
function scanDeleteSession(id) {
  const s = _scanSessions.find(x => x.id === id);
  if (!s) return;
  if (s.status === 'running') { showToast(t('cantDeleteRunning'), 'error'); return; }

  closeScanSessionMenu(); // que no quede el dropdown abierto atrás del modal
  _scanDeleteTargetId = id;
  document.getElementById('scan-delete-confirm-text').textContent =
    t('confirmDeleteText', { date: new Date(s.started_at).toLocaleString() });
  document.getElementById('scan-delete-confirm-modal').classList.add('open');
}

function closeScanDeleteConfirm() {
  document.getElementById('scan-delete-confirm-modal').classList.remove('open');
  _scanDeleteTargetId = null;
}

async function confirmScanDeleteSession() {
  const id = _scanDeleteTargetId;
  if (!id) return;
  closeScanDeleteConfirm();

  try {
    await api.aiScan.deleteSession(state.currentProject.id, id);
    _scanSessions = _scanSessions.filter(x => x.id !== id);
    if (_scanSession && _scanSession.id === id) {
      // Era la que estabas mirando — volvé al estado sin sesión activa.
      _scanSession = null;
      _scanThreads = [];
      renderEmptyState();
      renderInputRow();
      renderThreadsStrip();
      renderTabsBar();
      renderStatusStrip();
    }
    renderSessionPicker();
    showToast(t('sessionDeleted'), 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// Tira de estado por thread — invisible con 1 solo thread (el caso normal
// hoy), aparece apenas hay un delegate_to_subagent de por medio. Antes,
// con multi-agente, todo vivía mezclado en una sola lista lineal sin
// ninguna forma de ver de un vistazo "qué está haciendo cada agente" — el
// gap V1.5 que quedó anotado en el diseño (ver AI_PENTEST_AGENT.md).
// Estado aproximado, no una réplica exacta de la máquina de estados del
// backend: se actualiza en los dos momentos que sí se pueden inferir con
// certeza del stream de eventos (thread.started → running,
// subagent.reported → completed) — ver handleScanEvent(). Para el estado
// exacto de un thread puntual (¿tiene una gate pendiente ahora mismo?),
// las tarjetas del transcript siguen siendo la fuente de verdad.
function renderThreadsStrip() {
  const el = document.getElementById('scan-threads');
  if (!el) return;
  if (_scanThreads.length <= 1) { el.style.display = 'none'; el.innerHTML = ''; return; }

  el.style.display = 'flex';
  el.innerHTML = _scanThreads.map(thr => {
    const isPrimary = !thr.parent_thread_id;
    const label = isPrimary ? t('coordinator') : (thr.label || t('subAgent'));
    const status = thr.status || 'running';
    return `<span class="scan-thread-chip ${esc(status)}" title="${esc(label)} — ${esc(statusLabel(status))}"><span class="dot"></span><span class="aa-thread-ic">${isPrimary ? _aaIcon('bot', 12) : icon('workflow', { size: 12 })}</span><span class="aa-thread-label">${esc(label.slice(0, 80))}</span><span>· ${esc(statusLabel(status))}</span></span>`;
  }).join('');
}

// ── Pestañas: Chat / Detalle / Resumen ───────────────────────────────
function renderTabsBar() {
  const el = document.getElementById('scan-tabs');
  if (!el) return;
  // La fila de pestañas también aloja el indicador de actividad en vivo
  // (#scan-live-activity) — se esconde entera sin sesión.
  const row = document.getElementById('aa-tabs-row');
  if (!_scanSession) { el.style.display = 'none'; if (row) row.style.display = 'none'; return; }
  el.style.display = 'flex';
  if (row) row.style.display = 'flex';
  const nTools = _scanEvents.filter(e => e.type === 'tool.called').length;
  const nVulns = (state.customVulns || []).length;
  // Aviso en Chat cuando hay una aprobación pendiente y estás mirando otra pestaña.
  const pendingGate = _scanSession.status === 'waiting_approval' && _scanActiveTab !== 'chat';
  const tabs = [
    ['chat', 'tabChat', pendingGate ? '<span class="td-tab-n is-alert">!</span>' : ''],
    ['detalle', 'tabDetalle', `<span class="td-tab-n">${nTools}</span>`],
    ['resumen', 'tabResumen', `<span class="td-tab-n">${nVulns}</span>`],
  ];
  el.innerHTML = tabs.map(([id, key, badge]) =>
    `<button class="scan-tab ${_scanActiveTab === id ? 'active' : ''}" role="tab" aria-selected="${_scanActiveTab === id}" onclick="scanSelectTab('${id}')">${esc(t(key))}${badge}</button>`
  ).join('');
}

function scanSelectTab(tabId) {
  if (tabId === _scanActiveTab) return;
  _scanActiveTab = tabId;
  renderTabsBar();
  renderActiveTabPanel();
}

// El panel de Chat vive siempre en el DOM (nunca se destruye) — su
// contenido (#scan-transcript) se actualiza en vivo de forma incremental
// (appendLiveEvent()) sin importar qué pestaña esté visible ahora mismo,
// así al volver a Chat ya está al día. Detalle/Resumen sí se recalculan
// por completo cada vez que se activan — son vistas derivadas baratas de
// recomputar, sin ningún estado de scroll/foco que preservar entre pasadas.
function renderActiveTabPanel() {
  ['chat', 'detalle', 'resumen'].forEach(id => {
    document.getElementById(`scan-panel-${id}`)?.classList.toggle('active', id === _scanActiveTab);
  });
  if (_scanActiveTab === 'detalle') renderDetalleTab();
  else if (_scanActiveTab === 'resumen') renderResumenTab();
}

// ── Indicador de actividad en vivo ──────────────────────────────────────
// Pedido explícito: "sería bueno que haya algún icono moviéndose... con un
// mensaje breve de lo que está haciendo la IA". Heurística simple, no un
// estado nuevo del backend: mira el ÚLTIMO evento del historial completo
// (todos los threads) — si es un `tool.called` sin `tool.result` todavía,
// está ejecutando esa tool; si no, está "pensando" (esperando la respuesta
// del proveedor). En `waiting_approval` muestra qué tool específica quiere
// correr, para que el mensaje siga siendo útil ahí también.
// Devuelve { text, isToolCall } — `isToolCall` distingue "hay una tool call
// puntual en curso" (ya se ve como su propia fila en el transcript de
// Detalle, mostrar el banner ahí sería redundante) de "pensando/esperando al
// proveedor" (NO tiene ninguna otra señal en Detalle — ver renderLiveActivity).
function computeCurrentActivity() {
  if (!_scanSession) return null;
  const status = _scanSession.status;
  if (status !== 'running' && status !== 'waiting_approval') return null;

  const resultsByCallId = {};
  _scanEvents.forEach(e => { if (e.type === 'tool.result') resultsByCallId[String(e.payload.call_id)] = e; });

  for (let i = _scanEvents.length - 1; i >= 0; i--) {
    const ev = _scanEvents[i];
    if (ev.type !== 'tool.called') continue;
    if (resultsByCallId[String(ev.id)]) break; // la última call ya tiene resultado — nada pendiente
    return {
      isToolCall: true,
      text: status === 'waiting_approval'
        ? t('waitingApprovalFor', { tool: ev.payload.name })
        : t('executingTool', { tool: ev.payload.name }),
    };
  }
  return { isToolCall: false, text: status === 'waiting_approval' ? t('waitingApproval') : t('thinking') };
}

// Reportado: el banner mostraba SIEMPRE "Pensando en el próximo paso..." —
// otros textos ("Ejecutando X...") se veían por microsegundos y quedaban
// tapados enseguida. Causa real: muchas tools (propose_finding,
// get_existing_findings, etc.) resuelven casi instantáneo — tool.called y
// su tool.result llegan como dos mensajes de WS separados por milisegundos,
// así que computeCurrentActivity() vuelve al genérico "pensando" antes de
// que el texto específico llegue a ser legible. No es un bug del cálculo en
// sí — es que nada protegía la legibilidad del texto ya mostrado. Con este
// mínimo, bajar de "haciendo algo puntual" a "pensando" espera este tiempo;
// subir (aparece una tool call nueva) sigue siendo inmediato.
const MIN_ACTIVITY_DISPLAY_MS = 900;
let _liveActivityShownAt = 0;
let _liveActivityWasToolCall = false;
let _liveActivityDebounceTimer = null;

function renderLiveActivity() {
  const el = document.getElementById('scan-live-activity');
  if (!el) return;

  const activity = computeCurrentActivity();
  clearTimeout(_liveActivityDebounceTimer);

  if (!activity) {
    _liveActivityWasToolCall = false;
    el.textContent = '';
    document.getElementById('scan-typing-bubble')?.remove();
    return;
  }

  if (_liveActivityWasToolCall && !activity.isToolCall) {
    const elapsed = Date.now() - _liveActivityShownAt;
    if (elapsed < MIN_ACTIVITY_DISPLAY_MS) {
      _liveActivityDebounceTimer = setTimeout(renderLiveActivity, MIN_ACTIVITY_DISPLAY_MS - elapsed);
      return;
    }
  }

  _liveActivityShownAt = Date.now();
  _liveActivityWasToolCall = activity.isToolCall;

  // La burbuja de "escribiendo..." sigue siendo exclusiva del chat (Detalle
  // ya muestra cada tool call puntual como su propia fila, sería redundante
  // ahí) — pero el texto en la status strip (esta función) es global a la
  // sesión, visible sea cual sea la pestaña activa, ver README del rediseño.
  renderTypingBubble(activity);
  el.textContent = activity.text;
}

// Burbuja de "escribiendo..." dentro del transcript — pedido explícito: "que
// en el mismo chat aparezca una animación... que indique que la IA está
// formulando la respuesta". Se agrega/saca del DOM directamente (no
// re-renderiza `_scanEvents`) para no competir con appendLiveEvent(), que ya
// maneja el resto del transcript de forma incremental.
// Reportado: los puntitos "se cortan a cada rato y vuelven". Antes se sacaba
// en cada tool call puntual y en cada evento nuevo, y se recreaba con la
// animación de entrada — pero el chat ni siquiera muestra las tools de
// Nivel 0/1, así que desde el lado del pentester era un parpadeo sin motivo.
// Ahora vive mientras el agente trabaja (`running`, con o sin tool call en
// curso); solo se va cuando para o cuando espera una aprobación (ahí la
// tarjeta del gate ya es la señal).
function renderTypingBubble(activity) {
  const el = document.getElementById('scan-transcript');
  if (!el) return;
  const existing = document.getElementById('scan-typing-bubble');
  if (!activity || _scanSession?.status === 'waiting_approval') { existing?.remove(); return; }
  if (existing) return; // ya está mostrada — appendLiveEvent() inserta los eventos nuevos antes que ella

  const wasAtBottom = scanIsNearBottom(el);
  const node = document.createElement('div');
  node.className = 'scan-msg assistant scan-msg-enter';
  node.id = 'scan-typing-bubble';
  node.innerHTML = `<span class="who"><span class="aa-av">${_aaIcon('bot', 12)}</span>${esc(t('agentLabel'))}</span><div class="bubble scan-typing-dots"><span></span><span></span><span></span></div>`;
  node.addEventListener('animationend', () => node.classList.remove('scan-msg-enter'), { once: true });
  el.appendChild(node);
  if (wasAtBottom) scanScrollToBottom();
}

// Recorre TODOS los eventos y arma los baldes de highlights. No intenta
// replicar la forma exacta de cada tool.result — solo lee los campos que
// ya expone cada tool (`open_ports`, `found`, `url`/`status`, `error`...),
// así que agregar una tool nueva no rompe esto (simplemente no aporta a
// ningún balde hasta que se le agregue soporte acá).
function computeScanHighlights(events) {
  const resultsByCallId = {};
  events.forEach(ev => { if (ev.type === 'tool.result') resultsByCallId[String(ev.payload.call_id)] = ev; });

  const ports = new Map();       // "host:port" → {host, port}
  const endpoints = new Map();   // url → {url, status}
  const subdomains = new Map();  // subdomain → {subdomain, addresses, reachable, status, error}
  const review = [];             // { label, detail }
  const findings = [];           // { ev, result }
  let wildcardWarning = null;

  const noteEndpoint = (out) => { if (out?.url && out?.status != null) endpoints.set(out.url, { url: out.url, status: out.status, body: out.body_preview || out.content || null }); };
  const noteError = (name, out) => { if (out?.error) review.push({ label: name, detail: out.error }); };

  for (const ev of events) {
    if (ev.type !== 'tool.called') continue;
    const result = resultsByCallId[String(ev.id)];

    if (ev.payload.name === 'propose_finding') { findings.push({ ev, result }); continue; }

    // Gate de Nivel 2/3 sin resolver todavía — independiente de si terminó
    // llegando un output útil o no.
    if ((ev.payload.tier ?? 0) >= 2 && !result) {
      review.push({ label: t('waitingApprovalReview', { name: ev.payload.name }), detail: JSON.stringify(ev.payload.input).slice(0, 120) });
      continue;
    }
    if (!result) continue; // todavía ejecutándose

    const out = result.payload.result; // ver agentLoop.js — forma consistente gated/auto-ejecutado
    if (!out) continue;

    if (ev.payload.name === 'port_scan' && Array.isArray(out.open_ports)) {
      out.open_ports.forEach(p => ports.set(`${out.host}:${p}`, { host: out.host, port: p }));
    } else if (ev.payload.name === 'subdomain_enum') {
      (out.found || []).forEach(s => subdomains.set(s.subdomain, s));
      (out.resolution_errors || []).forEach(e => review.push({ label: `DNS: ${e.subdomain}`, detail: e.error }));
      if (out.wildcard_warning) wildcardWarning = out.wildcard_warning;
    } else if (ev.payload.name === 'run_exploit_poc' && Array.isArray(out.steps)) {
      out.steps.forEach(s => { noteEndpoint(s); noteError(`${ev.payload.name} (${out.technique})`, s); });
    } else {
      noteEndpoint(out);
    }
    noteError(ev.payload.name, out);
  }

  return {
    ports: [...ports.values()], endpoints: [...endpoints.values()],
    subdomains: [...subdomains.values()], review, findings, wildcardWarning,
  };
}

// Mismas clases .sev-badge/.sev-{level} globales que vulns.js severityBadge()
// — se duplica acá (3 líneas) en vez de compartir función porque vulns.js no
// se carga en esta página. Reportado: la severidad en "Hallazgos propuestos"
// aparecía como texto plano sin color que la identifique.
const _SEV_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
function _severityBadge(sev) {
  const s = sev || 'medium';
  return `<span class="sev-badge sev-${esc(s)}">${esc(_SEV_LABELS[s] || s)}</span>`;
}

// La vieja UI de chips (ports/endpoints/subdominios/hallazgos/para revisar)
// se retiró con el rediseño — sus datos ahora viven repartidos donde tiene
// más sentido cada uno: endpoints/para-revisar como contadores en
// renderStatusStrip(), hallazgos propuestos ya se ven en el Chat (tarjeta
// de gate), y cada port_scan/subdomain_enum individual sigue totalmente
// visible (con su detalle completo) como su propia fila en Detalle. La
// vista AGREGADA de puertos/subdominios (dedupe entre varias llamadas) no
// tiene un lugar propio en las 3 pestañas nuevas — ver README del
// rediseño, que no la contempla como concepto de UI.

// ── Pestaña Detalle: feed vertical de acciones de la IA ─────────────────
// A diferencia de Chat (filtrado, solo conversación real), acá se ve CADA
// tool.called sin importar el tier, más las líneas de sistema (inicio,
// pausa, checkpoints...) — es el feed completo de "qué está haciendo la
// IA", ver README del rediseño. No fabrica pasos futuros/"pendientes": solo
// muestra lo que efectivamente ya se llamó, con su estado real (done si ya
// tiene resultado, running si no).
// Texto de un turn.checkpoint según su `reason` (agentLoop.js). Hoy el
// backend solo emite 'no_progress' (freno de racha sin resultados, bd446dd);
// el de iteraciones no trae reason, y el presupuesto es otro evento
// (session.cost_cap_reached). Un reason desconocido —p. ej. de un backend
// más nuevo que este JS cacheado— cae al texto genérico en vez de romper.
const CHECKPOINT_REASON_KEYS = { no_progress: 'checkpointNoProgress' };

function checkpointText(payload = {}) {
  const key = payload.reason && CHECKPOINT_REASON_KEYS[payload.reason];
  if (key) return t(key, { calls: payload.calls });
  return payload.auto
    ? t('checkpointAuto', { calls: payload.calls })
    : t('checkpointManual', { calls: payload.calls });
}

const DETALLE_SYSTEM_TYPES = new Set(['session.started', 'session.error', 'session.paused', 'session.resumed', 'session.cost_cap_reached', 'thread.started', 'turn.checkpoint']);

function _detalleSystemLineText(ev) {
  switch (ev.type) {
    case 'session.started': return t('sessionStarted');
    case 'session.error': return t('errorLine', { reason: ev.payload.reason });
    case 'session.paused': return t('pausedLine');
    case 'session.resumed': return t('resumedLine');
    case 'session.cost_cap_reached': return t('costCapReachedLine', { cap: `$${Number(ev.payload.cap).toFixed(2)}`, spent: `$${Number(ev.payload.spent).toFixed(4)}` });
    case 'thread.started': return t('subagentDelegated', { task: ev.payload.task });
    case 'turn.checkpoint': return checkpointText(ev.payload);
    default: return ev.type;
  }
}

// Resumen corto del input de una tool para la fila del timeline (url,
// método+path, host...) — solo lectura de campos comunes, una tool nueva
// sin ninguno de estos simplemente cae al primer valor escalar.
function _aaInputSummary(input) {
  if (!input || typeof input !== 'object') return '';
  if (input.method || input.path) return `${input.method || 'GET'} ${input.path || '/'}`;
  if (input.url) return String(input.url);
  if (Array.isArray(input.request_sequence)) return `${input.technique || ''} · ${input.request_sequence.length} req`.trim();
  if (input.host) return input.ports ? `${input.host} · ${input.ports}` : String(input.host);
  for (const k of ['domain', 'task', 'name', 'query', 'target']) if (typeof input[k] === 'string') return input[k];
  const first = Object.values(input).find(v => typeof v === 'string' || typeof v === 'number');
  return first != null ? String(first) : '';
}

// Salida "útil" de un tool.result: las dos formas de payload que existen
// (ver renderResolvedGate) — anidada en `result`, o el payload del gate
// resuelto (decision/reason/error) sin los campos de enlace.
function _aaResultOutput(result) {
  const p = (result && result.payload) || {};
  if ('result' in p) return p.result;
  const { call_id, name, ...rest } = p; // eslint-disable-line no-unused-vars
  return rest;
}

// Estado visible de una tool call en el timeline. Sin resultado: si la
// sesión ya terminó quedó "sin resolver"; si es Nivel 2+ gateada, espera
// aprobación; si no, sigue corriendo.
function _aaToolState(ev, result) {
  const terminal = _scanSession && (_scanSession.status === 'error' || _scanSession.status === 'completed');
  if (!result) {
    if (terminal) return 'stale';
    const autonomous = !!(state.currentProject && state.currentProject.ai_autonomous_requests);
    return (ev.payload.tier ?? 0) >= 2 && !autonomous ? 'waiting' : 'running';
  }
  const p = result.payload || {};
  if (p.decision === 'rejected' || p.error || (p.result && (p.result.error || p.result.decision === 'rejected'))) return 'error';
  return 'done';
}

const _AA_TEXT_FIELDS = ['body_preview', 'content', 'body', 'html', 'output', 'stdout', 'stderr'];
const _AA_TOOL_STATE_ICON = { done: 'check', waiting: 'triangle-alert', error: 'x', stale: 'minus' };

function _aaSysKind(ev) {
  const p = ev.payload || {};
  switch (ev.type) {
    case 'session.started': return ['play', 'done'];
    case 'session.error': return ['circle-x', 'error'];
    case 'session.paused': return ['pause', 'warn'];
    case 'session.resumed': return ['play', 'sys'];
    case 'session.cost_cap_reached': return ['triangle-alert', 'warn'];
    case 'thread.started': return ['workflow', 'sys'];
    case 'turn.checkpoint': return p.auto && !CHECKPOINT_REASON_KEYS[p.reason] ? ['rotate-ccw', 'sys'] : ['pause', 'warn'];
    default: return ['info', 'sys'];
  }
}

// Detalle expandido de una tool: para las HTTP se reconstruye el
// request/response legible (igual que en las tarjetas del Chat); para el
// resto, input/output como JSON. Todo en bloques numerados plegables.
function _aaToolDetail(ev, result) {
  const name = ev.payload.name;
  const input = ev.payload.input;
  const out = result ? _aaResultOutput(result) : undefined;
  const k = String(ev.id);
  const blocks = [];
  if (name === 'run_exploit_poc' && Array.isArray(input && input.request_sequence)) {
    const steps = Array.isArray(out && out.steps) ? out.steps : [];
    input.request_sequence.forEach((req, i) => {
      blocks.push(_aaCode(`${t('requestLabel')} ${i + 1}`, formatHttpRequestPreview(req), `${k}:rq${i}`));
      if (steps[i]) blocks.push(_aaCode(`${t('responseLabel')} ${i + 1}`, formatHttpResponsePreview(steps[i]), `${k}:rs${i}`, { error: !!steps[i].error }));
    });
  } else if (isHttpTool(name) && input) {
    blocks.push(_aaCode(t('requestLabel'), formatHttpRequestPreview(input), `${k}:rq`));
    if (out && (out.status != null || out.error)) blocks.push(_aaCode(t('responseLabel'), formatHttpResponsePreview(out), `${k}:rs`, { error: !!out.error }));
    else if (out !== undefined) blocks.push(_aaCode(t('outputLabel'), _aaJson(out), `${k}:out`));
  } else {
    blocks.push(_aaCode(t('inputLabel'), _aaJson(input), `${k}:in`));
    // Campos de texto multilínea (HTML de fetch_endpoint, etc.) van en su
    // propio bloque: dentro del JSON quedaban como una sola línea con "\n".
    const texts = out && typeof out === 'object' && !Array.isArray(out)
      ? _AA_TEXT_FIELDS.filter(f => typeof out[f] === 'string' && out[f].includes('\n')) : [];
    if (texts.length) {
      const rest = { ...out };
      texts.forEach(f => delete rest[f]);
      blocks.push(_aaCode(t('outputLabel'), _aaJson(rest), `${k}:out`, { error: !!out.error }));
      texts.forEach(f => blocks.push(_aaCode(f, out[f], `${k}:o_${f}`)));
    } else if (out !== undefined) {
      blocks.push(_aaCode(t('outputLabel'), _aaJson(out), `${k}:out`, { error: !!(out && out.error) }));
    }
  }
  return blocks.join('');
}

function renderDetalleTab() {
  const el = document.getElementById('scan-panel-detalle');
  if (!el) return;

  const resultsByCallId = {};
  _scanEvents.forEach(ev => { if (ev.type === 'tool.result') resultsByCallId[String(ev.payload.call_id)] = ev; });

  const rows = _scanEvents.filter(ev => ev.type === 'tool.called' || DETALLE_SYSTEM_TYPES.has(ev.type));
  const heading = `<div class="scan-panel-heading">${icon('list', { size: 12 })} ${esc(t('detailHeading'))}</div>`;

  if (!rows.length) {
    el.innerHTML = `${heading}<div class="scan-detail-empty">${esc(t('detailEmpty'))}</div>`;
    return;
  }

  // Etiqueta del sub-agente dueño del evento (el coordinador no lleva chip).
  const subLabel = threadId => {
    const th = _scanThreads.find(x => x.id === threadId);
    return th && th.parent_thread_id ? (th.label || t('subAgent')) : null;
  };

  let nTools = 0, nRunning = 0, nErr = 0;
  const html = rows.map(ev => {
    const isTool = ev.type === 'tool.called';
    const expanded = ev.id != null && _expandedDetailIds.has(ev.id);
    const when = _aaClock(ev.created_at);
    let dot, main, chips = '', full = '';
    let expandable = ev.id != null;

    if (isTool) {
      nTools++;
      const result = resultsByCallId[String(ev.id)];
      const st = _aaToolState(ev, result);
      if (st === 'running' || st === 'waiting') nRunning++;
      if (st === 'error') nErr++;
      const dotCls = st === 'stale' ? 'sys' : st;
      dot = `<span class="aa-ic scan-detail-dot ${dotCls}">${st === 'running' ? '<span class="aa-spin"></span>' : icon(_AA_TOOL_STATE_ICON[st], { size: 12 })}</span>`;
      const summary = _aaInputSummary(ev.payload.input);
      main = `<span class="scan-detail-text">${esc(ev.payload.name)}</span>${summary ? `<span class="scan-detail-sub" title="${esc(summary)}">${esc(summary.slice(0, 240))}</span>` : ''}`;
      const owner = subLabel(ev.thread_id);
      const dur = result ? _aaDuration(ev.created_at, result.created_at) : null;
      chips = `${owner ? `<span class="aa-chip aa-chip-plain" title="${esc(owner)}">${icon('workflow', { size: 10 })} ${esc(owner.slice(0, 18))}</span>` : ''}${_aaTierChip(ev.payload.tier ?? 0)}${dur ? `<span class="aa-chip aa-chip-plain">${esc(dur)}</span>` : ''}`;
      if (expanded) full = _aaToolDetail(ev, result);
    } else {
      const [ic, cls] = _aaSysKind(ev);
      dot = `<span class="aa-ic scan-detail-dot ${cls}">${icon(ic, { size: 12 })}</span>`;
      main = `<span class="scan-detail-text is-sys">${esc(_detalleSystemLineText(ev))}</span>`;
      // Un payload vacío ({}) no tiene nada que mostrar al expandir.
      expandable = expandable && ev.payload && Object.keys(ev.payload).length > 0;
      if (expanded && expandable) full = _aaCode(t('payloadLabel'), _aaJson(ev.payload), `${ev.id}:p`);
    }

    return `
      <div class="scan-detail-row ${expanded && full ? 'expanded' : ''} ${isTool ? '' : 'is-sys'}">
        <div class="scan-detail-row-head" ${expandable ? `onclick="toggleDetailRow('${esc(String(ev.id))}')"` : ''}>
          ${dot}
          <div class="scan-detail-body">${main}</div>
          ${chips ? `<div class="aa-tl-chips">${chips}</div>` : ''}
          <div class="scan-detail-time mono" title="${esc(ev.created_at ? new Date(ev.created_at).toLocaleString() : '')}">${esc(when)}</div>
          ${expandable ? `<div class="scan-detail-chevron">${icon('chevron-right', { size: 14 })}</div>` : ''}
        </div>
        ${full ? `<div class="scan-detail-full">${full}</div>` : ''}
      </div>
    `;
  }).join('');

  el.innerHTML = `
    <div class="aa-tl-head">
      ${heading}
      <div class="aa-tl-sum">
        <span class="aa-chip aa-chip-plain">${esc(t('detailCountActions', { n: nTools }))}</span>
        ${nRunning ? `<span class="aa-chip aa-http-4">${esc(t('detailCountRunning', { n: nRunning }))}</span>` : ''}
        ${nErr ? `<span class="aa-chip aa-http-err">${esc(t('detailCountErrors', { n: nErr }))}</span>` : ''}
      </div>
    </div>
    <div class="scan-detail-feed">${html}</div>
  `;
}

function toggleDetailRow(eventId) {
  const ev = _scanEvents.find(e => String(e.id) === String(eventId));
  const id = ev ? ev.id : eventId;
  if (_expandedDetailIds.has(id)) _expandedDetailIds.delete(id);
  else _expandedDetailIds.add(id);
  renderDetalleTab();
}

// ── Pestaña Resumen: hallazgos del proyecto por severidad ───────────────
// A diferencia de Chat/Detalle (ambos sobre _scanEvents, esta sesión
// puntual), Resumen lee state.customVulns — los hallazgos REALES del
// proyecto (ya confirmados/guardados), no lo que esta sesión particular
// propuso. Ver README del rediseño: "findings... a nivel de proyecto, no
// por sesión" — confirmado como la interpretación correcta acá.
const SCAN_SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function _aaStatCard(cls, iconHtml, label, count, sub, barPct, small) {
  return `
    <div class="ss-card ${cls}">
      <div class="ss-top"><span class="ss-icon">${iconHtml}</span><span class="ss-label">${esc(label)}</span></div>
      <div class="ss-count${small ? ' is-sm' : ''}">${esc(String(count))}</div>
      ${barPct != null ? `<div class="ss-bar"><span class="aa-bar-fill" style="width:${Math.max(0, Math.min(100, barPct)).toFixed(1)}%"></span></div>` : ''}
      ${sub ? `<div class="ss-sub">${esc(sub)}</div>` : ''}
    </div>`;
}

function renderResumenTab() {
  const el = document.getElementById('scan-panel-resumen');
  if (!el) return;

  const vulns = state.customVulns || [];
  const counts = {};
  SCAN_SEV_ORDER.forEach(s => counts[s] = 0);
  vulns.forEach(v => { const s = v.severity || 'medium'; if (counts[s] !== undefined) counts[s]++; });
  const total = vulns.length;

  // Bloque "Esta sesión": agregados de computeScanHighlights() (dedupe
  // entre varias llamadas) — puertos/subdominios no tenían ningún lugar
  // propio desde que se retiró la vieja UI de chips.
  const hl = computeScanHighlights(_scanEvents);
  const nTools = _scanEvents.filter(e => e.type === 'tool.called').length;
  const hosts = new Set(hl.ports.map(p => p.host)).size;
  const unreachable = hl.subdomains.filter(s => s.reachable === false || s.error).length;
  const cost = Number(_scanSession && _scanSession.total_cost) || 0;
  const cap = Number(_scanSession && _scanSession.ai_max_cost_usd) || 0;
  const sessionCards = [
    _aaStatCard('aa-k-actions', icon('zap', { size: 14 }), t('statActions'), nTools, null, null),
    _aaStatCard('aa-k-endpoints', _aaIcon('globe', 14), t('statEndpoints'), hl.endpoints.length, null, null),
    _aaStatCard('aa-k-ports', _aaIcon('network', 14), t('statPorts'), hl.ports.length, hosts ? t('statHosts', { n: hosts }) : null, null),
    _aaStatCard('aa-k-subs', icon('search', { size: 14 }), t('statSubdomains'), hl.subdomains.length, unreachable ? t('statUnreachable', { n: unreachable }) : null, null),
    _aaStatCard('aa-k-cost', _aaIcon('coins', 14), t('statCost'), `$${cost.toFixed(cost >= 100 ? 2 : 4)}`,
      cap ? t('statCostCap', { cap: `$${cap.toFixed(2)}` }) : t('statNoCap'), cap ? (cost / cap) * 100 : null, true),
  ].join('');

  const sevCards = SCAN_SEV_ORDER.map(sev => _aaStatCard(
    `aa-sev-${sev}`, _aaIcon('shield', 14), _SEV_LABELS[sev], counts[sev],
    t('pctOfTotal', { pct: total ? Math.round((counts[sev] / total) * 100) : 0 }),
    total ? (counts[sev] / total) * 100 : 0,
  )).join('');

  const sessionSec = _scanSession ? `
    <div class="aa-sum-sec">
      <div class="scan-panel-heading">${_aaIcon('bot', 12)} ${esc(t('sessionStatsHeading'))}</div>
      <div class="aa-ss-grid">${sessionCards}</div>
    </div>` : '';

  const sevSec = `
    <div class="aa-sum-sec">
      <div class="scan-panel-heading">${_aaIcon('shield', 12)} ${esc(t('resumenHeading'))} <span class="aa-opt">· ${total}</span></div>
      <div class="aa-ss-grid">${sevCards}</div>
    </div>`;

  if (!vulns.length) {
    el.innerHTML = `${sessionSec}${sevSec}<div class="scan-detail-empty">${esc(t('resumenEmpty'))}</div>`;
    return;
  }

  // Cada fila abre el hallazgo en My Vulns (mismo deep-link que usa el
  // drawer de Targets: vulns?pid=…&vuln=…).
  const pid = encodeURIComponent(state.currentProject.id);
  const sorted = [...vulns].sort((a, b) => SCAN_SEV_ORDER.indexOf(a.severity || 'medium') - SCAN_SEV_ORDER.indexOf(b.severity || 'medium'));
  const rows = sorted.map(v => {
    const remStatus = v.remediation_status || 'open';
    const meta = [
      remStatus !== 'open' ? `<span class="vr-tag">${esc(t(`rem_${remStatus}`))}</span>` : '',
      v.category ? `<span>${esc(v.category)}</span>` : '',
      v.cwe ? `<span>${esc(String(v.cwe))}</span>` : '',
      v.cvss_score != null ? `<span>CVSS ${esc(String(v.cvss_score))}</span>` : '',
    ].filter(Boolean).join('<span class="td-dot">·</span>');
    return `
      <a class="td-finding" href="vulns?pid=${pid}&amp;vuln=${esc(encodeURIComponent(v.id))}" title="${esc(t('openInVulns'))}">
        ${_severityBadge(v.severity || 'medium')}
        <span class="td-finding-text">
          <span class="td-finding-name">${esc(v.name)}</span>
          ${meta ? `<span class="td-finding-meta">${meta}</span>` : ''}
        </span>
        <span class="td-finding-go">${icon('chevron-right', { size: 14 })}</span>
      </a>`;
  }).join('');

  el.innerHTML = `${sessionSec}${sevSec}<div class="td-list aa-findings">${rows}</div>`;
}

async function switchScanSession(id) {
  clearTimeout(_liveActivityDebounceTimer);
  _liveActivityWasToolCall = false;
  if (!id) {
    _scanSession = null;
    _scanThreads = [];
    renderEmptyState();
    renderInputRow();
    renderSessionPicker();
    renderThreadsStrip();
    renderTabsBar();
    renderStatusStrip();
    return;
  }
  await loadSession(id);
}

async function loadSession(sessionId) {
  const data = await api.aiScan.getSession(state.currentProject.id, sessionId);
  _scanSession = data.session;
  _scanEvents  = data.events;
  _scanThreads = data.threads || [];
  _expandedDetailIds = new Set(); // sesión distinta — sin nada abierto todavía
  _aaFullCode = new Set();
  _scanActiveTab = 'chat'; // volvemos siempre a Chat al cambiar de sesión
  _showScanPanels(true);
  renderSessionPicker();
  renderThreadsStrip();
  renderTabsBar();
  renderStatusStrip();
  renderInputRow();
  renderTranscript();
  renderActiveTabPanel();
}

// Sin sesión activa (todavía no se arrancó ninguna, o se acaba de borrar/
// deseleccionar) las pestañas y sus paneles no tienen nada que mostrar — se
// esconden del todo y el formulario de arranque ocupa ese espacio. Con una
// sesión sí, es al revés. Un solo lugar para esta decisión evita tener que
// acordarse de tocar los 3 elementos en cada punto que cambia _scanSession.
function _showScanPanels(show) {
  const panels = document.getElementById('scan-tab-panels');
  const emptyWrap = document.getElementById('scan-empty-wrap');
  if (panels) panels.style.display = show ? 'flex' : 'none';
  if (show && emptyWrap) emptyWrap.innerHTML = '';
}

// ── Arrancar una sesión nueva ─────────────────────────────────────────
function renderEmptyState() {
  _showScanPanels(false);
  const inScopeTargets = (state.targets || []).filter(t => t.scope === 'in');
  const el = document.getElementById('scan-empty-wrap');
  // "Escanear con AI Agent" en Targets manda acá con ?target=<id> — pedido
  // explícito de integrarse mejor con el ecosistema, en vez de tener que
  // volver a elegir el target a mano después de ya haberlo abierto en
  // Targets. Preselecciona, no auto-arranca — sigue siendo un click
  // explícito del pentester.
  const presetTarget = new URLSearchParams(window.location.search).get('target');
  const findingsCount = (state.customVulns || []).length;
  const autonomousDefault = !!state.currentProject.ai_autonomous_requests;
  // Se queda inline en vez de pasar a un drawer: sin sesión, este formulario
  // ES el contenido de la página — un drawer agregaría un click y dejaría
  // un vacío detrás. Mismo lenguaje que los drawers (secciones, pie fijo).
  el.innerHTML = `
    <div class="scan-empty">
      <div class="aa-start-hero">
        <div class="aa-mark">${_aaIcon('bot', 19)}</div>
        <div>
          <div class="aa-start-title">${esc(t('newSessionTitle'))}</div>
          <div class="scan-empty-desc">${esc(t('emptyStateDesc'))}</div>
          <div class="aa-start-chips">
            <span class="aa-chip aa-c-scope">${_aaIcon('target', 11)} ${inScopeTargets.length} ${esc(t(inScopeTargets.length === 1 ? 'inScopeLabel' : 'inScopeLabel_other'))}</span>
            <span class="aa-chip aa-c-findings">${_aaIcon('shield', 11)} ${findingsCount} ${esc(t('findingsLabel'))}</span>
            <span class="aa-chip ${autonomousDefault ? 'aa-http-4' : 'aa-http-2'}">${icon(autonomousDefault ? 'zap' : 'check', { size: 11 })} ${esc(t(autonomousDefault ? 'autonomousOnChip' : 'gatesOnChip'))}</span>
          </div>
        </div>
      </div>
      <div class="aa-start-body">
        <div class="form-group">
          <label class="form-label" for="scan-start-target">${esc(t('targetLabel'))} <span class="aa-opt">${esc(t('targetOptionalNote'))}</span></label>
          <select class="form-input" id="scan-start-target">
            <option value="">${esc(t('wholeProjectOption'))}</option>
            ${inScopeTargets.map(tg => `<option value="${esc(String(tg.id))}" ${tg.id === presetTarget ? 'selected' : ''}>${esc(tg.host)}</option>`).join('')}
          </select>
        </div>
        <div class="form-group">
          <label class="form-label" for="scan-start-instruction">${esc(t('initialInstructionLabel'))} <span class="aa-opt">${esc(t('instructionOptionalNote'))}</span></label>
          <textarea class="form-input note-textarea" id="scan-start-instruction" placeholder="${esc(t('instructionPlaceholder'))}"></textarea>
        </div>
        <details class="aa-adv">
          <summary>
            <span class="aa-chev">${icon('chevron-right', { size: 13 })}</span>
            ${esc(t('advancedOptions'))} <span class="aa-adv-note">${esc(t('advancedOptionsNote'))}</span>
          </summary>
          <div class="aa-adv-body">
            <div class="form-group">
              <label class="form-label" for="scan-start-profile">${esc(t('profileLabel'))}</label>
              <select class="form-input" id="scan-start-profile">
                <option value="pentest">${esc(t('profilePentest'))}</option>
                <option value="ctf">${esc(t('profileCtf'))}</option>
                <option value="lab">${esc(t('profileLab'))}</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label" for="scan-start-provider">${esc(t('providerLabel'))}</label>
              <select class="form-input" id="scan-start-provider">
                ${['groq', 'anthropic', 'deepseek', 'kimi', 'custom'].map(p =>
                  `<option value="${p}" ${p === (state.currentProject.ai_provider || 'groq') ? 'selected' : ''}>${p}</option>`
                ).join('')}
              </select>
            </div>
            <div class="form-group">
              <label class="form-label" for="scan-start-model">${esc(t('modelLabel'))}</label>
              <input type="text" class="form-input" id="scan-start-model" placeholder="${esc(t('modelPlaceholder'))}" value="${esc(state.currentProject.ai_model || '')}">
            </div>
            <div class="form-group">
              <label class="form-label" for="scan-start-cost-cap">${esc(t('costCapLabel'))} <span class="aa-opt">USD</span></label>
              <input type="number" min="0.01" step="0.01" class="form-input" id="scan-start-cost-cap" placeholder="${esc(t('costCapPlaceholder'))}">
            </div>
            <div class="aa-toggle-row">
              <span><span class="aa-toggle-label">${esc(t('autonomousModeLabel'))}</span><span class="aa-toggle-hint">${esc(t('autonomousModeHint'))}</span></span>
              <button type="button" class="setting-toggle ${autonomousDefault ? 'on' : ''}" id="scan-start-autonomous"
                aria-label="${esc(t('autonomousModeLabel'))}" onclick="this.classList.toggle('on')">
                <span class="setting-toggle-knob"></span>
              </button>
            </div>
            <div class="aa-toggle-row">
              <span><span class="aa-toggle-label">${esc(t('singleAgentLabel'))}</span><span class="aa-toggle-hint">${esc(t('singleAgentHint'))}</span></span>
              <button type="button" class="setting-toggle ${state.currentProject.ai_single_agent ? 'on' : ''}" id="scan-start-single-agent"
                aria-label="${esc(t('singleAgentLabel'))}" onclick="this.classList.toggle('on')">
                <span class="setting-toggle-knob"></span>
              </button>
            </div>
          </div>
        </details>
      </div>
      <div class="aa-start-foot">
        <span class="aa-hint">${esc(t('startLangHint', { lang: t('langName') }))}</span>
        <button class="btn btn-prim aa-start-btn" onclick="scanStartSession()">${icon('play', { size: 12 })} ${esc(t('startScanBtn'))}</button>
      </div>
    </div>
  `;
}

async function scanStartSession() {
  const target_id   = document.getElementById('scan-start-target').value || null;
  const instruction = document.getElementById('scan-start-instruction').value.trim() || null;
  // Config de IA de "Opciones avanzadas" — precargada con el default del
  // proyecto (ver renderEmptyState()), se manda tal cual se haya tocado o
  // no. Queda fija para toda la sesión, pisando la del proyecto — ver el
  // merge `effective` en agentLoop.js advance().
  const ai_provider = document.getElementById('scan-start-provider')?.value || null;
  const ai_model     = document.getElementById('scan-start-model')?.value.trim() || null;
  const ai_autonomous_requests = document.getElementById('scan-start-autonomous')?.classList.contains('on') || false;
  const ai_single_agent        = document.getElementById('scan-start-single-agent')?.classList.contains('on') || false;
  // 'pentest' (el default del <select>) se manda como null — es el
  // comportamiento actual sin cambios, no hace falta que el backend lo trate
  // como un valor distinto de "sin perfil".
  const profileValue = document.getElementById('scan-start-profile')?.value || 'pentest';
  const ai_profile = profileValue === 'pentest' ? null : profileValue;
  const costCapRaw = document.getElementById('scan-start-cost-cap')?.value.trim();
  const ai_max_cost_usd = costCapRaw ? Number(costCapRaw) : null;
  try {
    // `lang`: lo que valía el toggle ES/EN en este momento — fijo para toda
    // la sesión (ver migrate.js). El agente lo usa vía buildSystemPrompt()
    // para responder en ese idioma, no solo la interfaz.
    const { session } = await api.aiScan.createSession(state.currentProject.id, {
      target_id, instruction, lang: getAiLang(),
      ai_provider, ai_model, ai_autonomous_requests, ai_single_agent, ai_profile, ai_max_cost_usd,
    });
    _scanSessions.unshift(session);
    await loadSession(session.id);
    showToast(t('scanStarted'), 'success');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ── Status strip: estado global + contadores + Pausar/Interrumpir ──────
// Reemplaza al viejo .scan-toolbar (contexto + controles + highlights en 3
// piezas separadas) — ver README del rediseño. Se reconstruye entera en
// cada llamada (barato: solo arreglos en memoria + un computeScanHighlights
// sobre los eventos ya cargados), incluyendo el <span> de actividad en vivo
// que renderLiveActivity() puebla al final — un solo punto de entrada en
// vez de tener que acordarse de llamar a los dos por separado en cada sitio.
function renderStatusStrip() {
  const el = document.getElementById('scan-status-strip');
  if (!el) return;
  if (!_scanSession) { el.innerHTML = ''; renderLiveActivity(); return; }

  const s = _scanSession.status;
  const inScope  = (state.targets || []).filter(tg => tg.scope === 'in').length;
  const findings = (state.customVulns || []).length;
  const hl = computeScanHighlights(_scanEvents);

  let actions = '';
  if (s === 'running') {
    actions = `<button class="scan-btn-pause" onclick="scanPause()">${icon('pause', { size: 13 })} ${esc(t('pause'))}</button><button class="scan-btn-interrupt" onclick="scanInterruptPrompt()">${icon('zap', { size: 13 })} ${esc(t('interrupt'))}</button>`;
  } else if (s === 'paused') {
    actions = `<button class="scan-btn-resume" onclick="scanResume()">${icon('play', { size: 13 })} ${esc(t('resume'))}</button>`;
  } else if (s === 'error') {
    // Reintenta el turno que falló contra el proveedor (sin fondos, rate
    // limit, red) sin tener que escribir un mensaje — ver retry() en agentLoop.js.
    actions = `<button class="scan-btn-resume" onclick="scanRetry()">${icon('rotate-ccw', { size: 13 })} ${esc(t('retry'))}</button>`;
  }

  const inScopeLabel = t(inScope === 1 ? 'inScopeLabel' : 'inScopeLabel_other');
  el.innerHTML = `
    <div class="scan-status-dot-label aa-st-${esc(s)}${s === 'running' ? ' is-live' : ''}">
      <span class="dot"></span>
      <span class="label">${esc(statusLabel(s))}</span>
    </div>
    <div class="aa-stats">
      <div class="scan-counter aa-c-scope" title="${inScope} ${esc(inScopeLabel)}"><span class="aa-ic">${_aaIcon('target', 12)}</span><span class="n">${inScope}</span><span class="label">${esc(inScopeLabel)}</span></div>
      <div class="scan-counter aa-c-findings${findings ? ' clickable' : ''}" title="${findings} ${esc(t('findingsLabel'))}" ${findings ? `onclick="scanSelectTab('resumen')"` : ''}><span class="aa-ic">${_aaIcon('shield', 12)}</span><span class="n">${findings}</span><span class="label">${esc(t('findingsLabel'))}</span></div>
      ${_counterPopoverWrap('endpoints', hl.endpoints.length, t('endpointsLabel'), hl.endpoints, e => `
        <div class="scan-counter-popover-row"><span class="mono url" title="${esc(e.url)}">${esc(e.url)}</span>${_aaHttpChip(e)}</div>
      `, false, _aaIcon('globe', 12), 'aa-c-endpoints')}
      ${hl.review.length ? _counterPopoverWrap('review', hl.review.length, t('reviewLabel'), hl.review, r => `
        <div class="scan-counter-popover-row col"><span class="label">${esc(r.label)}</span><span class="detail mono">${esc(r.detail || '')}</span></div>
      `, true, icon('triangle-alert', { size: 12 }), 'aa-c-review') : ''}
    </div>
    <div class="scan-status-spacer"></div>
    <div class="scan-status-actions">${actions}</div>
  `;
  renderLiveActivity();
}

// Contador clickeable del status strip que despliega su contenido real —
// antes (pre-rediseño) esto vivía en la vieja UI de chips; el rediseño lo
// redujo a un número plano sin forma de ver qué hay detrás. `accentN`
// pinta el número en el color de acento (usado para "para revisar").
function _counterPopoverWrap(key, count, label, items, renderItem, accentN, iconHtml = '', toneCls = '') {
  const clickable = count > 0;
  const open = clickable && _scanCounterPopoverOpen === key;
  const onclick = clickable ? `onclick="event.stopPropagation();toggleCounterPopover('${key}')"` : '';
  return `
    <div class="scan-counter-popover-wrap">
      <div class="scan-counter ${toneCls}${clickable ? ' clickable' : ''}${open ? ' is-open' : ''}" title="${count} ${esc(label)}" ${onclick}>
        ${iconHtml ? `<span class="aa-ic">${iconHtml}</span>` : ''}<span class="n${accentN ? ' accent' : ''}">${count}</span><span class="label">${esc(label)}</span>
      </div>
      ${clickable ? `
      <div class="scan-counter-popover ${open ? 'open' : ''}">
        <div class="scan-counter-popover-head">${esc(label)} · ${count}</div>
        <div class="scan-counter-popover-list">${items.map(renderItem).join('')}</div>
      </div>` : ''}
    </div>
  `;
}

function toggleCounterPopover(key) {
  _scanCounterPopoverOpen = _scanCounterPopoverOpen === key ? null : key;
  renderStatusStrip();
}

function closeCounterPopovers() {
  if (!_scanCounterPopoverOpen) return;
  _scanCounterPopoverOpen = null;
  renderStatusStrip();
}
document.addEventListener('click', e => { if (!e.target.closest('.scan-counter-popover-wrap')) closeCounterPopovers(); });

function renderInputRow() {
  const row   = document.getElementById('scan-input-row');
  const input = document.getElementById('scan-chat-input');
  if (!_scanSession) { row.style.display = 'none'; return; }
  row.style.display = 'flex';
  // `error` NO es terminal: es un fallo al hablar con el proveedor (sin
  // fondos, rate limit, red) — un mensaje nuevo revive los threads y
  // reintenta (ver sendMessage() en agentLoop.js).
  const terminal = _scanSession.status === 'completed';
  const blocked  = terminal || _scanSession.status === 'waiting_approval' || _scanSession.status === 'paused';
  input.disabled = blocked;
  input.placeholder = terminal
    ? t('sessionEndedPlaceholder')
    : _scanSession.status === 'error'
      ? t('sessionErrorPlaceholder')
      : _scanSession.status === 'waiting_approval'
        ? t('resolveApprovalPlaceholder')
        : _scanSession.status === 'paused'
          ? t('resumeToChatPlaceholder')
          : t('chatPlaceholder');
}

// Chat es SIEMPRE la vista filtrada — las tools de Nivel 0/1 (ruido
// individual: cada fetch_endpoint, cada port_scan) no aparecen acá, ver
// Detalle (renderDetalleTab()) para el feed completo con cada una. La
// conversación real (chat, gates de Nivel 2/3, reportes de sub-agentes,
// líneas de sistema) sí se muestra siempre — eso no es "ruido".
function shouldRenderInTranscript(ev) {
  if (ev.type === 'tool.called' && (ev.payload.tier ?? 0) < 2) return false;
  return true;
}

// ── Transcript ───────────────────────────────────────────────────────
// Rebuild completo — solo para cargar/cambiar de sesión (loadSession()).
// Acá está bien tirar todo el DOM: no hay nada que preservar en ese caso.
function renderTranscript() {
  const el = document.getElementById('scan-transcript');
  scanBindTranscriptScroll();
  scanHideJumpPill(); // rebuild completo — arranca anclado al fondo (ver final)
  if (!_scanEvents.length) { el.innerHTML = ''; return; }

  const resultsByCallId = {};
  _scanEvents.forEach(ev => { if (ev.type === 'tool.result') resultsByCallId[String(ev.payload.call_id)] = ev; });

  el.innerHTML = '';
  _scanEvents.forEach(ev => {
    if (ev.type === 'tool.result') return; // se renderiza junto a su tool.called, no aparte
    if (!shouldRenderInTranscript(ev)) return;
    const node = renderEvent(ev, resultsByCallId);
    node.dataset.eventId = String(ev.id);
    el.appendChild(node);
  });
  el.scrollTop = el.scrollHeight;
}

// Actualización incremental — usada por handleScanEvent() para cada evento
// que llega en vivo. A diferencia de renderTranscript(), NUNCA reconstruye
// el DOM entero: solo agrega el evento nuevo, o (si es un tool.result)
// reemplaza el ÚNICO nodo del tool.called que resuelve. Todo lo demás en
// pantalla queda intacto — un <details> que dejaste abierto en un tool call
// anterior ya no se cierra solo cada vez que llega otro evento (bug
// reportado: al re-renderizar TODO en cada mensaje de WS, cualquier
// <details> abierto se perdía, y el auto-scroll-al-final te sacaba de
// donde estabas leyendo aunque no tuviera nada que ver con el evento nuevo).
// ── Autoscroll del transcript ───────────────────────────────────────────
// Umbral generoso a propósito: mientras estés "cerca" del fondo seguís
// anclado y cada mensaje nuevo baja solo. Apenas te alejás para leer
// historial, dejamos de arrastrarte y en su lugar aparece la píldora.
const SCAN_STICK_THRESHOLD = 120;

function scanIsNearBottom(el) {
  return el.scrollHeight - el.scrollTop - el.clientHeight < SCAN_STICK_THRESHOLD;
}

function scanScrollToBottom(smooth) {
  const el = document.getElementById('scan-transcript');
  if (!el) return;
  el.scrollTo({ top: el.scrollHeight, behavior: smooth ? 'smooth' : 'auto' });
  scanHideJumpPill();
}

function scanShowJumpPill() {
  document.getElementById('scan-jump-btn')?.classList.add('show');
}
function scanHideJumpPill() {
  document.getElementById('scan-jump-btn')?.classList.remove('show');
}

// Si el usuario scrollea hasta el fondo a mano, la píldora ya no tiene sentido.
function scanBindTranscriptScroll() {
  const el = document.getElementById('scan-transcript');
  if (!el || el._scanScrollBound) return;
  el._scanScrollBound = true;
  el.addEventListener('scroll', () => { if (scanIsNearBottom(el)) scanHideJumpPill(); });
}

function appendLiveEvent(ev) {
  const el = document.getElementById('scan-transcript');
  // La burbuja de "escribiendo..." NO se saca acá (eso la hacía parpadear en
  // cada evento): los eventos nuevos se insertan ANTES que ella, así queda
  // siempre al final. renderLiveActivity() (que corre después en
  // handleScanEvent()) decide si sigue o se va con el estado post-evento.
  const typingBubble = document.getElementById('scan-typing-bubble');
  if (!el.children.length || (el.children.length === 1 && typingBubble)) { renderTranscript(); return; } // primer evento de una sesión recién arrancada — sin nada que preservar

  const wasAtBottom = scanIsNearBottom(el);
  // Un mensaje del agente (respuesta, o reporte de sub-agente) es lo que el
  // pentester está esperando ver — si llega mientras mira historial, avisamos.
  const isIncomingMessage =
    (ev.type === 'chat.message' && ev.payload.role !== 'user') ||
    ev.type === 'subagent.reported';

  if (ev.type === 'tool.result') {
    const calledEv = _scanEvents.find(e => e.type === 'tool.called' && String(e.id) === String(ev.payload.call_id));
    const existing = el.querySelector(`[data-event-id="${ev.payload.call_id}"]`);
    if (calledEv && existing) {
      const fresh = renderEvent(calledEv, { [String(ev.payload.call_id)]: ev });
      fresh.dataset.eventId = String(calledEv.id);
      existing.replaceWith(fresh);
    }
  } else {
    if (!shouldRenderInTranscript(ev)) return; // escondido en modo simple — ya resumido en las tarjetas de highlights
    const node = renderEvent(ev, {}); // recién llegado — nunca tiene tool.result todavía
    node.dataset.eventId = String(ev.id);
    node.classList.add('scan-msg-enter'); // entrada suave — solo en vivo
    el.insertBefore(node, typingBubble); // null (sin burbuja) = appendChild
  }

  if (wasAtBottom) scanScrollToBottom();
  else if (isIncomingMessage) scanShowJumpPill();
}

function renderEvent(ev, resultsByCallId) {
  if (ev.type === 'chat.message')      return renderChatMessage(ev);
  if (ev.type === 'tool.called')       return renderToolCalled(ev, resultsByCallId);
  if (ev.type === 'subagent.reported') return renderSubagentReport(ev);
  return renderSystemLine(ev);
}

// A diferencia del markdown de whiteboard.js (lo escriben tus propios
// compañeros de equipo, contenido confiable), lo que este agente muestra
// puede llevar texto influenciado por el sitio target — contenido externo y
// potencialmente adversarial que el modelo leyó (fetch_page_source,
// send_http_request, etc.) y puede terminar citando en su propia respuesta.
// `marked.parse()` solo no sanitiza HTML embebido — si el modelo repite un
// payload malicioso del target en su texto, se ejecutaría tal cual en el
// navegador de cualquiera mirando la sesión. DOMPurify.sanitize() cierra
// ese hueco (encontrado en revisión, no en el whiteboard original).
// Fails closed on purpose: if DOMPurify did not load, fall back to escaped plain
// text instead of rendering unsanitised markup. The previous `DOMPurify ? … : html`
// dropped the defence in exactly the situation it was written for — a network
// where the library cannot be fetched.
function renderMarkdown(text) {
  if (!window.marked || !window.DOMPurify) return `<p>${esc(text || '')}</p>`;
  return window.DOMPurify.sanitize(window.marked.parse(text || ''));
}

// Reporte de un sub-agente al terminar su tarea delegada — se renderiza
// como un mensaje, no como una línea de sistema chica, porque es contenido
// sustancial (lo que encontró), no solo un cambio de estado.
function renderSubagentReport(ev) {
  const div = document.createElement('div');
  div.className = 'scan-msg assistant is-sub';
  div.innerHTML = `<span class="who"><span class="aa-av is-sub">${icon('workflow', { size: 12 })}</span>${esc(ev.payload.label || t('subAgent'))}${_aaWhen(ev.created_at)}</span><div class="bubble">${renderMarkdown(ev.payload.summary)}</div>`;
  return div;
}

function renderChatMessage(ev) {
  const div = document.createElement('div');
  const isUser = ev.payload.role === 'user';
  div.className = `scan-msg ${isUser ? 'user' : 'assistant'}`;
  const bubbleHtml = isUser ? `<p>${esc(ev.payload.text || '')}</p>` : renderMarkdown(ev.payload.text);
  const name = isUser ? usernameFor(ev.created_by) : t('agentLabel');
  const avatar = isUser
    ? `<span class="aa-av is-user">${esc((name || '?').trim().charAt(0).toUpperCase())}</span>`
    : `<span class="aa-av">${_aaIcon('bot', 12)}</span>`;
  div.innerHTML = `<span class="who">${avatar}${esc(name)}${_aaWhen(ev.created_at)}</span><div class="bubble">${bubbleHtml}</div>`;
  return div;
}

// Returns raw user text (display name) — callers must esc() it.
function usernameFor(userId) {
  if (userId && state.user && userId === state.user.id) return t('you');
  const m = (state.members || []).find(x => x.id === userId || x.user_id === userId);
  return m ? displayName(m) : t('pentester');
}

// T0/T1/T2/T3 no son "tareas" — son el NIVEL DE RIESGO de la tool, lo que
// decide si necesita tu aprobación (ver AI_PENTEST_AGENT.md § Superficie de
// tools). El tooltip existe porque "T" solo, sin más contexto, confunde.
function tierTitle(tier) { return t(`tier${tier}Title`); }

// Reportado: propose_finding/update_finding se mostraban como
// JSON.stringify crudo — con los http_proofs ilegibles (los `\n` del
// request/response quedan escapados como texto en vez de saltos de línea
// reales) y sin ninguna jerarquía visual. Este helper arma el cuerpo de la
// tarjeta para esos dos tools específicamente — se usa desde los 3 estados
// de gate y desde el fallback autónomo de abajo. Otros tools gateados
// (send_http_request, test_payload, run_exploit_poc) no tienen este schema
// y siguen con su `<pre>JSON</pre>` tal cual, no fueron señalados como
// ilegibles.
function isFindingTool(name) { return name === 'propose_finding' || name === 'update_finding'; }

// Los proofs de un hallazgo del agente ya no los escribe el modelo: el
// backend los arma desde los evidence_refs citados (evidence.js) y los deja
// en `evidence_proofs` del tool.called — son las respuestas reales que vio.
// Una llamada vieja sin ese campo sigue mostrando sus http_proofs.
function findingCardInput(payload) {
  const input = payload.input || {};
  return Array.isArray(payload.evidence_proofs) ? { ...input, http_proofs: payload.evidence_proofs } : input;
}

// Status de la primera línea de una respuesta HTTP cruda ("HTTP/1.1 500").
function _aaRawHttpStatus(raw) {
  const m = typeof raw === 'string' && raw.match(/^HTTP\/[\d.]+\s+(\d{3})/);
  return m ? _aaHttpChip({ status: Number(m[1]) }) : '';
}

function renderFindingCardBody(input, key = 'f') {
  const parts = [];

  // Reportado: update_finding casi nunca trae `name` (solo manda los campos
  // que cambia), así que la tarjeta decía "(sin nombre)" y no había forma de
  // saber qué hallazgo estaba tocando. Se resuelve por `finding_id` contra
  // los hallazgos del proyecto ya cargados; un `name` en el input (renombre)
  // sigue teniendo prioridad.
  const existing = input.finding_id ? (state.customVulns || []).find(v => String(v.id) === String(input.finding_id)) : null;
  const name = input.name || existing?.name;
  const severity = input.severity || existing?.severity;

  parts.push(`
    <div class="scan-finding-head">
      ${severity ? _severityBadge(severity) : ''}
      <strong>${esc(name || t('unnamed'))}</strong>
    </div>
  `);

  // Metadatos como chips (antes vivían escondidos en el <summary> de la remediación).
  const chips = [];
  if (input.category) chips.push(`<span class="aa-chip aa-chip-plain scan-finding-tag">${esc(String(input.category))}</span>`);
  if (input.remediation_status) chips.push(`<span class="aa-chip aa-http-2 scan-finding-tag">${esc(t(`rem_${input.remediation_status}`))}</span>`);
  if (input.cwe) chips.push(`<span class="aa-chip aa-chip-plain">${esc(String(input.cwe))}</span>`);
  if (input.cvss_score != null) chips.push(`<span class="aa-chip ${_aaCvssTone(input.cvss_score)}">CVSS ${esc(String(input.cvss_score))}</span>`);
  if (input.confidence) chips.push(`<span class="aa-chip aa-chip-plain">${esc(t('confidenceLabel'))}: ${esc(String(input.confidence))}</span>`);
  if (chips.length) parts.push(`<div class="aa-chips">${chips.join('')}</div>`);

  if (input.description) parts.push(`<p class="scan-finding-desc">${esc(String(input.description))}</p>`);
  // update_finding de un retest — el pentester tiene que ver qué estado y
  // qué notas está aprobando, no solo el nombre del hallazgo.
  if (input.retest_notes || input.retest_date) {
    parts.push(`<p class="scan-finding-desc"><strong>${esc(t('retestNotesLabel'))}${input.retest_date ? ` (${esc(String(input.retest_date))})` : ''}:</strong> ${esc(String(input.retest_notes || ''))}</p>`);
  }

  if (input.remediation) {
    parts.push(`
      <details class="scan-finding-remediation">
        <summary><span class="aa-chev">${icon('chevron-right', { size: 12 })}</span>${esc(t('showRemediation'))}</summary>
        <p>${esc(String(input.remediation))}</p>
      </details>
    `);
  }

  if (Array.isArray(input.http_proofs) && input.http_proofs.length) {
    parts.push(`
      <div class="aa-sec-label">${esc(t('evidenceLabel'))} <span class="aa-n">${input.http_proofs.length}</span></div>
      <div class="scan-finding-proofs">
        ${input.http_proofs.map((p, i) => `
          <details class="scan-proof-item">
            <summary>
              <span class="aa-chev">${icon('chevron-right', { size: 12 })}</span>
              <span class="aa-proof-n">${i + 1}</span>
              ${p.method ? `<span class="aa-chip aa-chip-plain">${esc(String(p.method))}</span>` : ''}
              <span class="aa-proof-t">${esc(p.annotation ? String(p.annotation) : t('proofLabel', { n: i + 1 }))}</span>
              ${_aaRawHttpStatus(p.response)}
            </summary>
            <div class="aa-proof-body">
              ${p.request ? _aaCode(t('requestLabel'), p.request, `${key}:p${i}:rq`) : ''}
              ${p.response ? _aaCode(t('responseLabel'), p.response, `${key}:p${i}:rs`) : ''}
            </div>
          </details>
        `).join('')}
      </div>
    `);
  }

  return `<div class="scan-finding-card">${parts.join('')}</div>`;
}

// Mismo problema que propose_finding pero con otro schema: send_http_request/
// test_payload/run_exploit_poc mandan method+path+headers+body por separado
// (no un string de HTTP crudo como http_proofs) y la respuesta trae
// status/headers/body_preview como campos sueltos — reconstruimos un texto
// tipo request/response real para que se lea igual de bien que un proof.
function isHttpTool(name) { return name === 'send_http_request' || name === 'test_payload' || name === 'run_exploit_poc'; }

function formatHttpRequestPreview(req) {
  const lines = [`${req.method || 'GET'} ${req.path || '/'} HTTP/1.1`];
  if (req.headers) for (const [k, v] of Object.entries(req.headers)) lines.push(`${k}: ${v}`);
  if (req.body) { lines.push(''); lines.push(String(req.body)); }
  return lines.join('\n');
}

function formatHttpResponsePreview(res) {
  if (!res) return '';
  if (res.error) return res.error;
  const lines = [`HTTP/1.1 ${res.status ?? '?'}`];
  if (res.headers) for (const [k, v] of Object.entries(res.headers)) lines.push(`${k}: ${v}`);
  if (res.body_preview != null) { lines.push(''); lines.push(res.body_preview); }
  return lines.join('\n');
}

// `output` es el resultado de sendRequest() (scanToolsLevel2.js) — para
// send_http_request/test_payload directo, para run_exploit_poc adentro de
// `.steps[]`. `null` cuando todavía no corrió (gate pendiente/stale).
function renderHttpToolCardBody(name, input, output, key = 'h') {
  const parts = [];
  const proof = (i, req, res, label) => `
    <details class="scan-proof-item">
      <summary>
        <span class="aa-chev">${icon('chevron-right', { size: 12 })}</span>
        ${i != null ? `<span class="aa-proof-n">${i + 1}</span>` : ''}
        <span class="aa-chip aa-chip-plain">${esc(String(req.method || 'GET'))}</span>
        <span class="aa-proof-t" title="${esc(String(req.path || '/'))}">${esc(label)}</span>
        ${_aaHttpChip(res)}
      </summary>
      <div class="aa-proof-body">
        ${_aaCode(t('requestLabel'), formatHttpRequestPreview(req), `${key}:rq${i ?? ''}`)}
        ${res ? _aaCode(t('responseLabel'), formatHttpResponsePreview(res), `${key}:rs${i ?? ''}`, { error: !!res.error }) : ''}
      </div>
    </details>`;

  if (name === 'run_exploit_poc') {
    parts.push(`<div class="scan-finding-head"><strong class="mono">${esc(String(input.technique || name))}</strong></div>`);
    const steps = Array.isArray(input.request_sequence) ? input.request_sequence : [];
    const results = Array.isArray(output && output.steps) ? output.steps : [];
    parts.push(`
      <div class="aa-sec-label">${esc(t('requestLabel'))} <span class="aa-n">${steps.length}</span></div>
      <div class="scan-finding-proofs">${steps.map((req, i) => proof(i, req, results[i], String(req.path || '/'))).join('')}</div>
    `);
    return `<div class="scan-finding-card">${parts.join('')}</div>`;
  }

  parts.push(`<div class="scan-finding-head"><strong class="mono">${esc(String(input.method || ''))} ${esc(String(input.path || ''))}</strong></div>`);
  if (name === 'test_payload' && input.param_name) {
    parts.push(`<p class="scan-finding-desc">${input.category ? `<span class="aa-chip aa-chip-plain scan-finding-tag">${esc(String(input.category))}</span> ` : ''}<code>${esc(String(input.param_location))}.${esc(String(input.param_name))}</code> ← <code>${esc(String(input.payload))}</code></p>`);
  }
  parts.push(`<div class="scan-finding-proofs">${proof(null, input, output, String(input.path || '/'))}</div>`);
  return `<div class="scan-finding-card">${parts.join('')}</div>`;
}

// Cabecera común de las tarjetas de tool (gate pendiente/resuelto/rancio
// y ejecución autónoma): ícono de estado + título + tool/nivel + hora.
const _AA_GATE_KINDS = {
  pending:  ['triangle-alert', 'gatePendingTitle'],
  accepted: ['circle-check',   'gateAccepted'],
  rejected: ['circle-x',       'gateRejected'],
  stale:    ['minus',          'gateStale'],
  auto:     ['zap',            'gateAuto'],
  failed:   ['circle-x',       'gateFailed'],
};
function _aaGateHead(ev, kind) {
  const [ic, key] = _AA_GATE_KINDS[kind] || _AA_GATE_KINDS.stale;
  const when = _aaClock(ev.created_at);
  return `
    <div class="scan-gate-head">
      <span class="aa-ic">${icon(ic, { size: 13 })}</span>
      <div class="aa-gate-titles">
        <div class="aa-gate-title">${esc(t(key))}</div>
        <div class="aa-gate-sub"><strong>${esc(ev.payload.name)}</strong>${_aaTierChip(ev.payload.tier ?? 0)}</div>
      </div>
      ${when ? `<span class="aa-gate-time" title="${esc(new Date(ev.created_at).toLocaleString())}">${esc(when)}</span>` : ''}
    </div>`;
}

// Cuerpo según la tool: hallazgo, HTTP, o el input como bloque de código.
function _aaGateBody(ev, httpOutput) {
  const name = ev.payload.name;
  if (isFindingTool(name)) return renderFindingCardBody(findingCardInput(ev.payload), `g${ev.id}`);
  if (isHttpTool(name)) return renderHttpToolCardBody(name, ev.payload.input, httpOutput, `g${ev.id}`);
  return _aaCode(t('inputLabel'), _aaJson(ev.payload.input), `g${ev.id}:in`);
}

// Ejecución de una tool HTTP SIN gate (modo sin restricciones) — mismo
// lenguaje visual que un gate resuelto, pero sin aprobado/rechazado: acá
// nunca hubo una aprobación que dar, solo se ejecutó directo. `result`
// puede ser null si el tool.result todavía no llegó.
function renderAutoExecutedTool(ev, result) {
  const output = result ? result.payload.result : null;
  const failed = !!(output && output.error);
  const div = document.createElement('div');
  div.className = `scan-gate ${failed ? 'is-failed' : 'is-auto'}`;
  div.innerHTML = `
    ${_aaGateHead(ev, failed ? 'failed' : 'auto')}
    <div class="aa-gate-body">${renderHttpToolCardBody(ev.payload.name, ev.payload.input, output, `g${ev.id}`)}</div>
  `;
  return div;
}

function renderToolCalled(ev, resultsByCallId) {
  const result = resultsByCallId[String(ev.id)];
  const tier = ev.payload.tier ?? 0;

  // Nivel 2/3 se renderiza como gate SOLO si el proyecto realmente las
  // gatea — con ai_autonomous_requests prendido corren solas, igual que
  // Nivel 0/1, y agentLoop.js nunca produce un tool.result con forma
  // {decision,...} para ellas (bug encontrado en revisión: sin este
  // chequeo, cualquier tier≥2 auto-ejecutada se mostraba como "✗ Rechazado"
  // aunque hubiera corrido bien — renderResolvedGate esperaba un campo que
  // simplemente no existía).
  const autonomous = !!(state.currentProject && state.currentProject.ai_autonomous_requests);
  if (tier >= 2 && !autonomous) {
    if (result) return renderResolvedGate(ev, result);
    // Una gate sin tool.result todavía puede estar realmente pendiente, o
    // puede ser un remanente de una sesión que terminó (error/completed)
    // antes de que alguien la resolviera — en ese caso resolveGatedCall
    // hace un no-op silencioso si igual la aprobás, así que mostrarla con
    // botones activos es un botón muerto sin ningún feedback (encontrado en
    // revisión, con una captura real de este estado exacto).
    const terminal = _scanSession && (_scanSession.status === 'error' || _scanSession.status === 'completed');
    return terminal ? renderStaleGate(ev) : renderPendingGate(ev);
  }

  // Reportado: en modo autónomo, un propose_finding/update_finding (tier 3)
  // ya ejecutado caía en el fallback genérico de abajo — dos <pre>JSON</pre>
  // (input + result) apilados sin separación, la pared de texto ilegible
  // reportada. Mismo cuerpo de tarjeta que un gate resuelto, sin necesitar
  // el chequeo de tier<2 de renderResolvedGate (acá el tier SIEMPRE es ≥2).
  if (result && isFindingTool(ev.payload.name)) return renderResolvedGate(ev, result);
  // Mismo caso que arriba pero para send_http_request/test_payload/
  // run_exploit_poc ejecutadas sin gate — antes caían al fallback genérico
  // de abajo (dos <pre>JSON</pre> apilados, ilegible, reportado en vivo).
  if (isHttpTool(ev.payload.name)) return renderAutoExecutedTool(ev, result);

  const div = document.createElement('div');
  div.className = 'scan-tool';
  // Un spinner (sigue) vs. un check verde (terminó) se nota de un vistazo
  // sin tener que leer cada fila.
  const statusIcon = result
    ? icon('circle-check', { size: 13, class: 'scan-tool-done' })
    : '<span class="aa-spin scan-tool-spinner"></span>';
  div.innerHTML = `
    ${statusIcon}
    <details>
      <summary><span class="aa-chev">${icon('chevron-right', { size: 12 })}</span>${esc(ev.payload.name)} ${_aaTierChip(tier)}${_aaWhen(ev.created_at)}</summary>
      ${_aaCode(t('inputLabel'), _aaJson(ev.payload.input), `t${ev.id}:in`)}
      ${result ? _aaCode(t('outputLabel'), _aaJson(result.payload.result), `t${ev.id}:out`) : ''}
    </details>
  `;
  return div;
}

function renderPendingGate(ev) {
  const isFinding = ev.payload.name === 'propose_finding';
  const div = document.createElement('div');
  div.className = 'scan-gate is-pending';
  div.innerHTML = `
    ${_aaGateHead(ev, 'pending')}
    <div class="aa-gate-body">${_aaGateBody(ev, null)}</div>
    <div class="aa-gate-foot">
      <span class="aa-gate-hint">${esc(t('gatePendingHint'))}</span>
      <div class="scan-gate-actions">
        <button class="btn aa-btn-reject" onclick="scanReject(${ev.id})">${icon('x', { size: 13 })} ${esc(t('reject'))}</button>
        ${isFinding ? `<button class="btn" onclick="scanEditAndAdd(${ev.id})">${icon('square-pen', { size: 13 })} ${esc(t('editAndAdd'))}</button>` : ''}
        <button class="btn btn-prim" onclick="scanApprove(${ev.id})">${icon('check', { size: 13 })} ${esc(t('approveAsIs'))}</button>
      </div>
    </div>
  `;
  return div;
}

function renderStaleGate(ev) {
  const div = document.createElement('div');
  div.className = 'scan-gate is-stale';
  div.innerHTML = `
    ${_aaGateHead(ev, 'stale')}
    <div class="aa-gate-body">
      <div class="scan-gate-resolved">${icon('triangle-alert', { size: 12 })}<span>${esc(t('staleGateNote'))}</span></div>
      ${_aaGateBody(ev, null)}
    </div>
  `;
  return div;
}

function renderResolvedGate(ev, result) {
  // Dos shapes de payload posibles, según cómo se resolvió: resolveGatedCall()
  // (aprobación manual del pentester) spreadea {decision, created_vuln_id/
  // reason/error} directo en el payload; la escritura autónoma inline de
  // advance() (sin pasar por el gate — ver agentLoop.js línea ~516-531) los
  // deja anidados bajo `result`, igual que cualquier otro tool.result. Se
  // distingue por la presencia de `decision` en el nivel de arriba — cuando
  // no está, es la variante autónoma y hay que mirar un nivel más adentro.
  const output = 'decision' in result.payload ? result.payload : (result.payload.result || {});
  const decision = output.decision;
  const accepted = decision === 'accepted';
  const div = document.createElement('div');
  div.className = `scan-gate ${accepted ? 'is-accepted' : 'is-rejected'}`;
  // El veredicto ya está en la cabecera — acá va solo el detalle (motivo,
  // hallazgo creado/actualizado, error), si lo hay.
  let note = '';
  if (!accepted && output.reason) note += ` — ${esc(String(output.reason))}`;
  if (output.created_vuln_id) note += ev.payload.name === 'update_finding' ? t('findingUpdatedNote') : t('findingAddedNote');
  if (output.error) note += `${t('errorNotePrefix')}${esc(String(output.error))}`;
  note = note.replace(/^ — /, '');
  div.innerHTML = `
    ${_aaGateHead(ev, accepted ? 'accepted' : 'rejected')}
    <div class="aa-gate-body">
      ${note ? `<div class="scan-gate-resolved ${esc(String(decision || ''))}">${icon(accepted ? 'check' : 'x', { size: 12 })}<span>${note}</span></div>` : ''}
      ${_aaGateBody(ev, output.result || (output.error ? { error: output.error } : null))}
    </div>
  `;
  return div;
}

function renderSystemLine(ev) {
  const div = document.createElement('div');
  const p = ev.payload || {};
  const when = _aaClock(ev.created_at);

  // Banner — para lo que pide atención (error, pausa, tope de gasto).
  const banner = (cls, ic, title, text, extra = '') => {
    div.className = `aa-banner ${cls}`;
    div.innerHTML = `
      <span class="aa-ic">${icon(ic, { size: 13 })}</span>
      <div class="aa-banner-body">
        <div class="aa-banner-title">${esc(title)}</div>
        <div class="aa-banner-text">${esc(text)}</div>
        ${extra}
      </div>
      ${when ? `<span class="aa-banner-time">${esc(when)}</span>` : ''}`;
    return div;
  };

  if (ev.type === 'session.error') return banner('is-err', 'circle-x', t('errorTitle'), String(p.reason ?? ''));

  // Único system.line con una acción propia — subir el tope acá mismo, en
  // vez de mandar al pentester a buscar dónde hacerlo. No retoma la sesión
  // sola (ver el comentario en la ruta PATCH, ai-scan.js): solo actualiza el
  // tope; para seguir hace falta mandar un mensaje de chat, que ya está
  // habilitado (el input no se bloquea en estado `idle`).
  if (ev.type === 'session.cost_cap_reached') {
    return banner('', 'triangle-alert', t('costCapTitle'),
      t('costCapReachedLine', { cap: `$${Number(p.cap).toFixed(2)}`, spent: `$${Number(p.spent).toFixed(4)}` }), `
      <span class="scan-cost-cap-raise">
        <input type="number" min="0.01" step="0.01" class="scan-cost-cap-input" placeholder="${esc(t('costCapPlaceholder'))}">
        <button class="scan-cost-cap-btn" onclick="scanRaiseCostCap(this)">${esc(t('raiseCostCapBtn'))}</button>
      </span>`);
  }

  // Con modo autónomo, el checkpoint sigue de largo solo (`auto: true`)
  // — pedido explícito ("lo de decirle continuá me parece ridículo, la
  // idea es que trabaje solo"). Sin autónomo (o al llegar al freno de
  // última instancia, MAX_AUTO_CHECKPOINTS en agentLoop.js) sí necesita
  // un mensaje de chat para retomar — eso es una pausa real: banner.
  if (ev.type === 'turn.checkpoint' && (!p.auto || CHECKPOINT_REASON_KEYS[p.reason])) {
    return banner('', 'pause', t(p.reason === 'no_progress' ? 'noProgressTitle' : 'checkpointTitle'), checkpointText(p));
  }

  // El resto son cambios de estado — separador liviano con texto.
  const lines = {
    'session.started':  ['play', t('sessionStarted')],
    'session.paused':   ['pause', t('pausedLine')],
    'session.resumed':  ['play', t('resumedLine')],
    'thread.started':   ['workflow', t('subagentDelegated', { task: p.task ?? '' })],
    'turn.checkpoint':  ['rotate-ccw', checkpointText(p)],
  };
  const [ic, text] = lines[ev.type] || ['info', ev.type];
  div.className = 'scan-line';
  div.innerHTML = `<span class="aa-line-in">${icon(ic, { size: 11 })}<span>${esc(String(text))}</span>${when ? `<span class="aa-line-time">· ${esc(when)}</span>` : ''}</span>`;
  return div;
}

async function scanRaiseCostCap(btn) {
  const input = btn.previousElementSibling;
  const value = Number(input.value);
  if (!value || value <= 0) return;
  btn.disabled = true;
  try {
    const updated = await api.aiScan.updateSession(state.currentProject.id, _scanSession.id, { ai_max_cost_usd: value });
    if (_scanSession) _scanSession.ai_max_cost_usd = updated.ai_max_cost_usd;
    input.disabled = true;
    btn.textContent = t('costCapRaised');
    showToast(t('costCapRaised'), 'success');
  } catch (err) {
    btn.disabled = false;
    showToast(err.message, 'error');
  }
}

// ── WebSocket — eventos en vivo ─────────────────────────────────────────
function handleScanEvent(msg) {
  if (!_scanSession || msg.session_id !== _scanSession.id) {
    // Evento de una sesión que no estamos mirando (otro pentester arrancó
    // una nueva, por ejemplo) — no tocamos la vista actual, solo refrescamos
    // el picker por si hay que ofrecerla como opción.
    if (!_scanSessions.some(s => s.id === msg.session_id)) {
      api.aiScan.listSessions(state.currentProject.id).then(list => { _scanSessions = list; renderSessionPicker(); }).catch(() => {});
    }
    return;
  }
  _scanSession.status = msg.status;
  _scanEvents.push(msg.event);
  // Un thread.started en vivo implica un thread nuevo que el catch-up
  // original no tenía — lo agregamos como placeholder mínimo (suficiente
  // para las etiquetas de sub-agente; el catch-up completo lo trae bien
  // formado si se recarga la página).
  if (msg.event.type === 'thread.started' && !_scanThreads.some(t => t.id === msg.event.thread_id)) {
    _scanThreads.push({ id: msg.event.thread_id, parent_thread_id: 'unknown', label: msg.event.payload.task, status: 'running' });
  }
  // Un sub-agente que reporta terminó su tarea delegada — es el único otro
  // momento (además de thread.started) donde se puede inferir con certeza
  // el cambio de estado de un thread puntual desde el stream de eventos.
  if (msg.event.type === 'subagent.reported') {
    const t = _scanThreads.find(th => th.id === msg.event.payload.thread_id);
    if (t) t.status = 'completed';
  }
  renderInputRow();
  appendLiveEvent(msg.event);
  renderSessionPicker();
  renderThreadsStrip();
  renderTabsBar(); // contadores de las pestañas (acciones / aviso de aprobación pendiente)
  renderStatusStrip(); // barato — recomputa contadores + actividad en vivo sobre los eventos ya en memoria
  renderActiveTabPanel(); // no-op si Chat está activa; recompute barato de Detalle/Resumen si no
}

// ── Acciones del pentester ──────────────────────────────────────────────
// Shift+Enter inserta un salto de línea (Enter solo manda) — el textarea
// crece con el contenido hasta el max-height del CSS, después scrollea.
function scanAutosizeInput(input) {
  input.style.height = 'auto';
  input.style.height = `${input.scrollHeight + 2}px`; // +2: borde de 1px arriba/abajo
}

function scanSendMessage() {
  const input = document.getElementById('scan-chat-input');
  const text = input.value.trim();
  if (!text || !_scanSession) return;
  wsClient.send({ type: 'ai_scan:send_message', session_id: _scanSession.id, text });
  input.value = '';
  scanAutosizeInput(input);
  // Al mandar, siempre te llevo al fondo: re-ancla el autoscroll para que el
  // echo de tu mensaje, la burbuja de "escribiendo…" y la respuesta bajen
  // solas. Sin esto, si habías quedado unos px arriba el pin nunca se
  // recuperaba y parecía que la IA no respondía.
  scanScrollToBottom();
  input.focus();
}

function scanApprove(callId) {
  wsClient.send({ type: 'ai_scan:approve_action', session_id: _scanSession.id, call_id: callId });
}

function scanReject(callId) {
  // prompt() nativo a propósito para V1 — es una interacción secundaria y
  // poco frecuente, no amerita un modal propio todavía.
  const reason = window.prompt(t('rejectReasonPrompt')) || undefined;
  wsClient.send({ type: 'ai_scan:reject_action', session_id: _scanSession.id, call_id: callId, reason });
}

function scanPause()  { wsClient.send({ type: 'ai_scan:pause',  session_id: _scanSession.id }); }
function scanResume() { wsClient.send({ type: 'ai_scan:resume', session_id: _scanSession.id }); }
function scanRetry()  { wsClient.send({ type: 'ai_scan:retry',  session_id: _scanSession.id }); }

function scanInterruptPrompt() {
  const instruction = window.prompt(t('interruptPrompt'));
  if (!instruction) return;
  wsClient.send({ type: 'ai_scan:interrupt', session_id: _scanSession.id, instruction });
}

// ── "Editar y agregar" — modal liviano propio (ver nota en ai-agent.html) ─
function scanEditAndAdd(callId) {
  const calledEv = _scanEvents.find(e => e.id === callId && e.type === 'tool.called');
  if (!calledEv) return;
  openScanFindingModal(calledEv.payload.input, callId);
}

function openScanFindingModal(proposal, callId) {
  _scanEditCallId = callId;
  document.getElementById('sf-name').value = proposal.name || '';
  document.getElementById('sf-cat').value  = proposal.category || '';
  document.getElementById('sf-sev').value  = proposal.severity || 'medium';
  document.getElementById('sf-desc').value = proposal.description || '';
  document.getElementById('sf-rem').value  = proposal.remediation || '';
  document.getElementById('sf-cwe').value  = proposal.cwe || '';
  document.getElementById('sf-error').style.display = 'none';
  document.getElementById('scan-finding-modal').classList.add('open');
}

function closeScanFindingModal() {
  document.getElementById('scan-finding-modal').classList.remove('open');
  _scanEditCallId = null;
}

async function saveScanFinding() {
  const name = document.getElementById('sf-name').value.trim();
  const err  = document.getElementById('sf-error');
  const btn  = document.getElementById('sf-save-btn');
  if (!name) { err.textContent = t('nameRequired'); err.style.display = 'block'; return; }

  const payload = {
    name,
    category:    document.getElementById('sf-cat').value.trim() || 'Custom',
    severity:    document.getElementById('sf-sev').value,
    description: document.getElementById('sf-desc').value.trim(),
    remediation: document.getElementById('sf-rem').value.trim(),
    cwe:         document.getElementById('sf-cwe').value.trim() || null,
    // Le avisan al backend (POST /vulns) que resuelva el gate pendiente del
    // agente en el mismo request — ver AI_PENTEST_AGENT.md § "Editar y agregar".
    resolve_ai_session_id: _scanSession ? _scanSession.id : null,
    resolve_ai_call_id:    _scanEditCallId,
  };
  btn.disabled = true;
  try {
    const created = await api.vulns.create(state.currentProject.id, payload);
    state.customVulns.push(created);
    closeScanFindingModal();
    showToast(t('findingAdded'), 'success');
    // El tool.result que resuelve el gate llega solo por WS (resolveGatedCall
    // lo dispara del lado del backend) — no hace falta refrescar a mano acá.
  } catch (e) {
    err.textContent = e.message; err.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}
