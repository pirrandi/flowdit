// Evidencia citable para los hallazgos del AI Agent. Visto en prod (ver
// bd446dd / soft404.js): el agente proponía hallazgos sobre paths que nunca
// existieron — respuestas soft-404 de un SPA que contesta 200 a todo, 404s,
// o directamente cosas que nunca pidió. El gate humano no alcanzaba: la
// tarjeta muestra un texto convincente y nada de lo que el agente vio.
//
// Regla: cada tool.result de una tool que toca la red del target y que
// observó algo REAL recibe un `evidence_ref` estable ("ev_<id del evento
// tool.result>") que el modelo ve junto al resultado. propose_finding exige
// citar uno o más; se validan contra ai_scan_events ANTES del gate, y al
// aprobar se adjuntan como http_proofs las requests/respuestas tal como se
// guardaron — el revisor ve exactamente lo que vio el agente, no lo que el
// modelo dice que vio.
//
// El ref es el id del evento a propósito: el log es inmutable, así que el
// ref no cambia entre reconstrucciones del historial (prompt caching) y se
// valida con un lookup directo. Que sea secuencial no importa: un ref
// inventado o de otra sesión no pasa la validación.
//
// Textos para el modelo en inglés (los lee el modelo). Las anotaciones de los
// proofs van en el idioma de la sesión: terminan en el informe.

const db = require('../../db');

const REF_PREFIX = 'ev_';
const REF_PATTERN = /^ev_(\d{1,18})$/;

// Las tools que observan el target por red. Las de tier 0 leen la DB de
// Flowdit (no prueban nada del target) y las de tier 3 son escrituras.
const EVIDENCE_TOOLS = new Set([
  'fetch_endpoint', 'fetch_page_source', 'search_page_source',
  'port_scan', 'subdomain_enum',
  'send_http_request', 'test_payload', 'run_exploit_poc',
]);

const MAX_EVIDENCE_REFS = 10;
// Mismo tope de proofs que acepta el MCP (services/mcp/server.js).
const MAX_PROOFS = 10;
// El export DOCX corta cada bloque a 4000 caracteres; la UI muestra más. Se
// guarda algo más que eso para que el revisor tenga contexto, pero acotado:
// fetch_page_source puede devolver 50k caracteres por llamada y un hallazgo
// no es un dump del sitio.
const MAX_PROOF_REQUEST_CHARS = 4000;
const MAX_PROOF_RESPONSE_CHARS = 8000;

const NOT_FOUND_STATUSES = new Set([404, 410]);

function clipProof(text, max) {
  const s = String(text ?? '');
  return s.length > max ? `${s.slice(0, max)}\n… [truncated, ${s.length - max} more chars]` : s;
}

// Un paso HTTP (tier 1 o un step de tier 2) que sí observó algo: tiene
// status, no falló, y no es un 404/410/soft-404.
function stepObservedSomething(r) {
  return !!r && !r.error && !r.not_found && typeof r.status === 'number' && !NOT_FOUND_STATUSES.has(r.status);
}

// { citable: true } o { citable: false, why, detail } a partir del payload
// de un tool.result. `payload.result` es la salida de la tool tanto si corrió
// directo (tier 1, o tier 2 en modo autónomo) como si pasó por el gate
// (resolveGatedCall la guarda bajo `result` junto a `decision`).
function citability(name, payload) {
  if (!EVIDENCE_TOOLS.has(name)) return { citable: false, why: 'not_network' };
  if (payload?.decision === 'rejected') return { citable: false, why: 'rejected' };
  if (payload?.error) return { citable: false, why: 'error', detail: payload.error };
  const r = payload?.result;
  if (!r || typeof r !== 'object') return { citable: false, why: 'error', detail: 'no result' };
  if (r.error) return { citable: false, why: 'error', detail: r.error };
  if (r.not_found) return { citable: false, why: r.reason === 'soft_404' ? 'soft_404' : 'http_404' };

  switch (name) {
    case 'run_exploit_poc':
      // Una secuencia vale si al menos un paso observó algo real; los pasos
      // fallidos/404 no se adjuntan (ver proofsFor).
      return (r.steps || []).some(stepObservedSomething)
        ? { citable: true }
        : { citable: false, why: (r.steps || []).some(s => s && !s.error) ? 'http_404' : 'error', detail: 'no step of the sequence got a real response' };
    case 'port_scan':
      return (r.open_ports || []).length ? { citable: true } : { citable: false, why: 'empty', detail: 'no open ports were found' };
    case 'subdomain_enum':
      return (r.found || []).some(f => f.reachable) ? { citable: true } : { citable: false, why: 'empty', detail: 'no reachable subdomain was found' };
    default:
      if (typeof r.status !== 'number') return { citable: false, why: 'error', detail: 'no HTTP response' };
      if (NOT_FOUND_STATUSES.has(r.status)) return { citable: false, why: 'http_404' };
      return { citable: true };
  }
}

// El ref que ve el modelo junto al resultado, o null si no es citable.
function evidenceRefFor(ev) {
  if (ev?.type !== 'tool.result' || ev.id == null) return null;
  return citability(ev.payload?.name, ev.payload).citable ? `${REF_PREFIX}${ev.id}` : null;
}

function rejectionMessage(ref, name, c) {
  switch (c.why) {
    case 'soft_404': return `evidence_ref ${ref} is a soft-404 response — the target answers any non-existent path with that same page, so the path does not exist; you cannot report a finding on it`;
    case 'http_404': return `evidence_ref ${ref} is a not-found (404/410) response — the path does not exist; you cannot report a finding on it`;
    case 'error':    return `evidence_ref ${ref} is a failed request (${String(c.detail || 'error').slice(0, 200)}) — nothing was observed; you cannot report a finding on it`;
    case 'rejected': return `evidence_ref ${ref} is a request the pentester rejected — it never ran, so it proves nothing`;
    case 'empty':    return `evidence_ref ${ref} is a ${name} result that found nothing (${c.detail}) — you cannot report a finding on it`;
    default:         return `evidence_ref ${ref} is a ${name} result, which is not a network observation of the target — cite a fetch/request/scan result instead`;
  }
}

// Valida los refs de una propuesta. Alcance: la SESIÓN, no el thread — un
// sub-agente y su coordinador comparten sesión, y el coordinador solo conoce
// lo que el sub-agente vio por su reporte de texto; si el sub-agente le pasa
// los refs, el coordinador tiene que poder citarlos. La garantía que importa
// sigue intacta: el ref es una respuesta real, exitosa, de esta sesión y de
// este target. Otra sesión (u otro proyecto) nunca: no se puede verificar
// que el hallazgo corresponda a este trabajo.
//
// `targetId`: el del hallazgo (null = sin target, se infiere de los refs).
// Devuelve { errors: [...] } o { targetId, evidence: [{ ref, name, input, payload, createdAt }] }.
async function validateEvidenceRefs({ sessionId, targetId, refs, toolName = 'propose_finding' }) {
  const list = Array.isArray(refs) ? refs : (typeof refs === 'string' && refs.trim() ? [refs] : []);
  if (!list.length) {
    return { errors: [`${toolName} requires evidence_refs: one or more evidence_ref values (e.g. "ev_123") taken from successful network tool results in this session (fetch_endpoint, fetch_page_source, search_page_source, send_http_request, test_payload, run_exploit_poc, port_scan, subdomain_enum) that show this issue. If you have not observed it in a real response yet, test it first — do not report findings based on assumptions, guesses or not-found responses.`] };
  }
  if (list.length > MAX_EVIDENCE_REFS) {
    return { errors: [`evidence_refs accepts at most ${MAX_EVIDENCE_REFS} refs — cite only the responses that best demonstrate the issue`] };
  }

  const errors = [];
  const ids = [];
  const unique = [...new Set(list.map(r => String(r).trim()))];
  for (const ref of unique) {
    const m = REF_PATTERN.exec(ref);
    if (!m) errors.push(`"${ref.slice(0, 60)}" is not a valid evidence_ref — use the exact "ev_<number>" value shown in a tool result`);
    else ids.push(m[1]);
  }

  const { rows } = ids.length ? await db.query(
    `SELECT r.id, r.session_id, r.payload, r.created_at, c.payload AS call_payload
     FROM ai_scan_events r
     LEFT JOIN ai_scan_events c ON c.session_id = r.session_id AND c.type = 'tool.called' AND c.id::text = r.payload->>'call_id'
     WHERE r.id = ANY($1::bigint[]) AND r.type = 'tool.result'`,
    [ids]
  ) : { rows: [] };
  const byId = new Map(rows.map(r => [String(r.id), r]));

  const evidence = [];
  for (const id of ids) {
    const ref = `${REF_PREFIX}${id}`;
    const row = byId.get(id);
    // Otra sesión responde igual que inexistente: no confirma qué hay en
    // sesiones ajenas.
    if (!row || row.session_id !== sessionId) {
      errors.push(`evidence_ref ${ref} does not exist in this session — cite only evidence_ref values returned by tool results in this session`);
      continue;
    }
    const name = row.payload?.name;
    const c = citability(name, row.payload);
    if (!c.citable) { errors.push(rejectionMessage(ref, name, c)); continue; }
    const input = row.call_payload?.input || {};
    evidence.push({ ref, name, input, payload: row.payload, createdAt: row.created_at, targetId: input.target_id || null });
  }

  const targets = [...new Set(evidence.map(e => e.targetId))];
  if (targetId) {
    for (const e of evidence) {
      if (e.targetId !== targetId) errors.push(`evidence_ref ${e.ref} was observed on target_id "${e.targetId}", but this finding is for target_id "${targetId}" — cite evidence from the same target`);
    }
  } else if (targets.length > 1) {
    errors.push(`evidence_refs point to different targets (${targets.join(', ')}) — set target_id on the finding and cite evidence from that target only`);
  }

  if (errors.length) return { errors };
  return { targetId: targetId || targets[0] || null, evidence };
}

// ── evidencia → http_proofs ─────────────────────────────────────────────
// Mismo shape que el resto de la app (Burp import, MCP, vulns.js):
// { method, request, response, annotation }. `evidence_ref` extra: permite
// no adjuntar dos veces el mismo ref en un update_finding (http_proofs nunca
// sale al portal, ver PORTAL_FINDING_FIELDS en routes/vulns.js).

function rawRequest(method, url, headers = {}, body = null) {
  let target = url, host = '';
  try { const u = new URL(url); target = `${u.pathname}${u.search}`; host = u.host; } catch { /* url ya validada por la tool; si no, va cruda */ }
  const lines = [`${method || 'GET'} ${target} HTTP/1.1`];
  if (host) lines.push(`Host: ${host}`);
  for (const [k, v] of Object.entries(headers || {})) lines.push(`${k}: ${v}`);
  return body != null && body !== '' ? `${lines.join('\n')}\n\n${typeof body === 'string' ? body : JSON.stringify(body)}` : lines.join('\n');
}

function rawResponse(status, headers = {}, body = null) {
  const lines = [`HTTP/1.1 ${status}`];
  for (const [k, v] of Object.entries(headers || {})) if (v != null) lines.push(`${k}: ${v}`);
  return body != null && body !== '' ? `${lines.join('\n')}\n\n${body}` : lines.join('\n');
}

const ANNOTATIONS = {
  es: (ref, tool, at, extra) => `Evidencia ${ref} (${tool}${extra ? `, ${extra}` : ''}) capturada por el AI Agent el ${at}.`,
  en: (ref, tool, at, extra) => `Evidence ${ref} (${tool}${extra ? `, ${extra}` : ''}) captured by the AI Agent on ${at}.`,
};

function proof(method, request, response, ref, annotation) {
  return {
    method,
    request: clipProof(request, MAX_PROOF_REQUEST_CHARS),
    response: clipProof(response, MAX_PROOF_RESPONSE_CHARS),
    annotation,
    evidence_ref: ref,
  };
}

// Requests HTTP de una evidencia, en el orden en que corrieron.
function proofsFor(e, lang) {
  const r = e.payload.result;
  const at = new Date(e.createdAt).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
  const note = extra => (ANNOTATIONS[lang] || ANNOTATIONS.es)(e.ref, e.name, at, extra);

  switch (e.name) {
    case 'fetch_endpoint':
      return [proof(r.method || e.input.method || 'GET', rawRequest(e.input.method || 'GET', r.url),
        rawResponse(r.status, r.headers, r.body_preview), e.ref, note())];
    case 'fetch_page_source': {
      const range = r.offset || r.truncated ? `offset ${r.offset || 0}, ${r.returned_length} / ${r.total_length} chars` : null;
      return [proof('GET', rawRequest('GET', r.url),
        rawResponse(r.status, { 'content-type': r.content_type, location: r.location }, r.content), e.ref, note(range))];
    }
    case 'search_page_source': {
      const pattern = `/${e.input.pattern}/${e.input.flags ?? 'i'}`;
      const body = (r.matches || []).map(m => `@${m.position}: ${m.context}`).join('\n---\n');
      return [proof('GET', rawRequest('GET', r.url),
        rawResponse(r.status, { location: r.location }, `[${r.match_count} match(es) for ${pattern} in ${r.total_length} chars]\n${body}`), e.ref, note(pattern))];
    }
    case 'send_http_request':
      return [proof(r.method, rawRequest(r.method, r.url, e.input.headers, e.input.body),
        rawResponse(r.status, r.headers, r.body_preview), e.ref, note())];
    case 'test_payload': {
      // La tool arma la request a partir de param_location (ver
      // scanToolsLevel2.js); el query ya viene inyectado en r.url.
      const inj = r.injected || {};
      const headers = inj.location === 'header' ? { [inj.name]: inj.payload } : inj.location === 'body_json' ? { 'Content-Type': 'application/json' } : {};
      const body = inj.location === 'body_json' ? JSON.stringify({ [inj.name]: inj.payload }) : null;
      return [proof(r.method, rawRequest(r.method, r.url, headers, body),
        rawResponse(r.status, r.headers, r.body_preview), e.ref, note(r.category || null))];
    }
    case 'run_exploit_poc':
      return (r.steps || []).map((s, i) => [s, i]).filter(([s]) => stepObservedSomething(s)).map(([s, i]) => {
        const req = (e.input.request_sequence || [])[i] || {};
        return proof(s.method, rawRequest(s.method, s.url, req.headers, req.body),
          rawResponse(s.status, s.headers, s.body_preview), e.ref, note(`${r.technique || 'PoC'} — step ${i + 1}`));
      });
    case 'port_scan':
      return [proof('TCP', `TCP connect scan → ${r.host} (${r.scanned} ports)`,
        `Open ports: ${(r.open_ports || []).join(', ')}`, e.ref, note())];
    case 'subdomain_enum':
      return [proof('DNS', `DNS A lookups + HEAD https://<sub>.${r.base_domain}/ (${r.checked} candidates)`,
        (r.found || []).map(f => `${f.subdomain} → ${(f.addresses || []).join(', ')} — ${f.reachable ? `HTTP ${f.status}` : `unreachable (${f.error})`}`).join('\n') +
        (r.wildcard_warning ? `\n\n${r.wildcard_warning}` : ''), e.ref, note())];
    default:
      return [];
  }
}

function evidenceToProofs(evidence, lang = 'es') {
  return evidence.flatMap(e => proofsFor(e, lang)).slice(0, MAX_PROOFS);
}

module.exports = {
  EVIDENCE_TOOLS, MAX_EVIDENCE_REFS, MAX_PROOF_REQUEST_CHARS, MAX_PROOF_RESPONSE_CHARS,
  citability, evidenceRefFor, validateEvidenceRefs, evidenceToProofs,
};
