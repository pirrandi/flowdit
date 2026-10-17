// Detección de "soft 404": distinguir un path que existe de verdad de uno que
// el target contesta con su catch-all. Visto en prod: 10 endpoints guardados
// con status 404, y en un target React `/static/js` guardado como 200 —
// el SPA devuelve index.html con 200 para CUALQUIER ruta, así que el status
// solo no prueba nada. El agente después armaba hallazgos sobre paths que no
// existían. Antes de persistir un endpoint se lo compara contra una "línea
// base": la respuesta del target a un path aleatorio que no puede existir,
// pedido bajo el mismo prefijo (/api/* suele tener otro catch-all que /*).

const crypto = require('crypto');
const { buildTargetUrl, readBodyCapped } = require('./targetScope');

const PROBE_MARKER = 'fd404-';
const BASELINE_TTL_MS = 30 * 60 * 1000;
const MAX_BASELINES = 500;
const BASELINE_TIMEOUT_MS = 8000;

// La tolerancia por largo existe para páginas con un nonce/CSRF/timestamp
// que cambia en cada request. Solo aplica a cuerpos de 512+ bytes: en un
// JSON chico (`{"data":[]}` vs `{"error":"not found"}`) unos pocos bytes de
// diferencia SON la diferencia entre existir o no.
const LENGTH_TOLERANCE_BYTES = 64;
const LENGTH_TOLERANCE_RATIO = 0.02;
const MIN_BODY_FOR_LENGTH_MATCH = 512;

// (target_id|scheme|prefijo) → { promise, expiresAt }. Se guarda la promesa
// para que dos tools en paralelo sobre el mismo prefijo compartan una sola
// sonda. Map conserva el orden de inserción: al pasar el tope se descarta la
// más vieja.
const baselineCache = new Map();

function clearBaselineCache() { baselineCache.clear(); }

// El prefijo es el primer segmento cuando el path tiene 2+ (`/api/v1/x` →
// `/api`); para un path de un solo segmento (`/admin`) se sondea la raíz.
function probePrefix(pathname) {
  const segments = pathname.split('/').filter(Boolean);
  return segments.length >= 2 ? `/${segments[0]}` : '';
}

function mediaType(contentType) {
  return (contentType || '').split(';')[0].trim().toLowerCase();
}

function stripAll(text, needles) {
  let out = String(text ?? '');
  // Los más largos primero: `/api/x?y=1` antes que `/api/x`.
  for (const n of [...new Set(needles.filter(Boolean))].sort((a, b) => b.length - a.length)) {
    out = out.split(n).join('');
  }
  return out;
}

// Variantes con que una página puede repetir el path pedido: tal cual,
// decodificado, y codificado como componente (p.ej. `?next=%2Fadmin`).
function pathVariants(...paths) {
  const out = [];
  for (const p of paths) {
    if (!p) continue;
    out.push(p);
    try { out.push(decodeURIComponent(p)); } catch { /* path mal codificado: queda la variante cruda */ }
    out.push(encodeURIComponent(p));
  }
  return out;
}

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
// Hashes y números (request ids, timestamps) cambian entre requests aunque
// la página sea la misma.
const volatileNormalize = s => s.replace(/[0-9a-f]{8,}/gi, '#').replace(/\d+/g, '0');

// Regla exacta (todas tienen que cumplirse para ser soft-404):
// 1. mismo status que la línea base;
// 2. mismo Location, después de sacarle el path pedido / el path sonda
//    (un catch-all que redirige a `/login?next=<path>`);
// 3. mismo media type (sin parámetros como charset);
// 4. mismo cuerpo, después de sacarle el path pedido / el sondeado: hash
//    igual, o hash igual tras normalizar hex y dígitos, o — si ambos cuerpos
//    pesan 512+ bytes — largo dentro de ±max(64 bytes, 2%). Un HEAD no trae
//    cuerpo, así que se juzga solo por 1–3.
function matchesBaseline(baseline, candidate) {
  if (candidate.status !== baseline.status) return false;

  // Se sacan TODOS los paths de AMBOS lados: sacar `/a` solo del candidato
  // rompería palabras como `/assets` que la línea base conserva.
  const needles = pathVariants(...(candidate.paths || []), baseline.probePath);

  if (candidate.status >= 300 && candidate.status < 400) {
    if (stripAll(candidate.location, needles) !== stripAll(baseline.location, needles)) return false;
  }
  if (mediaType(candidate.contentType) !== mediaType(baseline.contentType)) return false;
  if (candidate.body == null) return true;

  const a = stripAll(candidate.body, needles);
  const b = stripAll(baseline.body, needles);
  if (a === b || sha256(volatileNormalize(a)) === sha256(volatileNormalize(b))) return true;

  const lenA = Buffer.byteLength(a), lenB = Buffer.byteLength(b);
  if (lenA < MIN_BODY_FOR_LENGTH_MATCH || lenB < MIN_BODY_FOR_LENGTH_MATCH) return false;
  return Math.abs(lenA - lenB) <= Math.max(LENGTH_TOLERANCE_BYTES, lenB * LENGTH_TOLERANCE_RATIO);
}

async function fetchBaseline(target, scheme, prefix) {
  const probePath = `${prefix}/${PROBE_MARKER}${crypto.randomBytes(6).toString('hex')}`;
  const res = await fetch(buildTargetUrl(target, scheme, probePath), { redirect: 'manual', signal: AbortSignal.timeout(BASELINE_TIMEOUT_MS) });
  const { text } = await readBodyCapped(res);
  return { probePath, status: res.status, location: res.headers.get('location'), contentType: res.headers.get('content-type'), body: text };
}

// null si no se pudo obtener: sin línea base no se clasifica, y la tool
// sigue como antes (el fallo no se cachea, el próximo request reintenta).
async function getBaseline(target, scheme, pathname) {
  const prefix = probePrefix(pathname);
  const key = `${target.id}|${scheme || 'https'}|${prefix}`;
  const now = Date.now();
  const hit = baselineCache.get(key);
  if (hit && hit.expiresAt > now) return hit.promise;

  const promise = fetchBaseline(target, scheme, prefix).catch(() => {
    if (baselineCache.get(key)?.promise === promise) baselineCache.delete(key);
    return null;
  });
  baselineCache.delete(key);
  baselineCache.set(key, { promise, expiresAt: now + BASELINE_TTL_MS });
  while (baselineCache.size > MAX_BASELINES) baselineCache.delete(baselineCache.keys().next().value);
  return promise;
}

// 'http_404' | 'soft_404' | null (existe, o no se pudo determinar).
// 401/403/405/5xx y los 3xx que no coinciden con la línea base son señales
// reales y se persisten. `body` es null para HEAD.
async function notFoundReason(target, scheme, url, rawPath, response, body) {
  if (response.status === 404 || response.status === 410) return 'http_404';
  // Solo un 2xx/3xx puede ser un catch-all disfrazado: 401/403/405/5xx se
  // guardan siempre, aunque el target conteste igual para todo — que un
  // prefijo entero pida auth o falle ya es información para el pentester.
  if (response.status < 200 || response.status >= 400) return null;
  const u = new URL(url);
  if (u.pathname === '/') return null; // la raíz siempre existe
  const baseline = await getBaseline(target, scheme, u.pathname);
  if (!baseline) return null;
  const candidate = {
    status: response.status, location: response.headers.get('location'),
    contentType: response.headers.get('content-type'), body,
    paths: [`${u.pathname}${u.search}`, u.pathname, rawPath],
  };
  return matchesBaseline(baseline, candidate) ? 'soft_404' : null;
}

// Texto en inglés: lo lee el modelo.
const NOT_FOUND_NOTES = {
  http_404: 'The target returned 404/410: this path does not exist. It was not recorded as an endpoint.',
  soft_404: 'The target answers ANY non-existent path here with this same response (a catch-all / soft 404), so this path most likely does not exist. Do not treat it as an existing endpoint and do not build findings on it. It was not recorded.',
};

module.exports = { notFoundReason, matchesBaseline, getBaseline, clearBaselineCache, probePrefix, NOT_FOUND_NOTES, PROBE_MARKER };
