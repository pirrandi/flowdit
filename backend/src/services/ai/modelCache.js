// Cache en memoria (TTL 1h) para GET /ai/models — evita pegarle al /models
// de cada proveedor en cada carga de la página de Settings. Clave por
// proveedor + qué key se usó (proyecto vs env global), porque una key
// distinta puede exponer una lista de modelos distinta. Solo se cachean
// resultados exitosos: un fallo transitorio (o una key recién corregida)
// no debe quedar pegado una hora.
const TTL_MS = 60 * 60 * 1000;
const cache = new Map();

// Mismo idioma Map+TTL que services/sso.js / services/mfa.js. Sin este
// sweep periódico, una key que un proyecto rota o borra deja su entrada
// huérfana en el Map para siempre (nada vuelve a pedir esa key exacta, así
// que el `get()` que purga por TTL nunca corre sobre ella) — crece sin
// límite y el secreto viejo sigue vivo en memoria del proceso.
function _sweep() {
  const now = Date.now();
  for (const [k, v] of cache) if (v.expiresAt < now) cache.delete(k);
}
setInterval(_sweep, 5 * 60 * 1000).unref();

function get(key) {
  const entry = cache.get(key);
  if (!entry) return undefined;
  if (entry.expiresAt < Date.now()) { cache.delete(key); return undefined; }
  return entry.value;
}

function set(key, value) {
  cache.set(key, { value, expiresAt: Date.now() + TTL_MS });
}

module.exports = { get, set };
