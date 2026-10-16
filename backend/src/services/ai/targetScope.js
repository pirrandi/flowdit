// Helpers compartidos entre las tools de Nivel 1 (recon pasivo) y Nivel 2
// (acción activa) — CUALQUIER tool que toque la red de un target, sin
// importar el tier, tiene que pasar por acá primero. El scope es lo que
// protege contra el escenario más grave de todos: que el agente ataque algo
// fuera del alcance autorizado. Nunca confiar en que el modelo respetó
// get_targets_in_scope por su cuenta — se re-valida en cada llamada.

const db = require('../../db');

// `targets.host` es texto libre sin validación de formato (ver
// targets.js — solo isLength) — es común pegar la URL completa
// (`https://example.com/`) donde estas tools esperan el hostname pelado
// para armar `${scheme}://${host}${path}`. Sin normalizar, el resultado es
// una URL con el esquema duplicado (`https://https://example.com/...`) que
// nunca resuelve por DNS — visto en vivo dos veces: el agente lo
// diagnosticó perfecto ambas veces (gracias a describeFetchError) pero
// quedó bloqueado esperando que alguien corrija el target a mano. Esto NO
// toca el dato en `targets.host` — solo lo que ven estas tools al construir
// URLs, así que la vista de Targets sigue mostrando el valor tal cual se
// guardó.
function normalizeHost(host) {
  return host.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/+$/, '');
}

// Devuelve el target si está en scope ('in') y activo; lanza si no existe,
// no pertenece al proyecto, está fuera de scope, o no está activo. El
// mensaje de error es lo que el modelo va a leer en el tool.result — tiene
// que ser claro para que entienda por qué falló y no insista.
// `scopedTargetId`: si la sesión (o el sub-agente) se arrancó acotada a un
// target, cualquier otro se rechaza aunque esté en scope del proyecto.
async function assertTargetInScope(targetId, projectId, scopedTargetId = null) {
  if (!targetId) throw new Error('target_id is required for this tool');
  if (scopedTargetId && targetId !== scopedTargetId) {
    throw new Error(`this session is scoped to target_id "${scopedTargetId}" — refusing to act against another target`);
  }

  const { rows } = await db.query(
    `SELECT id, host, type, scope, status FROM targets WHERE id=$1 AND project_id=$2`,
    [targetId, projectId]
  );
  const target = rows[0];
  if (!target) throw new Error('target_id does not belong to this project');
  if (target.scope !== 'in') throw new Error(`target "${target.host}" is out of scope — refusing to act against it`);
  if (target.status !== 'active') throw new Error(`target "${target.host}" is not active (status: ${target.status})`);

  target.host = normalizeHost(target.host);
  return target;
}

// `fetch()` nativo de Node, en un fallo de red, resume TODO en `err.message`
// ("fetch failed") — la causa real (DNS no resuelve, conexión rechazada,
// TLS roto, timeout) vive en `err.cause.code`/`err.cause.message` y se
// pierde si solo se propaga `err.message`. Compartida entre Nivel 1 y 2
// (ambas tocan la red del target) para que ni el pentester ni el propio
// modelo se queden sin saber por qué falló un request.
function describeFetchError(err) {
  const cause = err.cause;
  const detail = cause?.code || cause?.message || (typeof cause === 'string' ? cause : null);
  return detail ? `${err.message} (${detail})` : err.message;
}

// `scheme` y `path` los elige el modelo — concatenarlos a mano permitía
// salir del target: un scheme "file"/"ftp" (u otro arbitrario), o un path
// tipo "@evil.com/" que convierte al host del target en userinfo. Se arma
// con new URL() y se exige que el host resultante (con puerto) sea
// exactamente el del target. Los fetch usan redirect:'manual', así que un
// 3xx nunca salta solo a otro host — se le reporta el Location al modelo.
const ALLOWED_SCHEMES = new Set(['http', 'https']);

function buildTargetUrl(target, scheme, path) {
  const s = scheme || 'https';
  if (!ALLOWED_SCHEMES.has(s)) throw new Error(`scheme "${s}" not allowed — only "http" or "https"`);
  const p = String(path ?? '');
  let base, url;
  try {
    base = new URL(`${s}://${target.host}`);
    url  = new URL(`${s}://${target.host}${p.startsWith('/') ? '' : '/'}${p}`);
  } catch {
    throw new Error(`could not build a valid URL from target "${target.host}" and path "${p}"`);
  }
  if (url.host !== base.host || url.username || url.password) {
    throw new Error(`refusing to request "${url.href}": it does not point at target "${target.host}"`);
  }
  return url.href;
}

// response.text() lee el cuerpo entero a memoria sin tope — un target (o un
// archivo enorme) podía meterle cientos de MB al proceso. Se lee de a chunks
// y se corta al pasar `maxBytes`, avisando con `truncated`.
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

async function readBodyCapped(response, maxBytes = MAX_RESPONSE_BYTES) {
  if (!response.body) return { text: '', truncated: false };
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0, truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (size + value.byteLength > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - size));
      truncated = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  return { text: new TextDecoder().decode(Buffer.concat(chunks)), truncated };
}

module.exports = { assertTargetInScope, describeFetchError, buildTargetUrl, readBodyCapped, MAX_RESPONSE_BYTES };
