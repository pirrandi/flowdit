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
async function assertTargetInScope(targetId, projectId) {
  if (!targetId) throw new Error('target_id is required for this tool');

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

module.exports = { assertTargetInScope, describeFetchError };
