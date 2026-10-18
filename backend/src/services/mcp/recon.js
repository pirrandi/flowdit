// Puertos y endpoints que Claude Code carga DIRECTO (add_ports /
// add_endpoints), sin pasar por el inbox: son datos de recon observados, no
// conclusiones, y aprobarlos uno por uno sería pura fricción. Lo que sí se
// exige es lo mismo que al AI Agent: el target tiene que estar en scope
// ('in') y activo (assertTargetInScope). Idempotente: lo que ya existe se
// saltea y se informa, nunca es un error, así el modelo puede reintentar un
// lote sin duplicar nada.
const db       = require('../../db');
const activity = require('../activity');
const { assertTargetInScope } = require('../ai/targetScope');
const { normalizeEndpointPath } = require('../ai/scanToolsLevel1');

const MAX_PORTS_PER_CALL     = 100;
const MAX_ENDPOINTS_PER_CALL = 200;
const MAX_ENDPOINT_PATH_LENGTH = 1000; // VARCHAR(1000) de target_endpoints.path
const SOURCE = 'claude_code';
// Cuántos ejemplos viajan en el meta de Activity (el feed muestra el conteo).
const ACTIVITY_SAMPLE = 20;

async function inTransaction(fn) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function addPorts({ projectId, user, targetId, ports }) {
  const target = await assertTargetInScope(targetId, projectId);
  // Dentro del lote también cuenta como duplicado: el primero gana.
  const seen = new Set();
  const added = [], skipped = [];
  await inTransaction(async client => {
    for (const p of ports) {
      const protocol = p.protocol || 'tcp';
      const key = `${p.port}/${protocol}`;
      if (seen.has(key)) { skipped.push({ port: p.port, protocol, reason: 'repeated in this batch' }); continue; }
      seen.add(key);
      // target_ports no tiene índice único (puede haber filas viejas
      // repetidas cargadas a mano), así que la existencia se chequea en el
      // mismo INSERT.
      const { rows } = await client.query(
        `INSERT INTO target_ports (target_id, port, protocol, state, service, version, notes, added_by, source)
         SELECT $1::uuid, $2::int, $3::text, $4::text, $5::text, $6::text, $7::text, $8::uuid, $9::text
         WHERE NOT EXISTS (SELECT 1 FROM target_ports WHERE target_id = $1::uuid AND port = $2::int AND protocol = $3::text)
         RETURNING id`,
        [target.id, p.port, protocol, p.state || 'open', p.service || '', p.version || '', p.notes || '', user.id, SOURCE]
      );
      if (rows.length) added.push({ id: rows[0].id, port: p.port, protocol });
      else {
        const { rows: ex } = await client.query(
          `SELECT id FROM target_ports WHERE target_id = $1 AND port = $2 AND protocol = $3 LIMIT 1`,
          [target.id, p.port, protocol]
        );
        skipped.push({ port: p.port, protocol, existing_id: ex[0]?.id, reason: 'already recorded' });
      }
    }
  });
  if (added.length) {
    // Un solo evento por lote (no uno por puerto: 50 toasts no sirven). Va
    // como entity 'target' para que la vista de Targets sepa qué recargar.
    await activity.log({
      projectId, user, action: 'claude_code_ports_added', entityType: 'target',
      entityId: target.id, entityName: target.host,
      meta: { via: 'claude-code', count: added.length, items: added.slice(0, ACTIVITY_SAMPLE).map(a => `${a.port}/${a.protocol}`) },
    });
  }
  return { target: target.host, added, skipped };
}

async function addEndpoints({ projectId, user, targetId, endpoints }) {
  const target = await assertTargetInScope(targetId, projectId);
  const seen = new Set();
  const added = [], skipped = [];
  await inTransaction(async client => {
    for (const e of endpoints) {
      // Misma normalización que POST /endpoints y el AI Agent: el índice
      // único (target_id, path, method) decide qué es "el mismo endpoint".
      const path = normalizeEndpointPath(e.path).slice(0, MAX_ENDPOINT_PATH_LENGTH);
      const method = e.method || 'GET';
      const key = `${method} ${path}`;
      if (seen.has(key)) { skipped.push({ method, path, reason: 'repeated in this batch' }); continue; }
      seen.add(key);
      const { rows } = await client.query(
        `INSERT INTO target_endpoints (target_id, path, method, status_code, interesting, notes, added_by, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (target_id, path, method) DO NOTHING
         RETURNING id`,
        [target.id, path, method, e.status_code ?? null, !!e.interesting, e.notes || '', user.id, SOURCE]
      );
      if (rows.length) added.push({ id: rows[0].id, method, path });
      else {
        const { rows: ex } = await client.query(
          `SELECT id FROM target_endpoints WHERE target_id = $1 AND path = $2 AND method = $3`,
          [target.id, path, method]
        );
        skipped.push({ method, path, existing_id: ex[0]?.id, reason: 'already recorded' });
      }
    }
  });
  if (added.length) {
    await activity.log({
      projectId, user, action: 'claude_code_endpoints_added', entityType: 'target',
      entityId: target.id, entityName: target.host,
      meta: { via: 'claude-code', count: added.length, items: added.slice(0, ACTIVITY_SAMPLE).map(a => `${a.method} ${a.path}`) },
    });
  }
  return { target: target.host, added, skipped };
}

module.exports = { addPorts, addEndpoints, MAX_PORTS_PER_CALL, MAX_ENDPOINTS_PER_CALL };
