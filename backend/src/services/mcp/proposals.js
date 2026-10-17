// Propuestas de Claude Code (tabla mcp_proposals). Claude Code nunca escribe
// directo en custom_vulns ni en las notas: deja una propuesta, y recién
// cuando un writer del proyecto la aprueba desde el inbox se crea el
// hallazgo o se agrega la nota. Compartido entre las tools MCP (crear) y
// routes/mcp-proposals.js (listar/aprobar/rechazar). Quien propuso puede
// editar o retirar su propuesta mientras siga pendiente.
const db       = require('../../db');
const activity = require('../activity');
const { targetBelongsToProject } = require('../ownership');
const { assertTargetInScope } = require('../ai/targetScope');
const uploads  = require('./uploads');

// Tope de propuestas pendientes por proyecto: un Claude Code en loop no debe
// poder enterrar el inbox (ni la base) con miles de borradores.
const MAX_PENDING_PER_PROJECT = 200;

// El status HTTP viaja con el error para que la capa REST lo traduzca; las
// tools MCP solo usan el mensaje, que es lo que lee el modelo.
class ProposalError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// Cada tipo de entidad que acepta notas, con cómo validar que pertenece al
// proyecto y cómo escribirle la nota. Identificadores fijos del código,
// nunca input del usuario.
const NOTE_ENTITIES = {
  target: {
    lookup: `SELECT t.id AS target_id, t.host AS name
             FROM targets t WHERE t.id = $1 AND t.project_id = $2`,
    update: `UPDATE targets SET notes = ${appendSql('notes')}
             WHERE id = $1 AND project_id = $2`,
  },
  port: {
    lookup: `SELECT p.target_id, t.host || ':' || p.port || '/' || p.protocol AS name
             FROM target_ports p JOIN targets t ON t.id = p.target_id
             WHERE p.id = $1 AND t.project_id = $2`,
    update: `UPDATE target_ports p SET notes = ${appendSql('p.notes')}
             FROM targets t WHERE p.id = $1 AND t.id = p.target_id AND t.project_id = $2`,
  },
  endpoint: {
    lookup: `SELECT e.target_id, e.method || ' ' || t.host || e.path AS name
             FROM target_endpoints e JOIN targets t ON t.id = e.target_id
             WHERE e.id = $1 AND t.project_id = $2`,
    update: `UPDATE target_endpoints e SET notes = ${appendSql('e.notes')}
             FROM targets t WHERE e.id = $1 AND t.id = e.target_id AND t.project_id = $2`,
  },
  finding: {
    lookup: `SELECT v.target_id, v.name
             FROM custom_vulns v WHERE v.id = $1 AND v.project_id = $2`,
    update: `UPDATE custom_vulns SET notes = ${appendSql('notes')}, updated_by = $4, updated_at = NOW()
             WHERE id = $1 AND project_id = $2`,
  },
};

// La nota se AGREGA al final, nunca reemplaza lo que el pentester ya
// escribió. $3 = texto nuevo.
function appendSql(col) {
  return `CASE WHEN ${col} IS NULL OR btrim(${col}) = '' THEN $3 ELSE ${col} || E'\\n\\n' || $3 END`;
}

const NOTE_ENTITY_TYPES = Object.keys(NOTE_ENTITIES);

async function resolveNoteEntity(entityType, entityId, projectId) {
  const def = NOTE_ENTITIES[entityType];
  if (!def) throw new ProposalError(400, `entity_type must be one of: ${NOTE_ENTITY_TYPES.join(', ')}`);
  const { rows } = await db.query(def.lookup, [entityId, projectId]);
  if (!rows.length) throw new ProposalError(404, `${entityType} "${entityId}" does not belong to this project`);
  return rows[0];
}

async function assertPendingCapacity(projectId) {
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS n FROM mcp_proposals WHERE project_id = $1 AND status = 'pending'`,
    [projectId]
  );
  if (rows[0].n >= MAX_PENDING_PER_PROJECT) {
    throw new ProposalError(429, `this project already has ${rows[0].n} pending proposals — ask the team to review the inbox before proposing more`);
  }
}

// Mismo criterio que findDuplicateFinding() del AI Agent (agentLoop.js):
// mismo nombre ignorando mayúsculas/espacios + mismo target = mismo hallazgo.
// Se mira tanto custom_vulns como las propuestas todavía pendientes.
// `excludeProposalId`: al editar, la propuesta no tiene que chocar consigo misma.
async function findDuplicate(projectId, targetId, title, excludeProposalId = null) {
  const norm = `lower(btrim(regexp_replace($3, '\\s+', ' ', 'g')))`;
  const { rows: vulns } = await db.query(
    `SELECT id, name FROM custom_vulns
     WHERE project_id = $1 AND target_id IS NOT DISTINCT FROM $2
       AND lower(btrim(regexp_replace(name, '\\s+', ' ', 'g'))) = ${norm}
     LIMIT 1`,
    [projectId, targetId, title]
  );
  if (vulns.length) return `a finding named "${vulns[0].name}" already exists for this target (finding_id ${vulns[0].id}) — use propose_note on it to add information instead`;
  const { rows: props } = await db.query(
    `SELECT id FROM mcp_proposals
     WHERE project_id = $1 AND kind = 'finding' AND status = 'pending' AND target_id IS NOT DISTINCT FROM $2
       AND ($4::uuid IS NULL OR id <> $4::uuid)
       AND lower(btrim(regexp_replace(payload->>'title', '\\s+', ' ', 'g'))) = ${norm}
     LIMIT 1`,
    [projectId, targetId, title, excludeProposalId]
  );
  if (props.length) return `an identical finding proposal is already pending review (proposal_id ${props[0].id}) — do not propose it again`;
  return null;
}

async function insertProposal(queryable, { projectId, kind, payload, targetId, entityType = null, entityId = null, user, tokenId }) {
  const { rows } = await queryable.query(
    `INSERT INTO mcp_proposals (project_id, kind, payload, target_id, entity_type, entity_id, proposed_by, token_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id, kind, status, created_at`,
    [projectId, kind, JSON.stringify(payload), targetId, entityType, entityId, user.id, tokenId || null]
  );
  return rows[0];
}

async function createFindingProposal({ projectId, user, tokenId, input }) {
  const target = await assertTargetInScope(input.target_id, projectId);
  await assertPendingCapacity(projectId);
  const dup = await findDuplicate(projectId, target.id, input.title);
  if (dup) throw new ProposalError(409, dup);

  const payload = {
    title: input.title, severity: input.severity, category: input.category || 'Custom',
    description: input.description, remediation: input.remediation,
    cvss_vector: input.cvss_vector || null, cvss_score: input.cvss_score ?? null,
    cwe: input.cwe || null, evidence: input.evidence || null, http_proofs: input.http_proofs || [],
  };
  // Propuesta + vínculo de capturas en una transacción: si alguna subida no
  // se puede usar no queda una propuesta a medias sin sus imágenes.
  let proposal, attached = [];
  await inTransaction(async client => {
    proposal = await insertProposal(client, { projectId, kind: 'finding', payload, targetId: target.id, user, tokenId });
    if (input.evidence_upload_ids?.length) {
      attached = await uploads.attachUploads(client, { proposalId: proposal.id, userId: user.id, uploadIds: input.evidence_upload_ids });
    }
  });
  await activity.log({
    projectId, user, action: 'claude_code_proposed', entityType: 'mcp_proposal',
    entityId: proposal.id, entityName: input.title,
    meta: { via: 'claude-code', kind: 'finding', severity: input.severity, evidence_images: attached.length },
  });
  return { ...proposal, target_host: target.host, evidence_images: attached.length };
}

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

async function createNoteProposal({ projectId, user, tokenId, input }) {
  const entity = await resolveNoteEntity(input.entity_type, input.entity_id, projectId);
  // Notas sobre un target (o sus puertos/endpoints) pasan por el mismo chequeo
  // de scope que el AI Agent: nada de documentar trabajo sobre algo fuera del
  // alcance autorizado.
  if (input.entity_type !== 'finding') await assertTargetInScope(entity.target_id, projectId);
  await assertPendingCapacity(projectId);

  const proposal = await insertProposal(db, {
    projectId, kind: 'note', payload: { text: input.text, entity_name: entity.name },
    targetId: entity.target_id, entityType: input.entity_type, entityId: input.entity_id, user, tokenId,
  });
  await activity.log({
    projectId, user, action: 'claude_code_proposed', entityType: 'mcp_proposal',
    entityId: proposal.id, entityName: entity.name,
    meta: { via: 'claude-code', kind: 'note', entity_type: input.entity_type },
  });
  return { ...proposal, entity_name: entity.name };
}

// Campos editables por tipo: los mismos que acepta la tool de propuesta
// correspondiente (propose_finding / propose_note).
const FINDING_FIELDS = ['title', 'severity', 'category', 'description', 'remediation', 'cvss_vector', 'cvss_score', 'cwe', 'evidence', 'http_proofs'];
const FINDING_EXTRA  = ['target_id', 'evidence_upload_ids'];
const NOTE_FIELDS    = ['text', 'entity_type', 'entity_id'];

// Carga la propuesta del usuario EN este proyecto. Una propuesta ajena se
// reporta igual que una inexistente: no se confirma que exista.
async function loadOwnProposal(projectId, proposalId, userId) {
  const { rows } = await db.query(
    `SELECT * FROM mcp_proposals WHERE id = $1 AND project_id = $2 AND proposed_by = $3`,
    [proposalId, projectId, userId]
  );
  if (!rows.length) throw new ProposalError(404, `proposal "${proposalId}" is not one of your proposals in this project — call list_my_proposals`);
  return rows[0];
}

function notPending(status) {
  return new ProposalError(409, `proposal is already ${status} — only pending proposals can be changed or withdrawn`);
}

// Edición por quien propuso, mientras siga pendiente. Re-valida todo como
// al crear (scope, entidad, duplicado; rol y scope del token los re-valida
// la tool antes de llamar acá). La validación previa corre fuera de la
// transacción, pero el UPDATE condicionado a status='pending' AND
// proposed_by es el que decide: si un reviewer la aprobó en el medio, la
// edición no pisa nada y devuelve 409.
async function updateProposal({ projectId, proposalId, user, input }) {
  const current = await loadOwnProposal(projectId, proposalId, user.id);
  if (current.status !== 'pending') throw notPending(current.status);

  const given = k => input[k] !== undefined;
  const isFinding = current.kind === 'finding';
  const foreign = (isFinding ? NOTE_FIELDS : [...FINDING_FIELDS, ...FINDING_EXTRA]).filter(given);
  if (foreign.length) throw new ProposalError(400, `${foreign.join(', ')} cannot be set on a ${current.kind} proposal`);
  const changed = (isFinding ? [...FINDING_FIELDS, ...FINDING_EXTRA] : NOTE_FIELDS).filter(given);
  if (!changed.length) throw new ProposalError(400, 'nothing to update — pass at least one field to change');

  let payload, targetId = current.target_id, entityType = current.entity_type, entityId = current.entity_id, entityName;
  if (isFinding) {
    payload = { ...current.payload };
    for (const k of FINDING_FIELDS) if (given(k)) payload[k] = input[k];
    if (given('target_id') && input.target_id !== current.target_id) {
      targetId = (await assertTargetInScope(input.target_id, projectId)).id;
    }
    const dup = await findDuplicate(projectId, targetId, payload.title, current.id);
    if (dup) throw new ProposalError(409, dup);
    entityName = payload.title;
  } else {
    entityType = input.entity_type ?? current.entity_type;
    entityId   = input.entity_id ?? current.entity_id;
    const entity = await resolveNoteEntity(entityType, entityId, projectId);
    const moved = entityType !== current.entity_type || entityId !== current.entity_id;
    if (moved && entityType !== 'finding') await assertTargetInScope(entity.target_id, projectId);
    targetId = entity.target_id;
    payload = { text: input.text ?? current.payload.text, entity_name: entity.name };
    entityName = entity.name;
  }

  const updated = await inTransaction(async client => {
    const { rows } = await client.query(
      `UPDATE mcp_proposals
       SET payload = $4, target_id = $5, entity_type = $6, entity_id = $7, updated_at = NOW()
       WHERE id = $1 AND project_id = $2 AND proposed_by = $3 AND status = 'pending'
       RETURNING id, kind, status, updated_at`,
      [current.id, projectId, user.id, JSON.stringify(payload), targetId, entityType, entityId]
    );
    if (!rows.length) {
      const again = await client.query(`SELECT status FROM mcp_proposals WHERE id = $1`, [current.id]);
      throw notPending(again.rows[0]?.status || 'gone');
    }
    if (given('evidence_upload_ids')) {
      await uploads.attachUploads(client, { proposalId: current.id, userId: user.id, uploadIds: input.evidence_upload_ids });
    }
    return rows[0];
  });

  await activity.log({
    projectId, user, action: 'claude_code_proposal_updated', entityType: 'mcp_proposal',
    entityId: current.id, entityName,
    meta: { via: 'claude-code', kind: current.kind, fields: changed },
  });
  return { ...updated, fields: changed };
}

// Retiro por quien propuso. Nunca DELETE: la fila (y sus capturas) quedan
// para auditoría con status 'withdrawn'. Atómico igual que la aprobación.
async function withdrawProposal({ projectId, proposalId, user }) {
  const { rows } = await db.query(
    `UPDATE mcp_proposals SET status = 'withdrawn', updated_at = NOW()
     WHERE id = $1 AND project_id = $2 AND proposed_by = $3 AND status = 'pending'
     RETURNING id, kind, payload`,
    [proposalId, projectId, user.id]
  );
  if (!rows.length) {
    const current = await loadOwnProposal(projectId, proposalId, user.id);
    throw notPending(current.status);
  }
  const r = rows[0];
  await activity.log({
    projectId, user, action: 'claude_code_proposal_withdrawn', entityType: 'mcp_proposal',
    entityId: r.id, entityName: r.kind === 'finding' ? r.payload.title : r.payload.entity_name,
    meta: { via: 'claude-code', kind: r.kind },
  });
  return { id: r.id, kind: r.kind, status: 'withdrawn' };
}

// Capturas de una propuesta como data URLs, para que el inbox las muestre
// igual que la evidencia de un hallazgo. Se piden aparte (por propuesta) y
// no en el listado: son hasta 10 imágenes de 4 MB por propuesta.
async function getProposalEvidence(projectId, proposalId) {
  const { rows } = await db.query(`SELECT id FROM mcp_proposals WHERE id = $1 AND project_id = $2`, [proposalId, projectId]);
  if (!rows.length) throw new ProposalError(404, 'Proposal not found');
  return uploads.evidenceForProposal(db, proposalId);
}

const PROPOSAL_SELECT = `
  SELECT mp.id, mp.kind, mp.payload, mp.target_id, mp.entity_type, mp.entity_id, mp.status,
         mp.created_at, mp.updated_at, mp.reviewed_at, mp.resulting_vuln_id,
         ${uploads.UPLOADS_META_SQL} AS evidence_uploads,
         t.host AS target_host,
         pu.username AS proposed_by_username, pu.display_name AS proposed_by_display_name,
         ru.username AS reviewed_by_username, ru.display_name AS reviewed_by_display_name
  FROM mcp_proposals mp
  LEFT JOIN targets t ON t.id = mp.target_id
  LEFT JOIN users pu ON pu.id = mp.proposed_by
  LEFT JOIN users ru ON ru.id = mp.reviewed_by`;

async function listProposals(projectId, status = 'pending') {
  const { rows } = await db.query(
    `${PROPOSAL_SELECT} WHERE mp.project_id = $1 AND mp.status = $2 ORDER BY mp.created_at DESC LIMIT 500`,
    [projectId, status]
  );
  return rows;
}

// Aprobación atómica: el UPDATE condicionado a status='pending' es el que
// gana la carrera — dos aprobaciones simultáneas se serializan en el lock de
// la fila y la segunda ya no la encuentra pendiente (409, sin hallazgo
// duplicado). Si crear el hallazgo/nota falla, el ROLLBACK la deja pendiente.
async function approveProposal({ projectId, proposalId, user }) {
  const client = await db.pool.connect();
  let proposal, vulnId = null;
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE mcp_proposals SET status = 'approved', reviewed_by = $3, reviewed_at = NOW()
       WHERE id = $1 AND project_id = $2 AND status = 'pending'
       RETURNING *`,
      [proposalId, projectId, user.id]
    );
    if (!rows.length) {
      const exists = await db.query(`SELECT status FROM mcp_proposals WHERE id = $1 AND project_id = $2`, [proposalId, projectId]);
      if (!exists.rows.length) throw new ProposalError(404, 'Proposal not found');
      throw new ProposalError(409, `Proposal already ${exists.rows[0].status}`);
    }
    proposal = rows[0];
    const p = proposal.payload;

    if (proposal.kind === 'finding') {
      // Mismo INSERT que createFindingFromProposal() (agentLoop.js), más
      // origin y las notas. client_visible va explícito en false: publicar
      // al portal sigue siendo un paso aparte, de un lead.
      // El texto de evidencia va a `notes` (internas): `evidence` en
      // custom_vulns es la lista de imágenes, no admite texto.
      const validTargetId = await targetBelongsToProject(proposal.target_id, projectId);
      // Las capturas subidas se COPIAN a custom_vulns.evidence con el mismo
      // shape que escribe la UI (data URL + name + phase). Se leen con el
      // mismo client: misma transacción que el hallazgo.
      const images = (await uploads.evidenceForProposal(client, proposal.id))
        .map(img => ({ data: img.data, name: img.name, phase: 'original' }));
      const ins = await client.query(
        `INSERT INTO custom_vulns
           (project_id, name, category, severity, description, remediation, cwe, cvss_vector, cvss_score, http_proofs, notes, evidence, target_id, created_by, updated_by, ai_generated, client_visible, origin)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14,true,false,'claude_code') RETURNING id`,
        [
          projectId, p.title, p.category || 'Custom', p.severity || 'medium',
          p.description || '', p.remediation || '', p.cwe || null,
          p.cvss_vector || null, p.cvss_score ?? null, JSON.stringify(p.http_proofs || []),
          p.evidence || null, JSON.stringify(images), validTargetId, user.id,
        ]
      );
      vulnId = ins.rows[0].id;
      await client.query(`UPDATE mcp_proposals SET resulting_vuln_id = $1 WHERE id = $2`, [vulnId, proposal.id]);
    } else {
      const def = NOTE_ENTITIES[proposal.entity_type];
      const params = [proposal.entity_id, projectId, `[Claude Code] ${p.text}`];
      // Solo custom_vulns registra quién la editó ($4).
      if (proposal.entity_type === 'finding') params.push(user.id);
      const upd = await client.query(def.update, params);
      if (!upd.rowCount) throw new ProposalError(409, `The ${proposal.entity_type} this note was proposed for no longer exists`);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  if (proposal.kind === 'finding') {
    // Mismo evento que un hallazgo creado a mano o por el AI Agent; meta.via
    // es lo que el feed usa para marcar que vino de Claude Code.
    await activity.log({
      projectId, user, action: 'vuln_created', entityType: 'custom_vuln', entityId: vulnId,
      entityName: proposal.payload.title,
      meta: { severity: proposal.payload.severity, ai_generated: true, via: 'claude-code' },
    });
  } else {
    await activity.log({
      projectId, user, action: 'claude_code_proposal_approved', entityType: 'mcp_proposal',
      entityId: proposal.id, entityName: proposal.payload.entity_name,
      meta: { via: 'claude-code', kind: 'note', entity_type: proposal.entity_type },
    });
  }
  return { id: proposal.id, kind: proposal.kind, status: 'approved', resulting_vuln_id: vulnId };
}

async function rejectProposal({ projectId, proposalId, user }) {
  const { rows } = await db.query(
    `UPDATE mcp_proposals SET status = 'rejected', reviewed_by = $3, reviewed_at = NOW()
     WHERE id = $1 AND project_id = $2 AND status = 'pending'
     RETURNING id, kind, payload`,
    [proposalId, projectId, user.id]
  );
  if (!rows.length) {
    const exists = await db.query(`SELECT status FROM mcp_proposals WHERE id = $1 AND project_id = $2`, [proposalId, projectId]);
    if (!exists.rows.length) throw new ProposalError(404, 'Proposal not found');
    throw new ProposalError(409, `Proposal already ${exists.rows[0].status}`);
  }
  const r = rows[0];
  await activity.log({
    projectId, user, action: 'claude_code_proposal_rejected', entityType: 'mcp_proposal',
    entityId: r.id, entityName: r.kind === 'finding' ? r.payload.title : r.payload.entity_name,
    meta: { via: 'claude-code', kind: r.kind },
  });
  return { id: r.id, kind: r.kind, status: 'rejected' };
}

module.exports = {
  createFindingProposal, createNoteProposal, updateProposal, withdrawProposal,
  listProposals, approveProposal, rejectProposal, getProposalEvidence,
  ProposalError, NOTE_ENTITY_TYPES, MAX_PENDING_PER_PROJECT,
};
