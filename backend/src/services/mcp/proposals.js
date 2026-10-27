// Propuestas de Claude Code (tabla mcp_proposals). Claude Code nunca escribe
// directo en custom_vulns, en las notas ni en targets: deja una propuesta, y
// recién cuando un writer del proyecto la aprueba desde el inbox se crea el
// hallazgo, se aplica el cambio propuesto a un hallazgo existente
// ('finding_update'), se agrega la nota o se crea el target (con el scope que
// elige el humano al aprobar: Claude Code nunca decide qué está en alcance).
// Compartido entre las tools MCP (crear) y
// routes/mcp-proposals.js (listar/aprobar/rechazar). Quien propuso puede
// editar o retirar su propuesta mientras siga pendiente.
const db       = require('../../db');
const activity = require('../activity');
const { targetBelongsToProject } = require('../ownership');
const { assertTargetInScope } = require('../ai/targetScope');
const uploads  = require('./uploads');
const report   = require('./report');
const ws       = require('../ws');
const { notifyProjectWriters } = require('../notifications');
const { isLeadRole } = require('../../middleware/project');

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

const NAME_NORM_SQL = col => `lower(btrim(regexp_replace(${col}, '\\s+', ' ', 'g')))`;

// Hallazgo del proyecto con ese nombre (normalizado) en ese target.
// `excludeVulnId`: al renombrar un hallazgo, no tiene que chocar consigo mismo.
async function findVulnByName(queryable, projectId, targetId, title, excludeVulnId = null) {
  const { rows } = await queryable.query(
    `SELECT id, name FROM custom_vulns
     WHERE project_id = $1 AND target_id IS NOT DISTINCT FROM $2
       AND ($4::uuid IS NULL OR id <> $4::uuid)
       AND ${NAME_NORM_SQL('name')} = ${NAME_NORM_SQL('$3')}
     LIMIT 1`,
    [projectId, targetId, title, excludeVulnId]
  );
  return rows[0] || null;
}

// Mismo criterio que findDuplicateFinding() del AI Agent (agentLoop.js):
// mismo nombre ignorando mayúsculas/espacios + mismo target = mismo hallazgo.
// Se mira tanto custom_vulns como las propuestas todavía pendientes (de
// hallazgo nuevo y de renombre de uno existente).
// `excludeProposalId`: al editar, la propuesta no tiene que chocar consigo misma.
// `excludeVulnId`: al proponer un cambio de título, el hallazgo propio no cuenta.
async function findDuplicate(projectId, targetId, title, excludeProposalId = null, excludeVulnId = null) {
  const norm = NAME_NORM_SQL('$3');
  const vuln = await findVulnByName(db, projectId, targetId, title, excludeVulnId);
  if (vuln) return `a finding named "${vuln.name}" already exists for this target (finding_id ${vuln.id}) — use propose_note or propose_finding_update on it instead`;
  const { rows: props } = await db.query(
    `SELECT id FROM mcp_proposals
     WHERE project_id = $1 AND kind IN ('finding','finding_update') AND status = 'pending' AND target_id IS NOT DISTINCT FROM $2
       AND ($4::uuid IS NULL OR id <> $4::uuid)
       AND ${NAME_NORM_SQL("payload->>'title'")} = ${norm}
     LIMIT 1`,
    [projectId, targetId, title, excludeProposalId]
  );
  if (props.length) return `a proposal with this finding title for this target is already pending review (proposal_id ${props[0].id}) — do not propose it again`;
  return null;
}

// Avisa a la sala del proyecto cuántas propuestas quedan pendientes (punto en
// "Findings" del nav + refresco del inbox). Se llama después de cada cambio
// de status ya confirmado; best-effort: si falla, la acción ya ocurrió y la
// próxima carga de página corrige el punto.
async function announcePending(projectId) {
  try {
    // `pending` feeds the Findings nav dot and inbox, which never show
    // report content; `report_pending` feeds the report builder (export.html).
    const { rows } = await db.query(
      `SELECT COUNT(*) FILTER (WHERE kind <> 'report_section')::int AS n,
              COUNT(*) FILTER (WHERE kind = 'report_section')::int AS report_n
       FROM mcp_proposals WHERE project_id = $1 AND status = 'pending'`,
      [projectId]
    );
    ws.broadcastProposalsChanged(projectId, rows[0].n, rows[0].report_n);
  } catch (err) {
    console.error('announcePending failed:', err.message);
  }
}

// Mismo criterio que normalizeHost() (ai/targetScope.js) más minúsculas:
// "https://App.example.com/" y "app.example.com" son el mismo target.
const HOST_NORM_SQL = col =>
  `lower(regexp_replace(regexp_replace(btrim(${col}), '^[a-z][a-z0-9+.-]*://', '', 'i'), '/+$', ''))`;

async function findDuplicateTarget(projectId, host, excludeProposalId = null) {
  const { rows: targets } = await db.query(
    `SELECT id, host, scope FROM targets
     WHERE project_id = $1 AND ${HOST_NORM_SQL('host')} = ${HOST_NORM_SQL('$2')} LIMIT 1`,
    [projectId, host]
  );
  if (targets.length) return `a target "${targets[0].host}" already exists in this project (target_id ${targets[0].id}, scope "${targets[0].scope}") — do not propose it again`;
  const { rows: props } = await db.query(
    `SELECT id FROM mcp_proposals
     WHERE project_id = $1 AND kind = 'target' AND status = 'pending'
       AND ($3::uuid IS NULL OR id <> $3::uuid)
       AND ${HOST_NORM_SQL("payload->>'host'")} = ${HOST_NORM_SQL('$2')}
     LIMIT 1`,
    [projectId, host, excludeProposalId]
  );
  if (props.length) return `an identical target proposal is already pending review (proposal_id ${props[0].id}) — do not propose it again`;
  return null;
}

// Nombre legible de una propuesta, para Activity.
function proposalName(kind, payload) {
  if (kind === 'finding') return payload.title;
  if (kind === 'target') return payload.host;
  if (kind === 'report_section') return reportTargetName(payload);
  return payload.entity_name; // note y finding_update
}

function reportTargetName(payload) {
  return payload.subsection_title ? `${payload.section_title} › ${payload.subsection_title}` : payload.section_title;
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
  // Sin await: ni el aviso ni la campana deben demorar (o romper) la
  // respuesta a Claude Code. notifyProjectWriters nunca rechaza.
  announcePending(projectId);
  notifyProjectWriters({
    projectId, type: 'ai_finding_proposed', entityType: 'mcp_proposal', entityId: proposal.id,
    payload: { source: 'claude_code', finding_title: input.title, severity: input.severity },
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
  announcePending(projectId);
  return { ...proposal, entity_name: entity.name };
}

// Propuesta de target: SIN scope. El scope lo elige el humano al aprobar
// (approveProposal), así Claude Code no puede poner nada en alcance.
async function createTargetProposal({ projectId, user, tokenId, input }) {
  await assertPendingCapacity(projectId);
  const dup = await findDuplicateTarget(projectId, input.host);
  if (dup) throw new ProposalError(409, dup);

  const payload = { host: input.host, type: input.type || 'domain', notes: input.notes || null };
  const proposal = await insertProposal(db, { projectId, kind: 'target', payload, targetId: null, user, tokenId });
  await activity.log({
    projectId, user, action: 'claude_code_proposed', entityType: 'mcp_proposal',
    entityId: proposal.id, entityName: input.host,
    meta: { via: 'claude-code', kind: 'target', type: payload.type },
  });
  announcePending(projectId);
  notifyProjectWriters({
    projectId, type: 'ai_target_proposed', entityType: 'mcp_proposal', entityId: proposal.id,
    payload: { source: 'claude_code', target_host: input.host, target_type: payload.type },
  });
  return { ...proposal, host: input.host };
}

// Campos de un hallazgo EXISTENTE que Claude Code puede proponer cambiar, con
// la columna de custom_vulns a la que van. Identificadores fijos del código:
// el UPDATE de approveProposal se arma solo con estas columnas. Afuera a
// propósito: target_id, client_visible (publicar es de un lead), origin,
// estados y notas (eso es propose_note). Las capturas (evidence) van aparte:
// subidas vinculadas a la propuesta + evidence_mode, ver EVIDENCE_MODES.
const FINDING_UPDATE_COLUMNS = {
  title: 'name', severity: 'severity', category: 'category', description: 'description',
  remediation: 'remediation', cvss_vector: 'cvss_vector', cvss_score: 'cvss_score', cwe: 'cwe',
  http_proofs: 'http_proofs',
};
const FINDING_UPDATE_FIELDS = Object.keys(FINDING_UPDATE_COLUMNS);
// Cómo se aplican las capturas propuestas al aprobar: 'append' las suma a las
// actuales; 'replace' reemplaza las de fase 'original' (sin fase = original)
// y conserva las de retest.
const EVIDENCE_MODES = ['append', 'replace'];
const DEFAULT_EVIDENCE_MODE = 'append';

// `evidence` (data URLs, pesado) solo se lee al aprobar, que es cuando se
// escribe.
async function loadFinding(queryable, projectId, findingId, { forUpdate = false } = {}) {
  const { rows } = await queryable.query(
    `SELECT id, name, target_id, ${FINDING_UPDATE_FIELDS.filter(f => f !== 'title').join(', ')}${forUpdate ? ', evidence' : ''}
     FROM custom_vulns WHERE id = $1 AND project_id = $2 ${forUpdate ? 'FOR UPDATE' : ''}`,
    [findingId, projectId]
  );
  return rows[0] || null;
}

function sameAsCurrent(finding, field, value) {
  const cur = finding[FINDING_UPDATE_COLUMNS[field]];
  if (field === 'http_proofs') return JSON.stringify(cur || []) === JSON.stringify(value || []);
  if (field === 'cvss_score') return cur != null && Number(cur) === Number(value);
  return String(cur ?? '') === String(value ?? '');
}

// Solo los campos que de verdad cambian respecto del hallazgo actual: el
// payload es un diff, no una copia completa.
function changesFor(finding, input) {
  const out = {};
  for (const k of FINDING_UPDATE_FIELDS) {
    if (input[k] !== undefined && !sameAsCurrent(finding, k, input[k])) out[k] = input[k];
  }
  return out;
}

async function pendingUpdateFor(projectId, findingId) {
  const { rows } = await db.query(
    `SELECT id FROM mcp_proposals
     WHERE project_id = $1 AND kind = 'finding_update' AND status = 'pending' AND entity_id = $2 LIMIT 1`,
    [projectId, findingId]
  );
  return rows[0]?.id || null;
}

function pendingUpdateError(proposalId) {
  return new ProposalError(409, `a change to this finding is already pending review (proposal_id ${proposalId}) — use update_proposal on that proposal instead of proposing again`);
}

// Propuesta de cambio a un hallazgo existente. Nunca toca custom_vulns: el
// cambio se aplica recién cuando un writer la aprueba (approveProposal).
async function createFindingUpdateProposal({ projectId, user, tokenId, input }) {
  const finding = await loadFinding(db, projectId, input.finding_id);
  if (!finding) throw new ProposalError(404, `finding_id "${input.finding_id}" does not belong to this project — call list_findings`);
  const uploadIds = input.evidence_upload_ids || [];
  if (input.evidence_mode !== undefined && !uploadIds.length) {
    throw new ProposalError(400, 'evidence_mode only applies together with evidence_upload_ids');
  }
  if (!FINDING_UPDATE_FIELDS.some(k => input[k] !== undefined) && !uploadIds.length) {
    throw new ProposalError(400, `nothing to change — pass at least one of: ${[...FINDING_UPDATE_FIELDS, 'evidence_upload_ids'].join(', ')}`);
  }
  const changes = changesFor(finding, input);
  const fields = Object.keys(changes);
  if (uploadIds.length) fields.push('evidence');
  if (!fields.length) throw new ProposalError(400, 'every field you passed already has that value in the finding — nothing to propose');
  await assertPendingCapacity(projectId);
  const pendingId = await pendingUpdateFor(projectId, finding.id);
  if (pendingId) throw pendingUpdateError(pendingId);
  if (changes.title !== undefined) {
    const dup = await findDuplicate(projectId, finding.target_id, changes.title, null, finding.id);
    if (dup) throw new ProposalError(409, dup);
  }

  const payload = { ...changes, entity_name: finding.name };
  if (uploadIds.length) payload.evidence_mode = input.evidence_mode || DEFAULT_EVIDENCE_MODE;
  // Propuesta + vínculo de capturas en una transacción, como en
  // createFindingProposal.
  let proposal, attached = [];
  try {
    await inTransaction(async client => {
      proposal = await insertProposal(client, {
        projectId, kind: 'finding_update', payload,
        targetId: finding.target_id, entityType: 'finding', entityId: finding.id, user, tokenId,
      });
      if (uploadIds.length) {
        attached = await uploads.attachUploads(client, { proposalId: proposal.id, userId: user.id, uploadIds });
      }
    });
  } catch (err) {
    // Carrera con otra propuesta simultánea sobre el mismo hallazgo: la
    // frena el índice único parcial (ver migrate.js).
    if (err.code === '23505' && err.constraint === 'uq_mcp_proposals_pending_finding_update') {
      throw pendingUpdateError(await pendingUpdateFor(projectId, finding.id));
    }
    throw err;
  }
  await activity.log({
    projectId, user, action: 'claude_code_proposed', entityType: 'mcp_proposal',
    entityId: proposal.id, entityName: finding.name,
    meta: { via: 'claude-code', kind: 'finding_update', finding_id: finding.id, fields, evidence_images: attached.length },
  });
  announcePending(projectId);
  notifyProjectWriters({
    projectId, type: 'ai_finding_update_proposed', entityType: 'mcp_proposal', entityId: proposal.id,
    payload: { source: 'claude_code', finding_title: finding.name, fields },
  });
  return { ...proposal, entity_name: finding.name, fields, evidence_images: attached.length };
}

// ── Report sections (report_section) ──────────────────────────────────
// The payload carries the target ids, the titles at proposal time (for the
// inbox and Activity), the sanitized HTML and `base_content`: the current
// HTML of that field when the proposal was made or last edited, so the
// reviewer sees before/after. Approval re-locates the target by id.

// Report proposals need their own opt-in on top of claude_code_enabled
// (the tools check it too; this covers update_proposal on an existing one).
async function assertReportEnabled(projectId) {
  const { rows } = await db.query(`SELECT claude_code_report_enabled FROM projects WHERE id = $1`, [projectId]);
  if (!rows[0]?.claude_code_report_enabled) throw new ProposalError(403, REPORT_DISABLED_MESSAGE);
}
const REPORT_DISABLED_MESSAGE = 'report proposals are not enabled for this project — the project owner must turn on "Proponer contenido del informe" in Settings → Claude Code';

async function loadReportData(queryable, projectId, { forUpdate = false } = {}) {
  const { rows } = await queryable.query(
    `SELECT data, updated_at FROM report_config WHERE project_id = $1 ${forUpdate ? 'FOR UPDATE' : ''}`,
    [projectId]
  );
  return rows[0] || null;
}

// Validates the target and the content and returns the payload to store.
async function reportPayload(projectId, { sectionId, subsectionId, content, rationale }) {
  const row = await loadReportData(db, projectId);
  if (!row || !report.sectionsOf(row.data).length) {
    throw new ProposalError(404, 'this project has no saved report yet — a lead must open the report builder (Export) once before sections can be proposed');
  }
  const loc = report.locateTarget(row.data, sectionId, subsectionId);
  if (loc.error) throw new ProposalError(400, loc.error);
  const clean = report.sanitizeReportHtml(content);
  if (!clean || report.isBlankHtml(clean)) throw new ProposalError(400, 'content is empty after sanitizing — send the section as HTML prose (p, ul/ol/li, strong, em, h3/h4, table, code, pre, blockquote, a)');
  if (clean.length > report.MAX_CONTENT_CHARS) throw new ProposalError(400, `content is too long after sanitizing (max ${report.MAX_CONTENT_CHARS} chars)`);
  return {
    section_id: sectionId, subsection_id: subsectionId || null,
    section_title: loc.sectionTitle, subsection_title: loc.subsectionTitle,
    field: loc.field, content: clean, base_content: loc.current, rationale: rationale || null,
  };
}

async function pendingReportProposalFor(projectId, sectionId, subsectionId, excludeProposalId = null) {
  const { rows } = await db.query(
    `SELECT id FROM mcp_proposals
     WHERE project_id = $1 AND kind = 'report_section' AND status = 'pending'
       AND payload->>'section_id' = $2 AND COALESCE(payload->>'subsection_id', '') = $3
       AND ($4::uuid IS NULL OR id <> $4::uuid)
     LIMIT 1`,
    [projectId, sectionId, subsectionId || '', excludeProposalId]
  );
  return rows[0]?.id || null;
}

function pendingReportError(proposalId) {
  return new ProposalError(409, `a proposal for this report section is already pending review (proposal_id ${proposalId}) — use update_proposal on that proposal instead of proposing again`);
}

async function createReportSectionProposal({ projectId, user, tokenId, input }) {
  await assertReportEnabled(projectId);
  const payload = await reportPayload(projectId, {
    sectionId: input.section_id, subsectionId: input.subsection_id, content: input.content, rationale: input.rationale,
  });
  await assertPendingCapacity(projectId);
  const pendingId = await pendingReportProposalFor(projectId, payload.section_id, payload.subsection_id);
  if (pendingId) throw pendingReportError(pendingId);

  let proposal;
  try {
    proposal = await insertProposal(db, { projectId, kind: 'report_section', payload, targetId: null, user, tokenId });
  } catch (err) {
    // Race with a simultaneous proposal for the same section (see migrate.js).
    if (err.code === '23505' && err.constraint === 'uq_mcp_proposals_pending_report_section') {
      throw pendingReportError(await pendingReportProposalFor(projectId, payload.section_id, payload.subsection_id));
    }
    throw err;
  }
  await activity.log({
    projectId, user, action: 'claude_code_proposed', entityType: 'mcp_proposal',
    entityId: proposal.id, entityName: reportTargetName(payload),
    meta: { via: 'claude-code', kind: 'report_section', section_id: payload.section_id, subsection_id: payload.subsection_id },
  });
  announcePending(projectId);
  return { ...proposal, section_title: payload.section_title, subsection_title: payload.subsection_title, field: payload.field };
}

// Campos editables por tipo: los mismos que acepta la tool de propuesta
// correspondiente (propose_finding / propose_note / propose_target /
// propose_finding_update). En un finding_update el hallazgo (entity_id) no
// se puede cambiar: para otro hallazgo, otra propuesta.
const FINDING_FIELDS = ['title', 'severity', 'category', 'description', 'remediation', 'cvss_vector', 'cvss_score', 'cwe', 'evidence', 'http_proofs'];
const FINDING_EXTRA  = ['target_id', 'evidence_upload_ids'];
const NOTE_FIELDS    = ['text', 'entity_type', 'entity_id'];
const TARGET_FIELDS  = ['host', 'type', 'notes'];
const FIELDS_BY_KIND = {
  finding: [...FINDING_FIELDS, ...FINDING_EXTRA],
  note:    NOTE_FIELDS,
  target:  TARGET_FIELDS,
  finding_update: [...FINDING_UPDATE_FIELDS, 'evidence_upload_ids', 'evidence_mode'],
  // The target section is fixed: for another section, another proposal.
  report_section: ['content', 'rationale'],
};
const ALL_FIELDS = [...new Set(Object.values(FIELDS_BY_KIND).flat())];

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
  const own = FIELDS_BY_KIND[current.kind];
  const foreign = ALL_FIELDS.filter(k => !own.includes(k)).filter(given);
  if (foreign.length) throw new ProposalError(400, `${foreign.join(', ')} cannot be set on a ${current.kind} proposal`);
  const changed = own.filter(given);
  if (!changed.length) throw new ProposalError(400, 'nothing to update — pass at least one field to change');

  let payload, targetId = current.target_id, entityType = current.entity_type, entityId = current.entity_id, entityName;
  if (current.kind === 'target') {
    payload = { ...current.payload };
    for (const k of TARGET_FIELDS) if (given(k)) payload[k] = input[k];
    const dup = await findDuplicateTarget(projectId, payload.host, current.id);
    if (dup) throw new ProposalError(409, dup);
    entityName = payload.host;
  } else if (current.kind === 'finding') {
    payload = { ...current.payload };
    for (const k of FINDING_FIELDS) if (given(k)) payload[k] = input[k];
    if (given('target_id') && input.target_id !== current.target_id) {
      targetId = (await assertTargetInScope(input.target_id, projectId)).id;
    }
    const dup = await findDuplicate(projectId, targetId, payload.title, current.id);
    if (dup) throw new ProposalError(409, dup);
    entityName = payload.title;
  } else if (current.kind === 'finding_update') {
    const finding = await loadFinding(db, projectId, current.entity_id);
    if (!finding) throw new ProposalError(409, 'the finding this change was proposed for no longer exists — withdraw this proposal');
    const merged = { ...current.payload };
    for (const k of FINDING_UPDATE_FIELDS) if (given(k)) merged[k] = input[k];
    const changes = changesFor(finding, merged);
    // Capturas que quedan vinculadas después de la edición: la lista nueva si
    // viene, si no las que ya tenía.
    const shots = given('evidence_upload_ids')
      ? new Set(input.evidence_upload_ids).size
      : (await db.query(`SELECT COUNT(*)::int AS n FROM mcp_uploads WHERE used_by_proposal_id = $1`, [current.id])).rows[0].n;
    if (given('evidence_mode') && !shots) {
      throw new ProposalError(400, 'evidence_mode only applies together with evidence_upload_ids');
    }
    if (!Object.keys(changes).length && !shots) {
      throw new ProposalError(400, 'with this edit the proposal would not change anything in the finding — withdraw it instead');
    }
    if (changes.title !== undefined) {
      const dup = await findDuplicate(projectId, finding.target_id, changes.title, current.id, finding.id);
      if (dup) throw new ProposalError(409, dup);
    }
    payload = { ...changes, entity_name: finding.name };
    if (shots) payload.evidence_mode = input.evidence_mode ?? current.payload.evidence_mode ?? DEFAULT_EVIDENCE_MODE;
    targetId = finding.target_id;
    entityName = finding.name;
  } else if (current.kind === 'report_section') {
    await assertReportEnabled(projectId);
    const pl = current.payload;
    // Re-validated against the CURRENT report: the section may be gone, and
    // base_content is refreshed so the reviewer compares against what is
    // there now.
    payload = await reportPayload(projectId, {
      sectionId: pl.section_id, subsectionId: pl.subsection_id,
      content: given('content') ? input.content : pl.content,
      rationale: given('rationale') ? input.rationale : pl.rationale,
    });
    entityName = reportTargetName(payload);
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
    entityId: r.id, entityName: proposalName(r.kind, r.payload),
    meta: { via: 'claude-code', kind: r.kind },
  });
  announcePending(projectId);
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
         mp.created_at, mp.updated_at, mp.reviewed_at, mp.resulting_vuln_id, mp.resulting_target_id,
         ${uploads.UPLOADS_META_SQL} AS evidence_uploads,
         t.host AS target_host,
         -- Valores ACTUALES del hallazgo de un finding_update, para que el
         -- inbox muestre antes/después. NULL si el hallazgo ya no existe.
         CASE WHEN cv.id IS NOT NULL THEN jsonb_build_object(
           'title', cv.name, 'severity', cv.severity, 'category', cv.category,
           'description', cv.description, 'remediation', cv.remediation,
           'cvss_vector', cv.cvss_vector, 'cvss_score', cv.cvss_score, 'cwe', cv.cwe,
           'http_proofs', cv.http_proofs,
           'evidence_count', jsonb_array_length(COALESCE(cv.evidence, '[]'::jsonb)),
           'original_evidence_count', (SELECT COUNT(*) FROM jsonb_array_elements(COALESCE(cv.evidence, '[]'::jsonb)) e
                                       WHERE COALESCE(e->>'phase', 'original') = 'original')) END AS current_finding,
         pu.username AS proposed_by_username, pu.display_name AS proposed_by_display_name,
         ru.username AS reviewed_by_username, ru.display_name AS reviewed_by_display_name
  FROM mcp_proposals mp
  LEFT JOIN targets t ON t.id = mp.target_id
  LEFT JOIN custom_vulns cv ON mp.kind = 'finding_update' AND cv.id = mp.entity_id AND cv.project_id = mp.project_id
  LEFT JOIN users pu ON pu.id = mp.proposed_by
  LEFT JOIN users ru ON ru.id = mp.reviewed_by`;

// Every kind a proposal can have (mirrors mcp_proposals_kind_check).
const PROPOSAL_KINDS = ['finding', 'note', 'target', 'finding_update', 'report_section'];

// `kind` keeps only that kind, `excludeKind` drops it: the Findings inbox
// lists everything but report_section, the report builder only report_section.
async function listProposals(projectId, status = 'pending', { kind = null, excludeKind = null } = {}) {
  const { rows } = await db.query(
    `${PROPOSAL_SELECT} WHERE mp.project_id = $1 AND mp.status = $2
       AND ($3::text IS NULL OR mp.kind = $3) AND ($4::text IS NULL OR mp.kind <> $4)
     ORDER BY mp.created_at DESC LIMIT 500`,
    [projectId, status, kind, excludeKind]
  );
  return rows;
}

// Aprobación atómica: el UPDATE condicionado a status='pending' es el que
// gana la carrera — dos aprobaciones simultáneas se serializan en el lock de
// la fila y la segunda ya no la encuentra pendiente (409, sin hallazgo
// duplicado). Si crear el hallazgo/nota/target falla, el ROLLBACK la deja
// pendiente.
// `scope` ('in' | 'out') es obligatorio para una propuesta de target y no
// tiene default a propósito: poner algo en alcance es una decisión humana
// explícita, ni Claude Code ni un valor por omisión la toman.
const TARGET_SCOPES = ['in', 'out'];

// `role` is the approver's project role: report content is the client
// deliverable, so a report_section proposal needs a lead (owner/editor), the
// same rule as PUT /report-config, even though the route admits any writer.
async function approveProposal({ projectId, proposalId, user, scope, role }) {
  const client = await db.pool.connect();
  let proposal, vulnId = null, targetId = null, updatedName = null, evidenceApplied = 0, reportUpdatedAt = null;
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
    } else if (proposal.kind === 'target') {
      if (!TARGET_SCOPES.includes(scope)) {
        throw new ProposalError(400, 'Choose the scope for this target: "in" or "out"');
      }
      // Pudo crearse a mano mientras la propuesta esperaba.
      const { rows: dup } = await client.query(
        `SELECT host FROM targets WHERE project_id = $1 AND ${HOST_NORM_SQL('host')} = ${HOST_NORM_SQL('$2')} LIMIT 1`,
        [projectId, p.host]
      );
      if (dup.length) throw new ProposalError(409, `A target "${dup[0].host}" already exists in this project`);
      // Mismo INSERT que POST /targets (routes/targets.js), con quien aprueba
      // como added_by y el origen marcado.
      const ins = await client.query(
        `INSERT INTO targets (project_id, host, type, scope, notes, added_by, source)
         VALUES ($1,$2,$3,$4,$5,$6,'claude_code') RETURNING id`,
        [projectId, p.host, p.type || 'domain', scope, p.notes || '', user.id]
      );
      targetId = ins.rows[0].id;
      await client.query(`UPDATE mcp_proposals SET resulting_target_id = $1, target_id = $1 WHERE id = $2`, [targetId, proposal.id]);
    } else if (proposal.kind === 'finding_update') {
      // FOR UPDATE: nadie edita el hallazgo entre el chequeo y el UPDATE.
      const finding = await loadFinding(client, projectId, proposal.entity_id, { forUpdate: true });
      if (!finding) throw new ProposalError(409, 'The finding this change was proposed for no longer exists');
      // Pudo crearse (o renombrarse) otro hallazgo con ese nombre mientras
      // la propuesta esperaba.
      if (p.title !== undefined) {
        const dup = await findVulnByName(client, projectId, finding.target_id, p.title, finding.id);
        if (dup) throw new ProposalError(409, `A finding named "${dup.name}" already exists for this target`);
      }
      // Solo las columnas del payload (whitelist FINDING_UPDATE_COLUMNS) más
      // evidence si la propuesta trae capturas. No toca client_visible ni
      // origin.
      const values = [finding.id, projectId, user.id];
      const sets = [];
      for (const [field, col] of Object.entries(FINDING_UPDATE_COLUMNS)) {
        if (p[field] === undefined) continue;
        values.push(field === 'http_proofs' ? JSON.stringify(p[field] || []) : p[field]);
        sets.push(`${col} = $${values.length}`);
      }
      // Capturas: mismo shape que el branch 'finding'. 'replace' saca solo las
      // de fase original; las de retest se conservan.
      const images = (await uploads.evidenceForProposal(client, proposal.id))
        .map(img => ({ data: img.data, name: img.name, phase: 'original' }));
      if (images.length) {
        const current = Array.isArray(finding.evidence) ? finding.evidence : [];
        const kept = p.evidence_mode === 'replace'
          ? current.filter(e => (e?.phase || 'original') !== 'original')
          : current;
        values.push(JSON.stringify([...kept, ...images]));
        sets.push(`evidence = $${values.length}`);
        evidenceApplied = images.length;
      }
      if (!sets.length) throw new ProposalError(409, 'This proposal has no changes to apply');
      await client.query(
        `UPDATE custom_vulns SET ${sets.join(', ')}, updated_by = $3, updated_at = NOW()
         WHERE id = $1 AND project_id = $2`,
        values
      );
      vulnId = finding.id;
      updatedName = p.title ?? finding.name;
      await client.query(`UPDATE mcp_proposals SET resulting_vuln_id = $1 WHERE id = $2`, [vulnId, proposal.id]);
    } else if (proposal.kind === 'report_section') {
      if (!isLeadRole(role)) throw new ProposalError(403, 'Only the owner or an editor can approve report content');
      // FOR UPDATE: a PUT /report-config cannot interleave between reading
      // the blob and writing it back. Only the target field changes.
      const row = await loadReportData(client, projectId, { forUpdate: true });
      const loc = row ? report.locateTarget(row.data, p.section_id, p.subsection_id) : { error: 'the report no longer exists' };
      if (loc.error) {
        throw new ProposalError(409, `The report section this content was proposed for is no longer available (${loc.error}). The proposal stays pending: reject it, or ask Claude Code to propose again.`);
      }
      loc.holder[loc.field] = p.content;
      const serialized = JSON.stringify(row.data);
      if (Buffer.byteLength(serialized, 'utf8') > report.REPORT_MAX_BYTES) {
        throw new ProposalError(413, 'The report would become too large to store with this content');
      }
      // Same millisecond-precision, strictly increasing stamp as
      // PUT /report-config, which compares it for optimistic concurrency.
      const upd = await client.query(
        `UPDATE report_config
         SET data = $2, updated_by = $3,
             updated_at = GREATEST(date_trunc('milliseconds', clock_timestamp()), updated_at + INTERVAL '1 millisecond')
         WHERE project_id = $1 RETURNING updated_at`,
        [projectId, serialized, user.id]
      );
      reportUpdatedAt = upd.rows[0].updated_at;
      updatedName = reportTargetName(p);
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
  } else if (proposal.kind === 'target') {
    // Mismo evento que un target agregado a mano (target_added), así el feed,
    // los toasts y el refresco en vivo de Targets lo tratan igual.
    await activity.log({
      projectId, user, action: 'target_added', entityType: 'target', entityId: targetId,
      entityName: proposal.payload.host,
      meta: { type: proposal.payload.type || 'domain', scope, via: 'claude-code' },
    });
  } else if (proposal.kind === 'finding_update') {
    // Editar un hallazgo a mano (PATCH /vulns/:id) no deja evento en el feed,
    // solo refresca la lista. Acá sí queda uno, el de aprobar una propuesta
    // (como las notas), con qué campos cambiaron.
    await activity.log({
      projectId, user, action: 'claude_code_proposal_approved', entityType: 'mcp_proposal',
      entityId: proposal.id, entityName: updatedName,
      meta: {
        via: 'claude-code', kind: 'finding_update', finding_id: vulnId,
        fields: [
          ...Object.keys(proposal.payload).filter(k => FINDING_UPDATE_FIELDS.includes(k)),
          ...(evidenceApplied ? ['evidence'] : []),
        ],
        evidence_images: evidenceApplied,
      },
    });
    ws.broadcastVulnsChanged(projectId);
  } else if (proposal.kind === 'report_section') {
    await activity.log({
      projectId, user, action: 'claude_code_proposal_approved', entityType: 'mcp_proposal',
      entityId: proposal.id, entityName: updatedName,
      meta: {
        via: 'claude-code', kind: 'report_section',
        section_id: proposal.payload.section_id, subsection_id: proposal.payload.subsection_id,
      },
    });
    // Open report builders adopt the new server copy (export.html).
    ws.broadcastReportChanged(projectId, reportUpdatedAt);
  } else {
    await activity.log({
      projectId, user, action: 'claude_code_proposal_approved', entityType: 'mcp_proposal',
      entityId: proposal.id, entityName: proposal.payload.entity_name,
      meta: { via: 'claude-code', kind: 'note', entity_type: proposal.entity_type },
    });
    // Una nota aprobada sobre un hallazgo cambia custom_vulns.notes, pero el
    // evento de arriba es de la propuesta: avisar también a la lista.
    if (proposal.entity_type === 'finding') ws.broadcastVulnsChanged(projectId);
  }
  announcePending(projectId);
  return { id: proposal.id, kind: proposal.kind, status: 'approved', resulting_vuln_id: vulnId, resulting_target_id: targetId };
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
    entityId: r.id, entityName: proposalName(r.kind, r.payload),
    meta: { via: 'claude-code', kind: r.kind },
  });
  announcePending(projectId);
  return { id: r.id, kind: r.kind, status: 'rejected' };
}

module.exports = {
  createFindingProposal, createNoteProposal, createTargetProposal, createFindingUpdateProposal,
  createReportSectionProposal, assertReportEnabled, REPORT_DISABLED_MESSAGE, PROPOSAL_KINDS,
  updateProposal, withdrawProposal,
  listProposals, approveProposal, rejectProposal, getProposalEvidence,
  ProposalError, NOTE_ENTITY_TYPES, FINDING_UPDATE_FIELDS, EVIDENCE_MODES, MAX_PENDING_PER_PROJECT,
};
