// Servidor MCP de Flowdit para Claude Code (ver routes/mcp.js). Se arma uno
// nuevo por request (modo stateless) con el usuario y el token ya resueltos
// por requireApiToken, así cada tool cierra sobre quién llama sin estado
// compartido entre requests.
//
// v1 es SOLO lectura + propuestas: ninguna tool edita, borra, cambia estados
// ni crea targets. Proponer deja una fila en mcp_proposals que un humano
// aprueba desde el inbox (services/mcp/proposals.js).
//
// Las descripciones y los errores van en inglés a propósito: los lee el
// modelo, no el usuario, igual que las tools del AI Agent.
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');
const db = require('../../db');
const { findProjectForUser, WRITER_ROLES } = require('../../middleware/project');
const { projectAccessSql } = require('../ownership');
const proposals = require('./proposals');
const { version } = require('../../../package.json');

const uuid = z.string().uuid();
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
const PROPOSE   = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };

const INSTRUCTIONS =
  'Flowdit is a pentest management platform. These tools let you READ project data ' +
  '(projects, targets, ports, endpoints, findings) and PROPOSE new findings or notes. ' +
  'Proposals are drafts: a human must approve them in Flowdit before they become real ' +
  'findings/notes, and nothing here can edit, delete or publish anything. Only propose ' +
  'findings against targets that are in scope (list_targets shows scope/status), and ' +
  'check list_findings first to avoid duplicates.';

function ok(data) {
  return { content: [{ type: 'text', text: JSON.stringify(data) }] };
}

function clip(s, max = 4000) {
  if (typeof s !== 'string') return s;
  return s.length > max ? `${s.slice(0, max)}… [truncated ${s.length - max} chars]` : s;
}

// Errores pensados para el modelo (scope, permisos, duplicados) llegan tal
// cual; los de Postgres (traen `code` SQLSTATE) se loguean y se reemplazan por
// un mensaje genérico, para no filtrar SQL ni detalles internos.
function guarded(fn) {
  return async (args, extra) => {
    try {
      return await fn(args, extra);
    } catch (err) {
      if (typeof err?.code === 'string' && /^[0-9A-Z]{5}$/.test(err.code)) {
        console.error('MCP tool DB error:', err.message);
        return { content: [{ type: 'text', text: 'Internal error while querying Flowdit — try again later' }], isError: true };
      }
      return { content: [{ type: 'text', text: err?.message || String(err) }], isError: true };
    }
  };
}

function buildMcpServer({ user, token }) {
  const server = new McpServer({ name: 'flowdit', version }, { instructions: INSTRUCTIONS });

  // El acceso se re-valida en CADA tool call (membership + opt-in del
  // proyecto), nunca se confía en lo que devolvió list_projects antes: el
  // owner puede apagar claude_code_enabled o sacar al usuario a mitad de
  // sesión. Un proyecto apagado responde igual que uno inexistente.
  async function projectFor(projectId, { propose = false } = {}) {
    const project = await findProjectForUser(projectId, user.id);
    if (!project || !project.claude_code_enabled) {
      throw new Error(`project "${projectId}" not found or Claude Code access is not enabled for it — call list_projects to see the projects you can use`);
    }
    if (propose) {
      if (token.scopes !== 'read_propose') {
        throw new Error('this API token is read-only (scope "read") — the user must create a token with scope "read_propose" in Flowdit to propose findings or notes');
      }
      if (!WRITER_ROLES.includes(project.member_role)) {
        throw new Error(`your role in this project is "${project.member_role}" — only owner, editor or pentester can propose findings or notes`);
      }
    }
    return project;
  }

  async function targetFor(projectId, targetId) {
    const { rows } = await db.query(
      `SELECT id, host, type, scope, status FROM targets WHERE id = $1 AND project_id = $2`,
      [targetId, projectId]
    );
    if (!rows.length) throw new Error(`target_id "${targetId}" does not belong to this project — call list_targets`);
    return rows[0];
  }

  // ── Lectura ────────────────────────────────────────────────────────────
  server.registerTool('list_projects', {
    description: 'List the Flowdit projects you can access that have Claude Code access enabled, with your role in each.',
    inputSchema: {},
    annotations: READ_ONLY,
  }, guarded(async () => {
    const { rows } = await db.query(
      `SELECT p.id, p.name, p.status, p.target, p.date_start, p.date_end,
              COALESCE(pm.role, CASE om.role WHEN 'owner' THEN 'owner' WHEN 'admin' THEN 'editor' END) AS role
       FROM projects p
       LEFT JOIN project_members pm ON pm.project_id = p.id AND pm.user_id = $1
       LEFT JOIN organization_members om ON om.organization_id = p.organization_id AND om.user_id = $1 AND om.role IN ('owner','admin')
       WHERE (pm.user_id IS NOT NULL OR om.user_id IS NOT NULL) AND p.claude_code_enabled = true
       ORDER BY p.updated_at DESC`,
      [user.id]
    );
    return ok({ projects: rows, token_scope: token.scopes });
  }));

  server.registerTool('get_project', {
    description: 'Get a project overview: description, engagement dates, your role, a summary of its targets and finding counts by severity.',
    inputSchema: { project_id: uuid },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id }) => {
    const p = await projectFor(project_id);
    const [{ rows: targets }, { rows: sev }, { rows: pend }] = await Promise.all([
      db.query(
        `SELECT t.id, t.host, t.type, t.scope, t.status,
                (SELECT COUNT(*) FROM target_ports tp WHERE tp.target_id = t.id)::int AS ports,
                (SELECT COUNT(*) FROM target_endpoints te WHERE te.target_id = t.id)::int AS endpoints
         FROM targets t WHERE t.project_id = $1 ORDER BY t.created_at`,
        [project_id]
      ),
      db.query(`SELECT severity, COUNT(*)::int AS n FROM custom_vulns WHERE project_id = $1 GROUP BY severity`, [project_id]),
      db.query(`SELECT COUNT(*)::int AS n FROM mcp_proposals WHERE project_id = $1 AND status = 'pending'`, [project_id]),
    ]);
    return ok({
      id: p.id, name: p.name, status: p.status, target: p.target, description: p.description,
      date_start: p.date_start, date_end: p.date_end, your_role: p.member_role,
      can_propose: token.scopes === 'read_propose' && WRITER_ROLES.includes(p.member_role),
      targets,
      findings_by_severity: Object.fromEntries(sev.map(r => [r.severity, r.n])),
      pending_proposals: pend[0].n,
    });
  }));

  server.registerTool('list_targets', {
    description: 'List the targets (hosts/URLs/IP ranges) of a project with scope ("in"/"out"), status, notes and counts. Only act on targets with scope "in" and status "active".',
    inputSchema: { project_id: uuid },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id }) => {
    await projectFor(project_id);
    const { rows } = await db.query(
      `SELECT t.id, t.host, t.type, t.scope, t.status, t.notes,
              (SELECT COUNT(*) FROM target_ports tp WHERE tp.target_id = t.id)::int AS ports,
              (SELECT COUNT(*) FROM target_endpoints te WHERE te.target_id = t.id)::int AS endpoints,
              (SELECT COUNT(*) FROM custom_vulns v WHERE v.target_id = t.id)::int AS findings
       FROM targets t WHERE t.project_id = $1 ORDER BY t.created_at`,
      [project_id]
    );
    return ok({ targets: rows.map(t => ({ ...t, notes: clip(t.notes, 2000) })) });
  }));

  server.registerTool('list_ports', {
    description: 'List the ports/services recorded for one target of a project.',
    inputSchema: { project_id: uuid, target_id: uuid },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id, target_id }) => {
    await projectFor(project_id);
    const target = await targetFor(project_id, target_id);
    const { rows } = await db.query(
      `SELECT id, port, protocol, state, service, version, notes
       FROM target_ports WHERE target_id = $1 ORDER BY port, protocol`,
      [target_id]
    );
    return ok({ target: target.host, ports: rows.map(r => ({ ...r, notes: clip(r.notes, 1000) })) });
  }));

  server.registerTool('list_endpoints', {
    description: 'List the HTTP endpoints recorded for one target of a project (paginated).',
    inputSchema: {
      project_id: uuid,
      target_id: uuid,
      interesting_only: z.boolean().optional().describe('Only endpoints flagged as interesting'),
      limit: z.number().int().min(1).max(1000).optional().describe('Default 200'),
      offset: z.number().int().min(0).optional(),
    },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id, target_id, interesting_only, limit = 200, offset = 0 }) => {
    await projectFor(project_id);
    const target = await targetFor(project_id, target_id);
    const filter = interesting_only ? 'AND interesting = true' : '';
    const [{ rows }, { rows: total }] = await Promise.all([
      db.query(
        `SELECT id, method, path, status_code, interesting, notes
         FROM target_endpoints WHERE target_id = $1 ${filter}
         ORDER BY path, method LIMIT $2 OFFSET $3`,
        [target_id, limit, offset]
      ),
      db.query(`SELECT COUNT(*)::int AS n FROM target_endpoints WHERE target_id = $1 ${filter}`, [target_id]),
    ]);
    return ok({ target: target.host, total: total[0].n, offset, endpoints: rows.map(r => ({ ...r, notes: clip(r.notes, 1000) })) });
  }));

  server.registerTool('list_findings', {
    description: 'List the findings of a project (compact: no description). Use get_finding for the full detail of one.',
    inputSchema: {
      project_id: uuid,
      severity: z.enum(SEVERITIES).optional(),
      target_id: uuid.optional(),
    },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id, severity, target_id }) => {
    await projectFor(project_id);
    const values = [project_id];
    let where = 'v.project_id = $1';
    if (severity)  { values.push(severity);  where += ` AND v.severity = $${values.length}`; }
    if (target_id) { values.push(target_id); where += ` AND v.target_id = $${values.length}`; }
    const { rows } = await db.query(
      `SELECT v.id, v.name, v.severity, v.category, v.target_id, t.host AS target_host,
              v.cvss_score, v.cwe, v.remediation_status, v.client_visible, v.origin, v.created_at
       FROM custom_vulns v LEFT JOIN targets t ON t.id = v.target_id
       WHERE ${where}
       ORDER BY CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END, v.created_at`,
      values
    );
    return ok({ findings: rows });
  }));

  server.registerTool('get_finding', {
    description: 'Get the full detail of one finding: description, remediation, CVSS, CWE, notes and HTTP proofs (long texts are truncated).',
    inputSchema: { project_id: uuid, finding_id: uuid },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id, finding_id }) => {
    await projectFor(project_id);
    const { rows } = await db.query(
      `SELECT v.*, t.host AS target_host FROM custom_vulns v
       LEFT JOIN targets t ON t.id = v.target_id
       WHERE v.id = $1 AND v.project_id = $2`,
      [finding_id, project_id]
    );
    const v = rows[0];
    if (!v) throw new Error(`finding_id "${finding_id}" does not belong to this project — call list_findings`);
    return ok({
      id: v.id, name: v.name, severity: v.severity, category: v.category,
      target_id: v.target_id, target_host: v.target_host,
      description: clip(v.description, 20000), remediation: clip(v.remediation, 20000),
      cvss_vector: v.cvss_vector, cvss_score: v.cvss_score, cwe: v.cwe,
      notes: clip(v.notes, 10000), payloads: v.payloads,
      remediation_status: v.remediation_status, retest_notes: v.retest_notes,
      client_visible: v.client_visible, origin: v.origin, ai_generated: v.ai_generated,
      // Las imágenes de evidencia son data URLs de varios MB: solo la cuenta.
      evidence_images: Array.isArray(v.evidence) ? v.evidence.length : 0,
      http_proofs: (v.http_proofs || []).map(p => ({
        method: p.method, annotation: p.annotation, request: clip(p.request), response: clip(p.response),
      })),
      created_at: v.created_at, updated_at: v.updated_at,
    });
  }));

  server.registerTool('list_my_proposals', {
    description: 'List the findings/notes you proposed through Claude Code and their review status (pending, approved, rejected).',
    inputSchema: {
      project_id: uuid.optional().describe('Limit to one project'),
      status: z.enum(['pending', 'approved', 'rejected']).optional(),
    },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id, status }) => {
    if (project_id) await projectFor(project_id);
    const values = [user.id];
    // Solo proyectos a los que el usuario TODAVÍA tiene acceso y con Claude
    // Code habilitado — mismo criterio que list_projects.
    let where = `mp.proposed_by = $1 AND p.claude_code_enabled = true AND ${projectAccessSql('mp.project_id', '$1')}`;
    if (project_id) { values.push(project_id); where += ` AND mp.project_id = $${values.length}`; }
    if (status)     { values.push(status);     where += ` AND mp.status = $${values.length}`; }
    const { rows } = await db.query(
      `SELECT mp.id, mp.project_id, p.name AS project_name, mp.kind, mp.status,
              mp.payload->>'title' AS title, mp.payload->>'severity' AS severity,
              mp.entity_type, mp.entity_id, mp.payload->>'entity_name' AS entity_name,
              mp.created_at, mp.reviewed_at, mp.resulting_vuln_id
       FROM mcp_proposals mp JOIN projects p ON p.id = mp.project_id
       WHERE ${where}
       ORDER BY mp.created_at DESC LIMIT 100`,
      values
    );
    return ok({ proposals: rows });
  }));

  // ── Propuestas ─────────────────────────────────────────────────────────
  server.registerTool('propose_finding', {
    description:
      'Propose a new finding for human review. This does NOT create the finding: it goes to the ' +
      'project\'s "Claude Code proposals" inbox and only becomes a real (unpublished) finding when ' +
      'a team member approves it. The target must be in scope and active. Check list_findings ' +
      'first — proposing the same title for the same target again is rejected as a duplicate.',
    inputSchema: {
      project_id: uuid,
      target_id: uuid.describe('Target the finding applies to (must be scope "in" and active)'),
      title: z.string().trim().min(3).max(300).describe('Short finding title, e.g. "Reflected XSS in search parameter"'),
      severity: z.enum(SEVERITIES),
      description: z.string().trim().min(1).max(20000).describe('What the issue is and its impact (markdown)'),
      remediation: z.string().trim().min(1).max(20000).describe('How to fix it (markdown)'),
      category: z.string().trim().max(100).optional().describe('e.g. "XSS", "SQL Injection", "IDOR"'),
      cvss_vector: z.string().trim().regex(/^CVSS:3\.[01]\/[A-Z:/]+$/, 'must be a CVSS v3.x vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').max(200).optional(),
      cvss_score: z.number().min(0).max(10).optional(),
      cwe: z.string().trim().regex(/^CWE-\d{1,6}$/i, 'must look like "CWE-79"').optional(),
      evidence: z.string().max(50000).optional().describe('Reproduction steps / tool output as plain text. Stored as internal notes of the finding.'),
      http_proofs: z.array(z.object({
        method: z.string().max(10).optional(),
        request: z.string().max(50000).describe('Raw HTTP request text'),
        response: z.string().max(50000).optional().describe('Raw HTTP response text'),
        annotation: z.string().max(1000).optional(),
      })).max(10).optional().describe('Raw HTTP request/response proofs'),
    },
    annotations: PROPOSE,
  }, guarded(async (input) => {
    await projectFor(input.project_id, { propose: true });
    const prop = await proposals.createFindingProposal({ projectId: input.project_id, user, tokenId: token.id, input });
    return ok({
      proposal_id: prop.id, status: prop.status, target: prop.target_host,
      message: 'Finding proposed. It is pending human review in Flowdit; it is not part of the report until approved.',
    });
  }));

  server.registerTool('propose_note', {
    description:
      'Propose a note to append to a target, port, endpoint or finding of the project. Like ' +
      'propose_finding, it is only added after a team member approves it. Notes on targets, ports ' +
      'and endpoints require the target to be in scope and active.',
    inputSchema: {
      project_id: uuid,
      entity_type: z.enum(proposals.NOTE_ENTITY_TYPES),
      entity_id: uuid.describe('id of the target, port, endpoint or finding (from the list_* tools)'),
      text: z.string().trim().min(1).max(10000),
    },
    annotations: PROPOSE,
  }, guarded(async (input) => {
    await projectFor(input.project_id, { propose: true });
    const prop = await proposals.createNoteProposal({ projectId: input.project_id, user, tokenId: token.id, input });
    return ok({
      proposal_id: prop.id, status: prop.status, entity: prop.entity_name,
      message: 'Note proposed. It is pending human review in Flowdit.',
    });
  }));

  return server;
}

module.exports = { buildMcpServer };
