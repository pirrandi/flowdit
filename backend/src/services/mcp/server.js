// Servidor MCP de Flowdit para Claude Code (ver routes/mcp.js). Se arma uno
// nuevo por request (modo stateless) con el usuario y el token ya resueltos
// por requireApiToken, así cada tool cierra sobre quién llama sin estado
// compartido entre requests.
//
// Política de escritura (aprobada explícitamente):
//   - Hallazgos, notas y TARGETS: solo propuestas. Proponer deja una fila en
//     mcp_proposals que un humano aprueba desde el inbox
//     (services/mcp/proposals.js); un target recién entra al proyecto con el
//     scope que elige el humano al aprobar. Lo único que se puede cambiar son
//     las PROPIAS propuestas pendientes (update_proposal / withdraw_proposal).
//   - Puertos y endpoints: escritura directa (add_ports / add_endpoints),
//     solo sobre targets en scope y activos, solo agregar (services/mcp/recon.js).
//   - Whiteboard: escritura directa SOLO de altas (notas, tarjetas, nodos,
//     flechas); nunca mueve, edita ni borra lo existente (services/mcp/whiteboard.js).
// Ninguna tool borra ni cambia estados/scope de datos del proyecto.
//
// Las descripciones y los errores van en inglés a propósito: los lee el
// modelo, no el usuario, igual que las tools del AI Agent.
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { z } = require('zod');
const db = require('../../db');
const { findProjectForUser, WRITER_ROLES } = require('../../middleware/project');
const { projectAccessSql } = require('../ownership');
const proposals = require('./proposals');
const recon = require('./recon');
const whiteboard = require('./whiteboard');
const { MAX_UPLOADS_PER_PROPOSAL, MAX_UPLOAD_BYTES } = require('./uploads');
const { version } = require('../../../package.json');

const uuid = z.string().uuid();
// Rol de proyecto de la cuenta del cliente: nunca accede por MCP (ver projectFor).
const CLIENT_ROLE = 'viewer';
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
const PROPOSE   = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
// Altas directas e idempotentes (lo repetido se saltea).
const ADD_ONLY  = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const TARGET_TYPES = ['domain', 'ip', 'cidr', 'url', 'other'];
const PORT_STATES  = ['open', 'filtered', 'closed'];
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'OTHER'];

// El equipo entrega los informes en español: todo texto que termina en un
// hallazgo o nota (título, descripción, remediación, evidencia narrada) tiene
// que llegar ya en español, no traducirse después a mano al aprobar.
// Identificadores técnicos (CWE, CVSS, HTTP crudo, nombres de producto) no
// se traducen.
const LANGUAGE_RULE =
  'ALWAYS write every proposal in Spanish (español): title, description, remediation, ' +
  'category, evidence narrative, http_proofs annotations and note text. Keep technical ' +
  'identifiers untranslated (CWE ids, CVSS vectors, raw HTTP requests/responses, code, ' +
  'product and parameter names). This applies even if the conversation is in another language.';

const INSTRUCTIONS =
  'Flowdit is a pentest management platform. These tools let you READ project data ' +
  '(projects, targets, ports, endpoints, findings, whiteboard), PROPOSE new findings, notes ' +
  'or targets, and directly ADD observed ports/endpoints and whiteboard items. ' +
  'Proposals are drafts: a human must approve them in Flowdit before they become real ' +
  'findings/notes/targets (a human also decides the scope of a proposed target). Ports and ' +
  'endpoints can only be added to targets with scope "in" and status "active". Nothing here can ' +
  'edit, delete or publish existing data, or change any scope. Only propose ' +
  'findings against targets that are in scope (list_targets shows scope/status), and ' +
  'check list_findings first to avoid duplicates. While a proposal is still pending you can ' +
  'fix it with update_proposal or withdraw it with withdraw_proposal. Screenshots are ' +
  'uploaded out of band (call get_upload_instructions WITH project_id first) and attached by id. ' +
  'Prefer a REAL screenshot; only if a real capture is impossible, generate an illustrative image and ' +
  'label it as reconstructed. Follow the cropping rules it returns and use the shell_prompt it gives ' +
  'for any terminal capture — never a placeholder prompt. ' +
  LANGUAGE_RULE;

// Campos de un hallazgo, compartidos por propose_finding (obligatorios los
// básicos) y update_proposal (todos opcionales).
const FINDING_FIELDS = {
  title: z.string().trim().min(3).max(300).describe('Short finding title in Spanish, e.g. "XSS reflejado en el parámetro de búsqueda"'),
  severity: z.enum(SEVERITIES),
  description: z.string().trim().min(1).max(20000).describe('What the issue is and its impact, in Spanish (markdown)'),
  remediation: z.string().trim().min(1).max(20000).describe('How to fix it, in Spanish (markdown)'),
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
  evidence_upload_ids: z.array(uuid).max(MAX_UPLOADS_PER_PROPOSAL).optional()
    .describe(`Screenshots to attach (max ${MAX_UPLOADS_PER_PROPOSAL}): upload_id values returned by POST /mcp/uploads. See get_upload_instructions.`),
};

// Campos de un target propuesto. NO hay scope a propósito: lo elige el
// humano al aprobar (ver approveProposal en proposals.js).
const TARGET_FIELDS = {
  host: z.string().trim().min(1).max(500).describe('Hostname, IP, CIDR or URL exactly as it should appear in the target list, e.g. "api.example.com"'),
  type: z.enum(TARGET_TYPES).describe('domain, ip, cidr, url or other'),
  notes: z.string().trim().max(10000).optional().describe('Why this target is relevant / how it was discovered (in Spanish)'),
};

// Host de shell a partir del nombre de la organización: minúsculas, lo que no
// sea [a-z0-9] pasa a "-", sin guiones colgando, acotado. Es lo que va después
// del "@" en el prompt de una captura de terminal (user@host), así que tiene
// que parecer un hostname, no el nombre con espacios. Si no queda nada usable,
// cae a "flowdit".
function orgHost(name) {
  const slug = String(name || '')
    .normalize('NFD').replace(/[̀-ͯ]/g, '') // quita acentos: "Résility" -> "Resility"
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);
  return slug || 'flowdit';
}

// Instrucciones de subida. NUNCA llevan el token: el modelo ya lo tiene en
// la config de Claude Code y devolverlo acá lo dejaría en el transcript.
// `shellPrompt` es el user@host que debe aparecer en cualquier captura de
// terminal (ver get_upload_instructions): el usuario real de Flowdit y la
// organización dueña del proyecto, nunca un placeholder inventado.
function uploadInstructions(uploadsUrl, shellPrompt) {
  const command = `curl -sS -H "Authorization: Bearer $FLOWDIT_TOKEN" -F "file=@/path/to/screenshot.png" ${uploadsUrl}`;
  const rendering = [
    'PRIORITY: attach a REAL screenshot — an actual capture of the command/tool output you ran or the browser state you observed. A real capture is always preferred; it is the only thing that truly proves a finding.',
    'ONLY if a real capture is genuinely impossible (no display, output not visually capturable, etc.) may you generate an illustrative image reconstructing the output. A generated image is a fallback, never the default.',
    'A generated/illustrative image MUST be visibly labelled as such (e.g. a header like "Reconstrucción — no es una captura real") and the proposal text must say the evidence was reconstructed. Never pass a generated image off as a real screenshot — fabricated evidence presented as real is a serious integrity problem in a pentest report.',
    'Crop the image tightly to its content: no empty margins, no blank space above/below the text, no filler. The image bounds should hug the terminal/tool output.',
  ];
  if (shellPrompt) {
    rendering.push(`If a shell prompt is visible (real capture or reconstruction), it must read "${shellPrompt}" (real Flowdit user @ the organization running the engagement). Never use placeholders like "pentester@flowdit" or "user@host".`);
  }
  return {
    upload_url: uploadsUrl,
    method: 'POST multipart/form-data, one file per request in the field "file"',
    command,
    token: 'Use the same fdt_ API token configured for this MCP server (scope "read_propose"). If $FLOWDIT_TOKEN is not set in the shell, ask the user to export it — never print or log the token.',
    accepted: `PNG, JPEG or WebP (detected from the file content), max ${MAX_UPLOAD_BYTES / 1024 / 1024} MB each`,
    rendering,
    ...(shellPrompt ? { shell_prompt: shellPrompt } : {}),
    response: '{ "upload_id": "...", "name": "...", "size": 123, "mime": "image/png" }',
    next_step: `Pass the upload_id values in evidence_upload_ids of propose_finding or update_proposal (max ${MAX_UPLOADS_PER_PROPOSAL} per proposal), or in images[].upload_id of add_whiteboard_items to place them on the whiteboard. Unattached uploads expire after 24h and each upload can be used only once (one proposal or one whiteboard image).`,
  };
}

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

function buildMcpServer({ user, token, uploadsUrl }) {
  const server = new McpServer({ name: 'flowdit', version }, { instructions: INSTRUCTIONS });

  // El acceso se re-valida en CADA tool call (membership + opt-in del
  // proyecto), nunca se confía en lo que devolvió list_projects antes: el
  // owner puede apagar claude_code_enabled o sacar al usuario a mitad de
  // sesión. Un proyecto apagado responde igual que uno inexistente.
  //
  // Un rol de proyecto 'viewer' es la cuenta del CLIENTE (page.js lo manda a
  // la vista cliente y desde 26fe968 solo recibe datos client-safe). Por MCP
  // leería el proyecto completo, borradores incluidos, así que para Claude
  // Code ese proyecto no existe: mismo error que para un no-miembro, sin
  // confirmar siquiera que el proyecto existe.
  async function projectFor(projectId, { propose = false } = {}) {
    const project = await findProjectForUser(projectId, user.id);
    if (!project || !project.claude_code_enabled || project.member_role === CLIENT_ROLE) {
      throw new Error(`project "${projectId}" not found or Claude Code access is not enabled for it — call list_projects to see the projects you can use`);
    }
    if (propose) {
      // `propose` cubre toda escritura (propuestas y altas directas de
      // puertos/endpoints/whiteboard): el único scope que escribe es read_propose.
      if (token.scopes !== 'read_propose') {
        throw new Error('this API token is read-only (scope "read") — the user must create a token with scope "read_propose" in Flowdit to propose or add data');
      }
      if (!WRITER_ROLES.includes(project.member_role)) {
        throw new Error(`your role in this project is "${project.member_role}" — only owner, editor or pentester can propose or add data`);
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
       -- Mismo rol efectivo que findProjectForUser: los proyectos donde el
       -- usuario es viewer (cliente) no se listan (ver projectFor).
       WHERE (pm.user_id IS NOT NULL OR om.user_id IS NOT NULL) AND p.claude_code_enabled = true
         AND COALESCE(pm.role, CASE om.role WHEN 'owner' THEN 'owner' WHEN 'admin' THEN 'editor' END) <> $2
       ORDER BY p.updated_at DESC`,
      [user.id, CLIENT_ROLE]
    );
    return ok({ projects: rows, token_scope: token.scopes });
  }));

  server.registerTool('get_project', {
    description: 'Get a project overview: description, engagement dates, your role, a summary of its targets and finding counts by severity.',
    inputSchema: { project_id: uuid },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id }) => {
    const p = await projectFor(project_id);
    const [{ rows: org }, { rows: targets }, { rows: sev }, { rows: pend }] = await Promise.all([
      db.query('SELECT name FROM organizations WHERE id = $1', [p.organization_id]),
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
      organization: org[0]?.name || null,
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
    description: 'List the findings/notes/targets you proposed through Claude Code and their review status (pending, approved, rejected, withdrawn). Only pending ones can be changed with update_proposal or withdrawn with withdraw_proposal.',
    inputSchema: {
      project_id: uuid.optional().describe('Limit to one project'),
      status: z.enum(['pending', 'approved', 'rejected', 'withdrawn']).optional(),
    },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id, status }) => {
    if (project_id) await projectFor(project_id);
    const values = [user.id];
    // Solo proyectos a los que el usuario TODAVÍA tiene acceso y con Claude
    // Code habilitado — mismo criterio que list_projects (sin los proyectos
    // donde hoy es viewer: si lo bajaron a cliente, sus propuestas viejas
    // tampoco se exponen por MCP).
    values.push(CLIENT_ROLE);
    let where = `mp.proposed_by = $1 AND p.claude_code_enabled = true AND ${projectAccessSql('mp.project_id', '$1')}
      AND COALESCE(
        (SELECT vpm.role FROM project_members vpm WHERE vpm.project_id = mp.project_id AND vpm.user_id = $1),
        'non-member'
      ) <> $2`;
    if (project_id) { values.push(project_id); where += ` AND mp.project_id = $${values.length}`; }
    if (status)     { values.push(status);     where += ` AND mp.status = $${values.length}`; }
    const { rows } = await db.query(
      `SELECT mp.id, mp.project_id, p.name AS project_name, mp.kind, mp.status,
              mp.payload->>'title' AS title, mp.payload->>'severity' AS severity,
              mp.payload->>'host' AS host, mp.resulting_target_id,
              mp.entity_type, mp.entity_id, mp.payload->>'entity_name' AS entity_name,
              mp.target_id, mp.created_at, mp.updated_at, mp.reviewed_at, mp.resulting_vuln_id,
              (SELECT COUNT(*)::int FROM mcp_uploads u WHERE u.used_by_proposal_id = mp.id) AS evidence_images
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
      'first — proposing the same title for the same target again is rejected as a duplicate. ' +
      'To attach screenshots, first upload each image out of band with ' +
      '`curl -sS -H "Authorization: Bearer $FLOWDIT_TOKEN" -F "file=@shot.png" <flowdit>/mcp/uploads` ' +
      '(call get_upload_instructions for the exact URL) and pass the returned upload_id values in evidence_upload_ids.' +
      ' ' + LANGUAGE_RULE,
    inputSchema: {
      project_id: uuid,
      target_id: uuid.describe('Target the finding applies to (must be scope "in" and active)'),
      ...FINDING_FIELDS,
    },
    annotations: PROPOSE,
  }, guarded(async (input) => {
    await projectFor(input.project_id, { propose: true });
    const prop = await proposals.createFindingProposal({ projectId: input.project_id, user, tokenId: token.id, input });
    return ok({
      proposal_id: prop.id, status: prop.status, target: prop.target_host, evidence_images: prop.evidence_images,
      message: 'Finding proposed. It is pending human review in Flowdit; it is not part of the report until approved.',
    });
  }));

  server.registerTool('propose_note', {
    description:
      'Propose a note to append to a target, port, endpoint or finding of the project. Like ' +
      'propose_finding, it is only added after a team member approves it. Notes on targets, ports ' +
      'and endpoints require the target to be in scope and active.' +
      ' ' + LANGUAGE_RULE,
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

  server.registerTool('update_proposal', {
    description:
      'Change one of YOUR proposals while it is still pending review (not yet approved, rejected or ' +
      'withdrawn). Only the fields you pass change. Finding proposals accept the propose_finding ' +
      'fields (plus target_id; evidence_upload_ids REPLACES the attached screenshots, [] removes ' +
      'them); note proposals accept text, entity_type and entity_id; target proposals accept host, ' +
      'type and notes (never scope). Scope and duplicate checks run ' +
      'again as when proposing.' +
      ' ' + LANGUAGE_RULE,
    inputSchema: {
      project_id: uuid,
      proposal_id: uuid.describe('From propose_finding/propose_note/propose_target or list_my_proposals'),
      target_id: uuid.optional().describe('Finding proposals only: move it to another in-scope target'),
      ...Object.fromEntries(Object.entries(FINDING_FIELDS).map(([k, v]) => [k, v.optional()])),
      entity_type: z.enum(proposals.NOTE_ENTITY_TYPES).optional().describe('Note proposals only'),
      entity_id: uuid.optional().describe('Note proposals only'),
      text: z.string().trim().min(1).max(10000).optional().describe('Note proposals only'),
      host: TARGET_FIELDS.host.optional().describe('Target proposals only'),
      type: TARGET_FIELDS.type.optional().describe('Target proposals only'),
      notes: TARGET_FIELDS.notes.describe('Target proposals only'),
    },
    annotations: { ...PROPOSE, idempotentHint: true },
  }, guarded(async ({ project_id, proposal_id, ...fields }) => {
    await projectFor(project_id, { propose: true });
    const r = await proposals.updateProposal({ projectId: project_id, proposalId: proposal_id, user, input: fields });
    return ok({
      proposal_id: r.id, kind: r.kind, status: r.status, updated_fields: r.fields,
      message: 'Proposal updated. It is still pending human review.',
    });
  }));

  server.registerTool('withdraw_proposal', {
    description:
      'Withdraw one of YOUR proposals that is still pending review, e.g. if it turned out to be a ' +
      'false positive. It is kept for audit with status "withdrawn" and can no longer be approved.',
    inputSchema: { project_id: uuid, proposal_id: uuid },
    annotations: { ...PROPOSE, destructiveHint: true, idempotentHint: true },
  }, guarded(async ({ project_id, proposal_id }) => {
    await projectFor(project_id, { propose: true });
    const r = await proposals.withdrawProposal({ projectId: project_id, proposalId: proposal_id, user });
    return ok({ proposal_id: r.id, kind: r.kind, status: r.status, message: 'Proposal withdrawn.' });
  }));

  server.registerTool('propose_target', {
    description:
      'Propose a new target (host, IP, CIDR or URL) discovered during testing, e.g. a subdomain or an API ' +
      'host. This does NOT create the target: it goes to the project\'s proposals inbox and a team member ' +
      'approves it AND decides its scope (in or out) — you cannot set the scope and must not assume a ' +
      'proposed target is in scope. Until it is approved, do not test it. Check list_targets first: a host ' +
      'that already exists (ignoring scheme, case and trailing slash) is rejected as a duplicate.' +
      ' ' + LANGUAGE_RULE,
    inputSchema: { project_id: uuid, ...TARGET_FIELDS },
    annotations: PROPOSE,
  }, guarded(async (input) => {
    await projectFor(input.project_id, { propose: true });
    const prop = await proposals.createTargetProposal({ projectId: input.project_id, user, tokenId: token.id, input });
    return ok({
      proposal_id: prop.id, status: prop.status, host: prop.host,
      message: 'Target proposed. It is pending human review in Flowdit; the reviewer decides its scope. Do not test it until it appears in list_targets with scope "in" and status "active".',
    });
  }));

  // ── Altas directas (sin aprobación) ────────────────────────────────────
  server.registerTool('add_ports', {
    description:
      `Record ports/services you observed on a target (max ${recon.MAX_PORTS_PER_CALL} per call). Written ` +
      'directly, without review, so only record what you actually observed. The target must have scope ' +
      '"in" and status "active". Ports already recorded (same port + protocol) are skipped and reported, ' +
      'not an error, so retrying a batch is safe. Cannot edit or delete existing ports.' +
      ' ' + LANGUAGE_RULE,
    inputSchema: {
      project_id: uuid,
      target_id: uuid.describe('Target (scope "in", status "active") from list_targets'),
      ports: z.array(z.object({
        port: z.number().int().min(1).max(65535),
        protocol: z.enum(['tcp', 'udp']).optional().describe('Default tcp'),
        state: z.enum(PORT_STATES).optional().describe('Default open'),
        service: z.string().trim().max(100).optional().describe('e.g. "http", "ssh"'),
        version: z.string().trim().max(200).optional().describe('e.g. "nginx 1.24.0"'),
        notes: z.string().trim().max(5000).optional(),
      })).min(1).max(recon.MAX_PORTS_PER_CALL),
    },
    annotations: ADD_ONLY,
  }, guarded(async ({ project_id, target_id, ports }) => {
    await projectFor(project_id, { propose: true });
    const r = await recon.addPorts({ projectId: project_id, user, targetId: target_id, ports });
    return ok({ target: r.target, added: r.added, skipped: r.skipped });
  }));

  server.registerTool('add_endpoints', {
    description:
      `Record HTTP endpoints you observed on a target (max ${recon.MAX_ENDPOINTS_PER_CALL} per call). Written ` +
      'directly, without review. The target must have scope "in" and status "active". Paths are ' +
      'normalized (no query string or fragment, no duplicate or trailing slashes); an endpoint already ' +
      'recorded (same normalized path + method) is skipped and reported, not an error. Cannot edit or ' +
      'delete existing endpoints.' +
      ' ' + LANGUAGE_RULE,
    inputSchema: {
      project_id: uuid,
      target_id: uuid.describe('Target (scope "in", status "active") from list_targets'),
      endpoints: z.array(z.object({
        path: z.string().trim().min(1).max(1000).describe('Path on the target, e.g. "/api/v1/users"'),
        method: z.enum(HTTP_METHODS).optional().describe('Default GET'),
        status_code: z.number().int().min(100).max(599).optional(),
        interesting: z.boolean().optional().describe('Flag endpoints worth a closer look'),
        notes: z.string().trim().max(5000).optional(),
      })).min(1).max(recon.MAX_ENDPOINTS_PER_CALL),
    },
    annotations: ADD_ONLY,
  }, guarded(async ({ project_id, target_id, endpoints }) => {
    await projectFor(project_id, { propose: true });
    const r = await recon.addEndpoints({ projectId: project_id, user, targetId: target_id, endpoints });
    return ok({ target: r.target, added: r.added, skipped: r.skipped });
  }));

  // ── Whiteboard (solo agregar) ──────────────────────────────────────────
  server.registerTool('get_whiteboard', {
    description:
      'Get a compact summary of the project whiteboard: target nodes, cards (with what they link to; a card linked ' +
      'to a finding also carries that finding\'s current title, severity and remediation_status, or deleted: true), ' +
      'sticky notes, images (with their caption) and arrows (with the endpoint/port each end points at and their style), with their ids, plus the targets not yet on the board. Every node, card, ' +
      'note and image includes its geometry (x, y, w, h in board px; y grows downwards). Items without an explicit ' +
      `size report the default they are drawn with (node ${whiteboard.SIZE.node.w}×${whiteboard.SIZE.node.h}, ` +
      `card ${whiteboard.SIZE.card.w}×${whiteboard.SIZE.card.h}, note ${whiteboard.SIZE.note.w}×${whiteboard.SIZE.note.h}); ` +
      'unsized cards and notes grow with their text, so their real height can be larger.',
    inputSchema: { project_id: uuid },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id }) => {
    await projectFor(project_id);
    return ok(await whiteboard.getWhiteboard(project_id));
  }));

  const offset = {
    dx: z.number().min(0).max(5000).optional().describe('Optional x offset (px) inside this batch; pass dx and dy together'),
    dy: z.number().min(0).max(5000).optional().describe('Optional y offset (px) inside this batch'),
  };
  const sizeRange = kind =>
    `${whiteboard.MIN_SIZE[kind].w}..${whiteboard.MAX_ITEM_SIZE} wide, ${whiteboard.MIN_SIZE[kind].h}..${whiteboard.MAX_ITEM_SIZE} tall`;
  const size = kind => ({
    w: z.number().positive().optional()
      .describe(`Optional width (px) of the new item, default ${whiteboard.SIZE[kind].w}; clamped to ${sizeRange(kind)}`),
    h: z.number().positive().optional()
      .describe(`Optional height (px) of the new item, default ${whiteboard.SIZE[kind].h}; the content scrolls if it does not fit`),
  });
  server.registerTool('add_whiteboard_items', {
    description:
      `Add items to the project whiteboard (max ${whiteboard.MAX_ITEMS_PER_CALL} per call): target nodes ` +
      '(a target box that shows its ports, endpoints and findings), cards (title + markdown body, ' +
      'optionally linked to a target, port, endpoint or finding of the project — a linked card gets an arrow to ' +
      'that target\'s node when it is on the board), sticky notes and images (screenshots uploaded first with ' +
      `POST /mcp/uploads, see get_upload_instructions; max ${whiteboard.MAX_IMAGES_PER_CALL} per call; each upload is ` +
      'consumed and cannot be reused). ADD-ONLY: existing items are never ' +
      'moved, edited or removed. The server places the batch in free space to the right of the current ' +
      'board; dx/dy optionally arrange items relative to each other inside the batch, and w/h optionally ' +
      'size the NEW items (larger items get larger grid cells so the batch never overlaps). Returns the new ' +
      'ids with their geometry (use the ids with connect_whiteboard_items).' +
      ' ' + LANGUAGE_RULE,
    inputSchema: {
      project_id: uuid,
      nodes: z.array(z.object({ target_id: uuid, ...offset, ...size('node') })).max(whiteboard.MAX_ITEMS_PER_CALL).optional()
        .describe('Target nodes to place (targets already on the board are skipped)'),
      cards: z.array(z.object({
        title: z.string().trim().min(1).max(200),
        body: z.string().max(5000).optional().describe('Markdown'),
        color: z.enum(whiteboard.CARD_COLORS).optional(),
        link: z.object({ type: z.enum(whiteboard.REF_TYPES), id: uuid }).optional()
          .describe('Target, port, endpoint or finding of this project the card is about. A finding card always shows the finding\'s CURRENT title, severity and remediation status in its header (your title is kept only as a fallback), with your body below'),
        ...offset,
        ...size('card'),
      })).max(whiteboard.MAX_ITEMS_PER_CALL).optional(),
      notes: z.array(z.object({
        text: z.string().trim().min(1).max(2000),
        color: z.enum(whiteboard.NOTE_COLORS).optional(),
        ...offset,
        ...size('note'),
      })).max(whiteboard.MAX_ITEMS_PER_CALL).optional(),
      images: z.array(z.object({
        upload_id: uuid.describe('upload_id returned by POST /mcp/uploads (your own, unused, less than 24h old)'),
        caption: z.string().trim().max(300).optional().describe('Short caption shown under the image'),
        ...offset,
        w: z.number().positive().optional()
          .describe(`Optional width (px), default ${whiteboard.SIZE.image.w} (or the image width if smaller); with only w or h the other keeps the image aspect ratio; clamped to ${sizeRange('image')}`),
        h: z.number().positive().optional().describe('Optional height (px)'),
      })).max(whiteboard.MAX_IMAGES_PER_CALL).optional(),
    },
    annotations: { ...ADD_ONLY, idempotentHint: false },
  }, guarded(async ({ project_id, nodes, cards, notes, images }) => {
    await projectFor(project_id, { propose: true });
    const r = await whiteboard.addItems({ projectId: project_id, user, nodes, cards, notes, images });
    const pick = kind => it => ({ id: it.id, ...whiteboard.geometry(kind, it) });
    return ok({
      added: {
        nodes: r.added.nodes.map(pick('node')), cards: r.added.cards.map(pick('card')), notes: r.added.notes.map(pick('note')),
        images: r.added.images.map(pick('image')),
        edges: r.added.edges.map(e => ({ id: e.id, from_id: e.fromId, to_id: e.toId })),
      },
      skipped: r.skipped,
    });
  }));

  server.registerTool('connect_whiteboard_items', {
    description:
      `Draw arrows between items already on the whiteboard (max ${whiteboard.MAX_EDGES_PER_CALL} per call). ` +
      'Arrows can connect target nodes (id = target id), cards, sticky notes and images. An end on a target node can ' +
      'point at one of that target\'s endpoints or ports (from_endpoint_id / from_port_id, to_endpoint_id / ' +
      'to_port_id; ids from list_endpoints / list_ports); the arrow then anchors on that row of the node. ' +
      'Optional style (line), arrow (which end gets the arrowhead, default end) and color. A connection that ' +
      'already exists in either direction (same items and endpoints/ports) is skipped, as is an item connected ' +
      'to itself. ADD-ONLY: nothing existing changes.' +
      ' ' + LANGUAGE_RULE,
    inputSchema: {
      project_id: uuid,
      edges: z.array(z.object({
        from_id: z.string().uuid(),
        to_id: z.string().uuid(),
        label: z.string().trim().max(100).optional(),
        from_endpoint_id: uuid.optional().describe('Endpoint of the target whose node is from_id'),
        to_endpoint_id: uuid.optional().describe('Endpoint of the target whose node is to_id'),
        from_port_id: uuid.optional().describe('Port of the target whose node is from_id'),
        to_port_id: uuid.optional().describe('Port of the target whose node is to_id'),
        style: z.enum(whiteboard.EDGE_STYLES).optional().describe('Line style, default solid'),
        arrow: z.enum(whiteboard.EDGE_ARROWS).optional().describe('Arrowhead position, default end'),
        color: z.enum(whiteboard.EDGE_COLORS).optional().describe('Line color; omit for the theme default'),
      })).min(1).max(whiteboard.MAX_EDGES_PER_CALL),
    },
    annotations: { ...ADD_ONLY, idempotentHint: true },
  }, guarded(async ({ project_id, edges }) => {
    await projectFor(project_id, { propose: true });
    const r = await whiteboard.connectItems({ projectId: project_id, user, edges });
    return ok({
      added: r.added.map(e => ({
        id: e.id, from_id: e.fromId, to_id: e.toId, label: e.label,
        ...(e.fromEp ? { from_endpoint_id: e.fromEp } : {}), ...(e.toEp ? { to_endpoint_id: e.toEp } : {}),
        ...(e.fromPort ? { from_port_id: e.fromPort } : {}), ...(e.toPort ? { to_port_id: e.toPort } : {}),
        style: e.style || 'solid', arrow: e.arrow || 'end', color: e.color || null,
      })),
      skipped: r.skipped,
    });
  }));

  server.registerTool('get_upload_instructions', {
    description: 'Get the exact command to upload a screenshot to Flowdit so it can be attached to a finding proposal via evidence_upload_ids or placed on the whiteboard via add_whiteboard_items images. Pass project_id to also get the real shell prompt (user@organization) and cropping rules your evidence screenshots must follow.',
    inputSchema: { project_id: uuid.optional().describe('The project the evidence is for — needed to build the correct user@organization shell prompt') },
    annotations: READ_ONLY,
  }, guarded(async ({ project_id }) => {
    let shellPrompt = null;
    if (project_id) {
      const p = await projectFor(project_id);
      const { rows } = await db.query('SELECT name FROM organizations WHERE id = $1', [p.organization_id]);
      shellPrompt = `${user.username}@${orgHost(rows[0]?.name)}`;
    }
    return ok({ ...uploadInstructions(uploadsUrl, shellPrompt), token_scope: token.scopes });
  }));

  return server;
}

module.exports = { buildMcpServer };
