// Nivel 0 — tools de solo lectura para el agente de scanner de IA. Sin gate
// de aprobación: no tienen efectos secundarios, solo leen datos que ya
// existen en el proyecto. Diseño completo en AI_PENTEST_AGENT.md.
//
// `project_id` NUNCA es un input que el modelo elige — siempre viene de
// `ctx.projectId`, inyectado por el backend desde la sesión autenticada.
// Esto es lo que impide que un prompt injection intente leer datos de otro
// proyecto: aunque el modelo "decida" pedir otro project_id, no hay forma
// de pasárselo a estas funciones. `target_id` sí lo puede elegir el modelo,
// pero cada query lo combina con project_id (o lo valida explícitamente
// contra targets) antes de devolver nada.
//
// Cada tool declara su propio `tier` — agentLoop.js decide gate sí/no según
// ese valor, nunca por nombre hardcodeado (ver scanToolsLevel1/2/3.js).

const db = require('../../db');

const scanTools = [
  {
    name: 'get_targets_in_scope',
    tier: 0,
    description:
      'Get every target currently in scope for this project (scope="in"). ' +
      'Always call this before proposing or performing any action against a ' +
      'target, so you never act outside the authorized engagement scope.',
    input_schema: { type: 'object', properties: {}, required: [] },
    async execute(_input, ctx) {
      const { rows } = await db.query(
        `SELECT id, host, type, status, notes
         FROM targets
         WHERE project_id=$1 AND scope='in'
         ORDER BY host`,
        [ctx.projectId]
      );
      return rows;
    },
  },

  {
    name: 'get_existing_findings',
    tier: 0,
    description:
      "Get findings already reported in this project, optionally filtered to " +
      "one target. Call this before proposing a new finding, so you don't " +
      'duplicate something already reported. The list is compact (no long text ' +
      'fields) — pass finding_id to get ONE finding in full (description, ' +
      'remediation, retest notes...). Always read a finding in full before ' +
      'update_finding changes any of its text fields.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string', description: 'Optional — limit to findings on this target' },
        finding_id: { type: 'string', description: 'Optional — return this one finding with all its fields' },
      },
      required: [],
    },
    async execute(input, ctx) {
      // Encontrado en vivo: sin forma de leer el texto actual, el agente
      // editaba a ciegas — pisó la remediación de 9 hallazgos sin saber qué
      // decía antes.
      if (input.finding_id) {
        const { rows } = await db.query(
          `SELECT id, name, category, severity, target_id, description, remediation, cwe,
                  cvss_vector, cvss_score, remediation_status, retest_date, retest_notes
           FROM custom_vulns WHERE id=$1 AND project_id=$2`,
          [input.finding_id, ctx.projectId]
        );
        return rows[0] || { error: 'finding not found in this project' };
      }
      const params = [ctx.projectId];
      let where = 'project_id=$1';
      if (input.target_id) { params.push(input.target_id); where += ` AND target_id=$${params.length}`; }
      const { rows } = await db.query(
        `SELECT id, name, category, severity, target_id, remediation_status
         FROM custom_vulns WHERE ${where} ORDER BY created_at DESC`,
        params
      );
      return rows;
    },
  },

  {
    name: 'search_vuln_templates',
    tier: 0,
    description:
      "Search Flowdit's built-in vulnerability template library by keyword or " +
      'category (e.g. "SQL injection", "IDOR", "XSS") to reuse standard ' +
      'descriptions, remediation text, and CWE mappings instead of writing ' +
      'them from scratch.',
    input_schema: {
      type: 'object',
      properties: { query: { type: 'string', description: 'Search term or category name' } },
      required: ['query'],
    },
    async execute(input) {
      const { rows } = await db.query(
        `SELECT id, name, category, severity, cwe, description, remediation, cvss_vector
         FROM vuln_templates
         WHERE to_tsvector('english', name) @@ plainto_tsquery('english', $1)
            OR category ILIKE '%' || $1 || '%'
         LIMIT 10`,
        [input.query]
      );
      return rows;
    },
  },

  {
    name: 'get_wstg_coverage',
    tier: 0,
    description:
      'Get which WSTG methodology test items are already marked done, ' +
      'failed, or N/A for this project, and which are still untested — use ' +
      'this to find coverage gaps to focus testing on.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string', description: 'Optional — limit to progress recorded against this target' },
      },
      required: [],
    },
    async execute(input, ctx) {
      const params = [ctx.projectId];
      let where = 'project_id=$1';
      if (input.target_id) { params.push(input.target_id); where += ` AND target_id=$${params.length}`; }
      const { rows } = await db.query(
        `SELECT test_id, status, target_id FROM wstg_progress WHERE ${where}`,
        params
      );
      return rows;
    },
  },

  {
    name: 'get_target_recon',
    tier: 0,
    description:
      "Get ports/services and endpoints already known for a specific target " +
      "(from prior scans or imports), so you don't re-discover information " +
      "that's already recorded. Call this before running any recon tool " +
      'against a target.',
    input_schema: {
      type: 'object',
      properties: { target_id: { type: 'string', description: 'The target to look up' } },
      required: ['target_id'],
    },
    async execute(input, ctx) {
      // target_ports/target_endpoints no tienen project_id propio (solo
      // target_id), así que acá sí hace falta validar la pertenencia contra
      // targets explícitamente antes de devolver nada.
      const { rows: targetRows } = await db.query(
        `SELECT id FROM targets WHERE id=$1 AND project_id=$2`,
        [input.target_id, ctx.projectId]
      );
      if (!targetRows.length) return { error: 'target_id does not belong to this project' };

      const [{ rows: ports }, { rows: endpoints }] = await Promise.all([
        db.query(`SELECT port, protocol, state, service, version FROM target_ports WHERE target_id=$1 ORDER BY port`, [input.target_id]),
        db.query(`SELECT path, method, status_code, interesting FROM target_endpoints WHERE target_id=$1 ORDER BY path`, [input.target_id]),
      ]);
      return { ports, endpoints };
    },
  },
];

module.exports = { scanTools };
