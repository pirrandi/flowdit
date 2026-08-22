// Nivel 3 — escritura en Flowdit. tier: 3. A diferencia de Nivel 2, esta
// tool NO tiene una acción real que "ejecutar" — proponer un hallazgo no
// hace nada por sí solo, es pura señal para el gate de aprobación.
// agentLoop.js (resolveGatedCall, rama tier===3) maneja la creación real en
// custom_vulns directamente cuando el pentester aprueba — por eso `execute`
// acá es solo un stub defensivo, nunca se llama en el flujo normal.

const propose_finding = {
  name: 'propose_finding',
  tier: 3,
  description:
    'Propose a new finding for the pentester to review. This does NOT create ' +
    'the finding — it generates a proposal that the pentester must explicitly ' +
    'approve, reject, or edit before anything is added to the report. Call ' +
    'get_existing_findings and search_vuln_templates first to avoid ' +
    'duplicating existing work and to reuse standard descriptions/remediation text. ' +
    'If you already have real HTTP evidence at this point (from send_http_request/ ' +
    'test_payload results you already ran for this issue), ALWAYS include it now ' +
    'in http_proofs — do not propose without it planning to add it later. To add ' +
    'evidence or refine a finding you already proposed, use update_finding instead ' +
    'of calling this again — calling this again for the same issue creates a ' +
    'duplicate finding, it does not edit the existing one.',
  input_schema: {
    type: 'object',
    properties: {
      name: { type: 'string', description: 'Short finding title, e.g. "Reflected XSS in search parameter"' },
      category: { type: 'string', description: 'e.g. "XSS", "SQL Injection", "IDOR" — matches Flowdit\'s vuln category conventions' },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
      target_id: { type: 'string', description: 'Optional — the target this finding applies to' },
      description: { type: 'string' },
      remediation: { type: 'string' },
      cwe: { type: 'string', description: 'Optional, e.g. "CWE-79"' },
      cvss_vector: { type: 'string', description: 'Optional CVSS v3.1 vector string' },
      cvss_score: { type: 'number', description: 'Optional CVSS v3.1 base score' },
      http_proofs: {
        type: 'array',
        description: 'Optional — raw HTTP request/response proof from your testing (based on send_http_request/test_payload results). Format request and response as plain raw HTTP text blocks (e.g. "GET /path HTTP/1.1\\nHost: example.com\\n..." and "HTTP/1.1 200 OK\\n...\\n\\n<body>"), not structured JSON — this renders as a proper HTTP proof in the report. There is no way to attach images/screenshots; do not invent an image field.',
        items: {
          type: 'object',
          properties: {
            method:     { type: 'string', description: 'e.g. "GET", "POST"' },
            request:    { type: 'string', description: 'Raw HTTP request text' },
            response:   { type: 'string', description: 'Raw HTTP response text' },
            annotation: { type: 'string', description: 'Optional short note explaining what this proof demonstrates' },
          },
        },
      },
      confidence: { type: 'string', enum: ['low', 'medium', 'high'], description: 'How confident you are this is a real, exploitable issue — helps the pentester triage what to review first' },
    },
    required: ['name', 'category', 'severity', 'description'],
  },
  async execute() {
    // No debería llamarse nunca — ver resolveGatedCall() en agentLoop.js.
    return { error: 'propose_finding has no direct execution — it is resolved via the approval gate' };
  },
};

// Encontrado en vivo: sin esta tool, la única forma que tenía el agente de
// "agregar proofs a un hallazgo ya propuesto" era llamar propose_finding de
// nuevo — eso NO edita nada, crea un hallazgo duplicado con el mismo
// nombre. Mismo tier/gate que propose_finding (sigue siendo una escritura
// en el reporte, el pentester la revisa igual).
const update_finding = {
  name: 'update_finding',
  tier: 3,
  description:
    'Update a finding you (or a previous turn) already proposed in this project — ' +
    'e.g. to add HTTP proofs after more testing, refine the description, or bump ' +
    'confidence. Use this INSTEAD OF propose_finding when the issue is the same one ' +
    'already reported — propose_finding always creates a brand new finding, never ' +
    'edits an existing one. Call get_existing_findings first to get the finding_id. ' +
    'Only the fields you pass are changed, everything else is left as-is. ' +
    'http_proofs is APPENDED to whatever proofs the finding already has, never replaced.',
  input_schema: {
    type: 'object',
    properties: {
      finding_id: { type: 'string', description: 'id of the existing finding, from get_existing_findings' },
      name: { type: 'string' },
      category: { type: 'string' },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
      description: { type: 'string' },
      remediation: { type: 'string' },
      cwe: { type: 'string' },
      cvss_vector: { type: 'string' },
      cvss_score: { type: 'number' },
      http_proofs: {
        type: 'array',
        description: 'New proofs to ADD to this finding (appended, existing proofs are kept) — same shape as propose_finding.http_proofs.',
        items: {
          type: 'object',
          properties: {
            method:     { type: 'string' },
            request:    { type: 'string' },
            response:   { type: 'string' },
            annotation: { type: 'string' },
          },
        },
      },
    },
    required: ['finding_id'],
  },
  async execute() {
    return { error: 'update_finding has no direct execution — it is resolved via the approval gate' };
  },
};

module.exports = { scanToolsLevel3: [propose_finding, update_finding] };
