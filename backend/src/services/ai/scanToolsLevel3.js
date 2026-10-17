// Nivel 3 — escritura en Flowdit. tier: 3. A diferencia de Nivel 2, esta
// tool NO tiene una acción real que "ejecutar" — proponer un hallazgo no
// hace nada por sí solo, es pura señal para el gate de aprobación.
// agentLoop.js (resolveGatedCall, rama tier===3) maneja la creación real en
// custom_vulns directamente cuando el pentester aprueba — por eso `execute`
// acá es solo un stub defensivo, nunca se llama en el flujo normal.
//
// Ya no hay `http_proofs` escritos por el modelo: era texto libre que el
// modelo podía inventar y terminaba en el informe como "proof HTTP". Ahora
// se citan `evidence_refs` (respuestas reales guardadas en ai_scan_events) y
// el backend arma los proofs a partir de ellas — ver evidence.js.

const propose_finding = {
  name: 'propose_finding',
  tier: 3,
  description:
    'Propose a new finding for the pentester to review. This does NOT create ' +
    'the finding — it generates a proposal that the pentester must explicitly ' +
    'approve, reject, or edit before anything is added to the report. Call ' +
    'get_existing_findings and search_vuln_templates first to avoid ' +
    'duplicating existing work and to reuse standard descriptions/remediation text. ' +
    'REQUIRED: evidence_refs — the evidence_ref values (e.g. "ev_123") of the real, ' +
    'successful responses in this session that show the issue. Every successful network ' +
    'tool result (fetch_endpoint, fetch_page_source, search_page_source, send_http_request, ' +
    'test_payload, run_exploit_poc, port_scan, subdomain_enum) carries one; not-found ' +
    '(404/410/soft-404) and failed results do not and cannot be cited. They must be from ' +
    'the same target as the finding. The cited requests/responses are attached verbatim ' +
    'as the finding\'s HTTP proofs — you do not write proofs yourself. No evidence yet? ' +
    'Test first; never propose from assumptions. To add ' +
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
      evidence_refs: {
        type: 'array', minItems: 1, maxItems: 10,
        items: { type: 'string' },
        description: 'evidence_ref values (e.g. ["ev_123"]) of successful network tool results in this session, on this target, that demonstrate the issue. Their requests/responses become the finding\'s HTTP proofs.',
      },
      confidence: { type: 'string', enum: ['low', 'medium', 'high'], description: 'How confident you are this is a real, exploitable issue — helps the pentester triage what to review first' },
    },
    required: ['name', 'category', 'severity', 'description', 'evidence_refs'],
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
    'e.g. to add evidence after more testing, refine the description, or bump ' +
    'confidence. Use this INSTEAD OF propose_finding when the issue is the same one ' +
    'already reported — propose_finding always creates a brand new finding, never ' +
    'edits an existing one. Call get_existing_findings first to get the finding_id. ' +
    'Only the fields you pass are changed, everything else is left as-is. ' +
    'evidence_refs (same rules as propose_finding) attach the cited responses as new HTTP proofs, ' +
    'APPENDED to the existing ones. They are REQUIRED when you raise the severity or set ' +
    'remediation_status "not_remediated" — those are new technical claims; purely editorial ' +
    'changes (wording, translation, remediation text) do not need them. ' +
    'During a retest, use remediation_status + retest_notes (+ retest_date) to record ' +
    'the outcome: "remediated" (client claims a fix), "verified_closed" (you confirmed the ' +
    'fix holds), "not_remediated" (retest shows it is still exploitable) or "open". ' +
    'Like every update_finding call, the pentester approves it before it is applied.',
  input_schema: {
    type: 'object',
    properties: {
      finding_id: { type: 'string', description: 'id of the existing finding, from get_existing_findings' },
      name: { type: 'string' },
      category: { type: 'string' },
      severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
      description: { type: 'string' },
      remediation: {
        type: 'string',
        description: 'The fix RECOMMENDATION for the client (how to remediate the issue) — replaces the existing text. ' +
          'Never put retest results or verification evidence here; those go in retest_notes.',
      },
      cwe: { type: 'string' },
      cvss_vector: { type: 'string' },
      cvss_score: { type: 'number' },
      remediation_status: {
        type: 'string',
        enum: ['open', 'remediated', 'not_remediated', 'verified_closed'],
        description: 'Retest outcome / remediation lifecycle status of the finding',
      },
      retest_date: { type: 'string', description: 'Date of the retest, YYYY-MM-DD' },
      retest_notes: { type: 'string', description: 'Retest verification: what was retested, how, and what was observed (evidence). Replaces the existing retest notes. Use this, NOT remediation, for retest results.' },
      evidence_refs: {
        type: 'array', maxItems: 10,
        items: { type: 'string' },
        description: 'evidence_ref values of successful network tool results in this session, on the finding\'s target — their requests/responses are APPENDED as HTTP proofs. Required when raising severity or setting remediation_status "not_remediated".',
      },
    },
    required: ['finding_id'],
  },
  async execute() {
    return { error: 'update_finding has no direct execution — it is resolved via the approval gate' };
  },
};

module.exports = { scanToolsLevel3: [propose_finding, update_finding] };
