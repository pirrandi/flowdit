const express = require('express');
const { requireAuth, requireUser } = require('../middleware/auth');

const router = express.Router();

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL   = 'llama-3.3-70b-versatile';

const SYSTEM_PROMPT = `Eres un pentester senior redactando informes profesionales de seguridad en español.
Escribe en tercera persona impersonal (ej. "se ha identificado", "se observó", "se logró", "se determinó") — nunca en primera persona.
El contenido debe ser técnicamente preciso y específico a la evidencia proporcionada — nunca escribas descripciones genéricas.
Puedes y debes usar markdown dentro de los valores del JSON: **negritas**, \`código inline\`, bloques de código con triple backtick, listas, saltos de línea con \\n.
Responde ÚNICAMENTE con JSON válido siguiendo el esquema solicitado. Sin texto fuera del objeto JSON.`;

router.post('/generate', requireAuth, requireUser, async (req, res) => {
  const { type, context = {} } = req.body;
  if (!type) return res.status(400).json({ error: 'type required' });

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY not configured' });

  const c = context;
  const payloadBlock = c.payloads?.length
    ? `Payloads used:\n${c.payloads.map(p => `  - ${p}`).join('\n')}`
    : '';

  let userPrompt;

  if (type === 'vuln-draft') {
    userPrompt = `Write a penetration test finding report entry using ONLY the details below. Do not invent data not present.

Finding name: ${c.name}
${c.category  ? `Category: ${c.category}` : ''}
${c.target    ? `Affected target: ${c.target}` : ''}
${c.notes     ? `Tester notes: ${c.notes}` : ''}
${payloadBlock}
${c.description ? `Partial description already written: ${c.description}` : ''}

Instrucciones:
- Todo el contenido debe estar redactado en español
- "name": título profesional y preciso que referencie el endpoint/parámetro específico si está disponible (máx 80 caracteres)
- "category": categoría OWASP más específica o etiqueta tecnológica aplicable
- "severity": elige critical/high/medium/low/info según el tipo de vulnerabilidad y contexto
- "description": 2-3 párrafos en markdown — explica qué es la vulnerabilidad, referencia el endpoint/parámetro/payload EXACTO del input, explica la causa raíz y describe el impacto real. Usa **negritas** para términos clave, \`código inline\` para endpoints/parámetros/valores, y bloques de código para payloads
- "remediation": pasos concretos y accionables en markdown — usa listas, \`código inline\` para comandos o configuraciones específicas, y bloques de código donde aplique

Respond with this exact JSON schema:
{
  "name": "...",
  "category": "...",
  "severity": "...",
  "description": "...",
  "remediation": "..."
}`;

  } else if (type === 'remediation') {
    userPrompt = `Write a specific remediation for the following penetration test finding. Reference the exact context provided.

Finding name: ${c.name || 'Unknown'}
${c.category    ? `Category: ${c.category}` : ''}
${c.target      ? `Affected target: ${c.target}` : ''}
${c.description ? `Description: ${c.description}` : ''}
${payloadBlock}

Instrucciones:
- Todo el contenido debe estar redactado en español
- Proporciona pasos de remediación concretos y accionables específicos a este hallazgo
- Referencia la tecnología, endpoint o parámetro específico cuando sea relevante
- Usa markdown: listas, \`código inline\` para comandos o configuraciones, bloques de código donde aplique
- No escribas consejos de seguridad genéricos

Respond with this exact JSON schema:
{
  "remediation": "..."
}`;

  } else if (type === 'cwe') {
    userPrompt = `Identify the most appropriate CWE identifier for the following penetration test finding.

Finding name: ${c.name || 'Unknown'}
${c.category    ? `Category: ${c.category}` : ''}
${c.description ? `Description: ${c.description}` : ''}
${c.notes       ? `Tester notes: ${c.notes}` : ''}
${payloadBlock}

Instrucciones:
- Elige el CWE más específico y preciso para este hallazgo (no uses CWEs genéricos si hay uno más específico)
- "cwe": el identificador exacto, formato "CWE-XXX" (ej. "CWE-89", "CWE-79", "CWE-287")
- "cwe_name": nombre oficial del CWE en inglés (ej. "SQL Injection", "Cross-site Scripting")

Respond with this exact JSON schema:
{
  "cwe": "CWE-XXX",
  "cwe_name": "..."
}`;

  } else if (type === 'severity-suggest') {
    userPrompt = `Classify the severity of the following penetration test finding based solely on its name and category.

Finding name: ${c.name || 'Unknown'}
${c.category ? `Category: ${c.category}` : ''}

Instrucciones:
- Elige UNA de estas opciones exactas: critical, high, medium, low, info
- Basa la decisión en el riesgo real típico de este tipo de vulnerabilidad
- "info" solo para hallazgos informativos sin impacto directo en seguridad
- "critical" para RCE, SQLi sin restricciones, auth bypass total, etc.

Respond with this exact JSON schema:
{
  "severity": "high",
  "reason": "one short sentence explaining why"
}`;

  } else if (type === 'exec-summary') {
    const sevLines = Object.entries(c.bySeverity || {})
      .filter(([,n]) => n > 0)
      .map(([sev, n]) => `  ${sev}: ${n}`)
      .join('\n');

    const highlights = (c.highlights || []).slice(0, 8)
      .map(v => `  - [${v.severity}] ${v.name}${v.target_host ? ' @ ' + v.target_host : ''}`)
      .join('\n');

    userPrompt = `Write a professional executive summary for a penetration test report. Use ONLY the data provided below.

Project: ${c.projectName || 'Undisclosed'}
${c.scope ? `Scope / description: ${c.scope}` : ''}
${c.testedAt ? `Test period: ${c.testedAt}` : ''}
Targets in scope: ${(c.targets || []).join(', ') || 'not specified'}

Total findings: ${c.totalVulns || 0}
${sevLines ? 'By severity:\n' + sevLines : ''}
${highlights ? 'Key findings:\n' + highlights : ''}
${c.wstg ? `WSTG coverage: ${c.wstg.pct}% (${c.wstg.done} passed, ${c.wstg.fail} vuln found, ${c.wstg.pending} pending)` : ''}

Instrucciones:
- Todo el contenido en español, tercera persona impersonal
- 2-3 párrafos en markdown
- Párrafo 1: contexto del engagement (tipo de prueba, alcance, período si está disponible)
- Párrafo 2: resumen cuantitativo de hallazgos — menciona los más críticos por nombre si los hay
- Párrafo 3: conclusión sobre la postura de seguridad general y recomendación de prioridad
- No uses frases genéricas como "se realizó una evaluación exhaustiva" — sé específico con los datos
- Usa **negritas** para hallazgos críticos o altos, y para métricas clave

Respond with this exact JSON schema:
{
  "description": "..."
}`;

  } else if (type === 'business-impact') {
    userPrompt = `Write a short business-impact statement for a penetration test finding, aimed at a non-technical executive audience. Use ONLY the data provided below.

Finding name: ${c.name || 'Unknown'}
Severity: ${c.severity || 'unknown'}
${c.category ? `Category: ${c.category}` : ''}
${c.target ? `Affected target: ${c.target}` : ''}
${c.description ? `Technical description: ${c.description}` : ''}

Instrucciones:
- Todo el contenido en español, tercera persona impersonal
- 1-2 frases, texto plano (sin markdown, sin listas, sin negritas)
- Explica la CONSECUENCIA de negocio (ej. fuga de datos de clientes, fraude financiero, interrupción del servicio, daño reputacional, incumplimiento normativo) — no expliques el mecanismo técnico
- No repitas el nombre del hallazgo ni uses jerga técnica (no menciones inyección, payloads, endpoints, código, etc.)
- Sé específico al contexto, no genérico

Respond with this exact JSON schema:
{
  "businessImpact": "..."
}`;

  } else {
    return res.status(400).json({ error: 'Unknown type' });
  }


  try {
    const response = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user',   content: userPrompt },
        ],
        temperature: 0.4,
        max_tokens: 1024,
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('Groq error:', err);
      return res.status(502).json({ error: 'AI service error' });
    }

    const data = await response.json();
    const raw  = data.choices?.[0]?.message?.content || '';

    // Escape literal control characters inside JSON string values
    // (models often emit bare newlines in multi-line text fields)
    function sanitizeJson(str) {
      let inString = false, escaped = false, out = '';
      for (let i = 0; i < str.length; i++) {
        const ch = str[i];
        if (escaped)               { out += ch; escaped = false; continue; }
        if (ch === '\\' && inString) { out += ch; escaped = true;  continue; }
        if (ch === '"')              { inString = !inString; out += ch; continue; }
        if (inString) {
          if      (ch === '\n') { out += '\\n'; continue; }
          else if (ch === '\r') { out += '\\r'; continue; }
          else if (ch === '\t') { out += '\\t'; continue; }
          else if (ch.charCodeAt(0) < 32) { continue; } // drop other ctrl chars
        }
        out += ch;
      }
      return out;
    }

    let parsed;
    try {
      parsed = JSON.parse(sanitizeJson(raw));
    } catch {
      const match = raw.match(/\{[\s\S]*\}/);
      if (match) {
        try { parsed = JSON.parse(sanitizeJson(match[0])); }
        catch { parsed = null; }
      }
      if (!parsed) {
        console.error('Could not parse AI response:', raw);
        return res.status(502).json({ error: 'Could not parse AI response' });
      }
    }

    res.json(parsed);
  } catch (err) {
    console.error('AI generate error:', err);
    res.status(500).json({ error: 'Internal error: ' + err.message });
  }
});

// POST /api/ai/chat
// Body: { question, history: [{role,content}], context: { project, vulns, wstg, targets, team, tickets, methodologies } }
router.post('/chat', requireAuth, requireUser, async (req, res) => {
  const { question, history = [], context = {} } = req.body;
  if (!question?.trim()) return res.status(400).json({ error: 'question required' });

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY not configured' });

  const ctx = context;
  const p   = ctx.project || {};

  let contextBlock = '';
  try {
    const activityLines = (ctx.activity || []).map(e => {
      const d  = new Date(e && e.when);
      const ts = isNaN(d.getTime()) ? '?' : d.toISOString().slice(0, 16).replace('T', ' ');
      return '  [' + ts + '] ' + (e.who || '?') + ' — ' + (e.action || '?') + (e.entity ? ' "' + e.entity + '"' : '');
    });

    const lines = [
      'Proyecto: ' + (p.name || '—') + ' | Target: ' + (p.target || '—') + ' | Estado: ' + (p.status || '—'),
      p.description ? 'Scope: ' + p.description : '',
      '',
      'Hallazgos (' + (ctx.vulns?.length || 0) + ' total):',
      (ctx.vulns || []).slice(0, 30).map(v => '  - [' + v.severity + '] ' + v.name + ' — ' + (v.status || 'pending') + (v.target_host ? ' @ ' + v.target_host : '')).join('\n') || '  Ninguno',
      (ctx.vulns?.length || 0) > 30 ? '  ... y ' + (ctx.vulns.length - 30) + ' más' : '',
      '',
      'WSTG: ' + (ctx.wstg?.done || 0) + ' passed · ' + (ctx.wstg?.fail || 0) + ' vuln found · ' + (ctx.wstg?.pending || 0) + ' pendientes · ' + (ctx.wstg?.pct || 0) + '% completado',
      '',
      'Targets in-scope: ' + ((ctx.targets || []).filter(t => t.scope === 'in').slice(0, 20).map(t => t.host + '(' + (t.type || '?') + ')').join(', ') || 'ninguno'),
      ctx.tickets?.length ? 'Tickets: ' + ctx.tickets.filter(t => t.status === 'open').length + ' abiertos, ' + ctx.tickets.filter(t => t.status === 'in_review').length + ' en revisión, ' + ctx.tickets.filter(t => t.status === 'closed').length + ' cerrados' : '',
      ctx.team?.length ? 'Equipo: ' + ctx.team.map(m => m.username + ' (' + m.role + ')').join(', ') : '',
      ctx.methodologies?.length ? 'Metodologías: ' + ctx.methodologies.map(m => m.name + ' ' + m.pct + '%').join(', ') : '',
      activityLines.length ? '\nActividad reciente (' + activityLines.length + ' entradas):\n' + activityLines.join('\n') : '',
    ];
    contextBlock = lines.filter(l => l !== '').join('\n');
  } catch (e) {
    console.error('[AI chat] contextBlock build error:', e.message);
    contextBlock = 'Proyecto: ' + (p.name || '—') + ' | Estado: ' + (p.status || '—');
  }

  const systemPrompt = [
    'Eres un asistente de pentesting integrado en Flowdit. Tu audiencia son pentesters experimentados.',
    'Responde en español, tercera persona impersonal (ej. "se observa", "se detecta", "se recomienda").',
    'Tono: directo, ácido, sin rodeos. Sin frases de relleno ni obviedades.',
    'Sé breve por defecto. Expándete solo cuando el tema lo justifique.',
    'Formatea SIEMPRE con markdown: **negritas**, `código inline`, listas con -, bloques de código para payloads.',
    'Si el contexto no es suficiente, dilo directamente y sugiere qué dato falta.',
    'No repitas información del contexto a menos que sea relevante.',
    '',
    'Estado actual del proyecto:',
    contextBlock,
  ].join('\n');

  console.log('[AI chat] project:', p.name, '| systemPrompt length:', systemPrompt.length);

  const messages = [
    { role: 'system', content: systemPrompt },
    ...history.slice(-6).filter(m => m && m.role && m.content),
    { role: 'user', content: question },
  ];

  try {
    const response = await fetch(GROQ_API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        messages,
        temperature: 0.5,
        max_tokens: 1024,
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      console.error('Groq chat error:', err);
      return res.status(502).json({ error: 'AI service error' });
    }

    const data   = await response.json();
    const answer = data.choices?.[0]?.message?.content || '';
    res.json({ answer });
  } catch (err) {
    console.error('AI chat error:', err);
    res.status(500).json({ error: 'Internal error: ' + err.message });
  }
});

module.exports = router;
