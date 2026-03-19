const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL   = 'llama-3.3-70b-versatile';

const SYSTEM_PROMPT = `You are a senior penetration tester writing professional security assessment reports.
Your output must be technically accurate, specific to the evidence provided, and written in clear English.
Always reference the exact endpoints, parameters, payloads, and targets mentioned in the input — never write generic descriptions.
Respond ONLY with valid JSON matching the requested schema. No markdown fences, no extra text outside the JSON object.`;

router.post('/generate', requireAuth, async (req, res) => {
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

Instructions:
- "name": precise professional title referencing the specific endpoint/parameter if present (max 80 chars)
- "category": most specific applicable OWASP category or technology label
- "severity": choose critical/high/medium/low/info based on the vulnerability type and context
- "description": 2-3 paragraphs — explain what the vulnerability is, reference the EXACT endpoint/parameter/payload from the input, explain root cause, and describe the real-world impact
- "remediation": specific actionable steps to fix THIS vulnerability (not generic advice), use a markdown list

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

Instructions:
- Provide concrete, actionable remediation steps specific to this finding
- Reference the specific technology, endpoint, or parameter when relevant
- Use a markdown list format
- Do not write generic security advice

Respond with this exact JSON schema:
{
  "remediation": "..."
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

module.exports = router;
