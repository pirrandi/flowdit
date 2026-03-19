const express = require('express');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODEL   = 'llama-3.3-70b-versatile';

const SYSTEM_PROMPT = `You are a professional penetration tester writing technical security reports.
Write concise, accurate, and professional content.
Respond ONLY with valid JSON matching the requested schema — no markdown fences, no extra text.`;

router.post('/generate', requireAuth, async (req, res) => {
  const { type, context = {} } = req.body;
  if (!type) return res.status(400).json({ error: 'type required' });

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY not configured' });

  let userPrompt;

  if (type === 'vuln-draft') {
    const hint = [context.name, context.category, context.notes].filter(Boolean).join(' | ');
    userPrompt = `Generate a vulnerability report entry for: "${hint}"

Respond with this exact JSON schema:
{
  "name": "short descriptive title (max 80 chars)",
  "category": "OWASP category or technology (max 40 chars)",
  "severity": "critical|high|medium|low|info",
  "description": "2-4 paragraph technical description explaining the vulnerability, root cause, and impact (markdown ok)",
  "remediation": "actionable remediation steps (markdown list ok)"
}`;

  } else if (type === 'remediation') {
    userPrompt = `Generate a remediation for the following vulnerability:
Name: ${context.name || 'Unknown'}
Category: ${context.category || 'Unknown'}
Description: ${context.description || '(no description provided)'}

Respond with this exact JSON schema:
{
  "remediation": "actionable remediation steps (markdown list ok)"
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
