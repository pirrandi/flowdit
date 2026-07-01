const GROQ_API_URL   = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL  = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

async function chatCompletion({ systemPrompt, messages, temperature = 0.4, maxTokens = 1024, model }) {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) throw new Error('GROQ_API_KEY not configured');

  const response = await fetch(GROQ_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: model || DEFAULT_MODEL,
      messages: [{ role: 'system', content: systemPrompt }, ...messages],
      temperature,
      max_tokens: maxTokens,
    }),
  });

  if (!response.ok) {
    const err = await response.text();
    console.error('Groq error:', err);
    throw new Error('AI service error');
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || '';
}

function generateJSON({ systemPrompt, userPrompt, temperature, maxTokens, model }) {
  return chatCompletion({ systemPrompt, messages: [{ role: 'user', content: userPrompt }], temperature, maxTokens, model });
}

function chat({ systemPrompt, messages, temperature, maxTokens, model }) {
  return chatCompletion({ systemPrompt, messages, temperature, maxTokens, model });
}

module.exports = { generateJSON, chat };
