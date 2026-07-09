const Anthropic = require('@anthropic-ai/sdk');

const DEFAULT_MODEL = process.env.ANTHROPIC_MODEL || 'claude-opus-4-8';

let client = null;
function getClient() {
  if (!client) {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) throw new Error('ANTHROPIC_API_KEY not configured');
    client = new Anthropic({ apiKey });
  }
  return client;
}

async function chatCompletion({ systemPrompt, messages, maxTokens = 1024, model }) {
  const anthropic = getClient(); // throws 'ANTHROPIC_API_KEY not configured' before any API call

  let response;
  try {
    response = await anthropic.messages.create({
      model: model || DEFAULT_MODEL,
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: messages.map(m => ({
        role: m.role === 'assistant' ? 'assistant' : 'user',
        content: m.content,
      })),
    });
  } catch (err) {
    console.error('Anthropic error:', err.message);
    throw new Error('AI service error', { cause: err });
  }

  if (response.stop_reason === 'refusal') throw new Error('AI declined to respond');
  const textBlock = response.content.find(b => b.type === 'text');
  return {
    text: textBlock?.text || '',
    model: model || DEFAULT_MODEL,
    usage: {
      inputTokens:  response.usage?.input_tokens  || 0,
      outputTokens: response.usage?.output_tokens || 0,
    },
  };
}

function generateJSON({ systemPrompt, userPrompt, maxTokens, model }) {
  return chatCompletion({ systemPrompt, messages: [{ role: 'user', content: userPrompt }], maxTokens, model });
}

function chat({ systemPrompt, messages, maxTokens, model }) {
  return chatCompletion({ systemPrompt, messages, maxTokens, model });
}

module.exports = { generateJSON, chat };
