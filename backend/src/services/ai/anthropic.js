const Anthropic = require('@anthropic-ai/sdk');

const DEFAULT_MODEL = process.env.ANTHROPIC_MODEL || 'claude-opus-4-8';

let client = null;
// A per-project apiKey bypasses the singleton (built fresh each call —
// project keys are the exception, not the hot path, so no cache needed).
// Without an override, the module-level singleton is reused as before.
function getClient(apiKey) {
  if (apiKey) return new Anthropic({ apiKey });
  if (!client) {
    const envKey = process.env.ANTHROPIC_API_KEY;
    if (!envKey) throw new Error('ANTHROPIC_API_KEY not configured');
    client = new Anthropic({ apiKey: envKey });
  }
  return client;
}

async function chatCompletion({ systemPrompt, messages, maxTokens = 1024, model, apiKey }) {
  const anthropic = getClient(apiKey); // throws 'ANTHROPIC_API_KEY not configured' before any API call

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

function generateJSON({ systemPrompt, userPrompt, maxTokens, model, apiKey }) {
  return chatCompletion({ systemPrompt, messages: [{ role: 'user', content: userPrompt }], maxTokens, model, apiKey });
}

function chat({ systemPrompt, messages, maxTokens, model, apiKey }) {
  return chatCompletion({ systemPrompt, messages, maxTokens, model, apiKey });
}

// ── Tool use (agente de scanner de IA — ver AI_PENTEST_AGENT.md) ─────────
//
// `messages` usa el formato canónico de agentLoop.js, no el de la Messages
// API — se traduce acá, en el borde, para que el loop no conozca nada
// específico de Anthropic. Formato canónico:
//   { role: 'user'|'assistant', content: string }
//   { role: 'assistant', toolCalls: [{ id, name, input }] }
//   { role: 'tool', toolCallId, name, result }
function toAnthropicMessages(messages) {
  return messages.map(m => {
    if (m.role === 'tool') {
      return {
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: m.toolCallId, content: JSON.stringify(m.result) }],
      };
    }
    if (m.toolCalls) {
      return {
        role: 'assistant',
        content: m.toolCalls.map(tc => ({ type: 'tool_use', id: tc.id, name: tc.name, input: tc.input })),
      };
    }
    return { role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content };
  });
}

async function chatWithTools({ systemPrompt, messages, tools, maxTokens = 4096, model, signal, apiKey }) {
  const anthropic = getClient(apiKey); // throws 'ANTHROPIC_API_KEY not configured' before any API call

  let response;
  try {
    response = await anthropic.messages.create(
      {
        model: model || DEFAULT_MODEL,
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: toAnthropicMessages(messages),
        // scanTools.js ya define { name, description, input_schema } —
        // coincide 1:1 con lo que espera la Messages API, sin transformar.
        tools: tools.map(t => ({ name: t.name, description: t.description, input_schema: t.input_schema })),
      },
      { signal } // segundo argumento = RequestOptions del SDK — acá viaja el AbortSignal
    );
  } catch (err) {
    // No envolver una cancelación intencional (agentLoop.js la detecta por
    // el nombre del error — envolverla en un Error genérico la haría
    // indistinguible de un fallo real del proveedor). No verificado contra
    // una llamada real qué nombre exacto usa el SDK al abortar.
    if (err.name === 'AbortError' || err.name === 'APIUserAbortError') throw err;
    console.error('Anthropic error:', err.message);
    throw new Error('AI service error', { cause: err });
  }

  if (response.stop_reason === 'refusal') throw new Error('AI declined to respond');

  const usage = {
    inputTokens:  response.usage?.input_tokens  || 0,
    outputTokens: response.usage?.output_tokens || 0,
  };

  const toolUseBlocks = response.content.filter(b => b.type === 'tool_use');
  if (toolUseBlocks.length) {
    return { type: 'tool_use', toolCalls: toolUseBlocks.map(b => ({ id: b.id, name: b.name, input: b.input })), usage, model: model || DEFAULT_MODEL };
  }

  const textBlock = response.content.find(b => b.type === 'text');
  return { type: 'text', text: textBlock?.text || '', usage, model: model || DEFAULT_MODEL };
}

// Lista todos los modelos disponibles, paginando con la iteración
// automática del SDK (Page implementa el protocolo async-iterable) — no
// asumir que entran en una sola página.
async function listModels({ apiKey } = {}) {
  const anthropic = getClient(apiKey); // throws 'ANTHROPIC_API_KEY not configured' before any API call
  const models = [];
  for await (const m of anthropic.models.list()) {
    models.push({ id: m.id });
  }
  return models.sort((a, b) => a.id.localeCompare(b.id));
}

module.exports = { generateJSON, chat, chatWithTools, listModels };
