// Wrapper de Kimi (Moonshot AI) sobre la lógica OpenAI-compatible genérica
// de openaiCompatible.js — igual que deepseek.js. Verificado contra la doc
// oficial (platform.kimi.ai/docs/guide/kimi-k3-quickstart, 2026-08-14): la
// API usa el mismo shape de chat-completions/tools que OpenAI, así que no
// hace falta lógica de traducción propia.

const { chatCompletionAt, chatWithToolsAt, listModelsAt } = require('./openaiCompatible');

const KIMI_API_URL  = 'https://api.moonshot.ai/v1/chat/completions';
const DEFAULT_MODEL = process.env.KIMI_MODEL || 'kimi-k3';

// Kimi K3 rechaza cualquier temperature distinta de 1 — 400 "invalid
// temperature: only 1 is allowed for this model" (encontrado en vivo). Se
// fuerza acá, ignorando lo que venga del caller — openaiCompatible.js
// default a 0.4 para todos los proveedores por igual, y ese default es
// justo lo que rompe con este modelo en particular.
const FORCED_TEMPERATURE = 1;

function generateJSON({ systemPrompt, userPrompt, maxTokens, model, apiKey }) {
  return chatCompletionAt({ apiUrl: KIMI_API_URL, apiKey: apiKey || process.env.KIMI_API_KEY, systemPrompt, messages: [{ role: 'user', content: userPrompt }], temperature: FORCED_TEMPERATURE, maxTokens, model: model || DEFAULT_MODEL });
}

function chat({ systemPrompt, messages, maxTokens, model, apiKey }) {
  return chatCompletionAt({ apiUrl: KIMI_API_URL, apiKey: apiKey || process.env.KIMI_API_KEY, systemPrompt, messages, temperature: FORCED_TEMPERATURE, maxTokens, model: model || DEFAULT_MODEL });
}

function chatWithTools({ systemPrompt, messages, tools, maxTokens, model, signal, apiKey }) {
  return chatWithToolsAt({ apiUrl: KIMI_API_URL, apiKey: apiKey || process.env.KIMI_API_KEY, systemPrompt, messages, tools, maxTokens, model: model || DEFAULT_MODEL, temperature: FORCED_TEMPERATURE, signal });
}

function listModels({ apiKey } = {}) {
  return listModelsAt({ apiUrl: KIMI_API_URL, apiKey: apiKey || process.env.KIMI_API_KEY });
}

module.exports = { generateJSON, chat, chatWithTools, listModels };
