// Wrapper de DeepSeek sobre la lógica OpenAI-compatible genérica de
// openaiCompatible.js — DeepSeek documenta su API como compatible con el
// formato de chat-completions de OpenAI (mismo shape de `tools`/
// `tool_calls`), así que no hace falta lógica de traducción propia. No
// verificado todavía contra una llamada real (ver AI_PENTEST_AGENT.md) —
// si algo en la forma exacta de la respuesta difiere, es acá donde se
// ajustaría, sin tocar agentLoop.js ni openaiCompatible.js.

const { chatCompletionAt, chatWithToolsAt, listModelsAt } = require('./openaiCompatible');

const DEEPSEEK_API_URL = 'https://api.deepseek.com/chat/completions';
// deepseek-chat/deepseek-reasoner were discontinued 2026-07-24 — confirmed
// against api-docs.deepseek.com/updates/, 2026-09-21. deepseek-flash
// (V4.1-Flash) is the current default; deepseek-v4-pro is the other live
// model, selectable per-project in settings.js.
const DEFAULT_MODEL    = process.env.DEEPSEEK_MODEL || 'deepseek-flash';

// deepseek-flash/deepseek-v4-pro default to "thinking mode" (reasoning_effort
// defaults to 'high' server-side) — found live: once enabled, DeepSeek
// requires the assistant's reasoning_content to be echoed back on the next
// turn ("must be passed back to the API"), which agentLoop.js's message
// format has no field for. Forcing reasoning_effort:'none' keeps DeepSeek
// on plain non-thinking completions, matching how deepseek-chat behaved
// before it was retired — revisit if reasoning_content passthrough is ever
// implemented across all providers' message history.
const DISABLE_THINKING = { reasoning_effort: 'none' };

function generateJSON({ systemPrompt, userPrompt, temperature, maxTokens, model, apiKey }) {
  return chatCompletionAt({ apiUrl: DEEPSEEK_API_URL, apiKey: apiKey || process.env.DEEPSEEK_API_KEY, systemPrompt, messages: [{ role: 'user', content: userPrompt }], temperature, maxTokens, model: model || DEFAULT_MODEL, extraBody: DISABLE_THINKING });
}

function chat({ systemPrompt, messages, temperature, maxTokens, model, apiKey }) {
  return chatCompletionAt({ apiUrl: DEEPSEEK_API_URL, apiKey: apiKey || process.env.DEEPSEEK_API_KEY, systemPrompt, messages, temperature, maxTokens, model: model || DEFAULT_MODEL, extraBody: DISABLE_THINKING });
}

function chatWithTools({ systemPrompt, messages, tools, maxTokens, model, temperature, signal, apiKey }) {
  return chatWithToolsAt({ apiUrl: DEEPSEEK_API_URL, apiKey: apiKey || process.env.DEEPSEEK_API_KEY, systemPrompt, messages, tools, maxTokens, model: model || DEFAULT_MODEL, temperature, signal, extraBody: DISABLE_THINKING });
}

function listModels({ apiKey } = {}) {
  return listModelsAt({ apiUrl: DEEPSEEK_API_URL, apiKey: apiKey || process.env.DEEPSEEK_API_KEY });
}

module.exports = { generateJSON, chat, chatWithTools, listModels };
