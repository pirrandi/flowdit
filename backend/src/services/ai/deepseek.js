// Wrapper de DeepSeek sobre la lógica OpenAI-compatible genérica de
// openaiCompatible.js — DeepSeek documenta su API como compatible con el
// formato de chat-completions de OpenAI (mismo shape de `tools`/
// `tool_calls`), así que no hace falta lógica de traducción propia. No
// verificado todavía contra una llamada real (ver AI_PENTEST_AGENT.md) —
// si algo en la forma exacta de la respuesta difiere, es acá donde se
// ajustaría, sin tocar agentLoop.js ni openaiCompatible.js.

const { chatCompletionAt, chatWithToolsAt } = require('./openaiCompatible');

const DEEPSEEK_API_URL = 'https://api.deepseek.com/chat/completions';
const DEFAULT_MODEL    = process.env.DEEPSEEK_MODEL || 'deepseek-chat';

function generateJSON({ systemPrompt, userPrompt, temperature, maxTokens, model }) {
  return chatCompletionAt({ apiUrl: DEEPSEEK_API_URL, apiKey: process.env.DEEPSEEK_API_KEY, systemPrompt, messages: [{ role: 'user', content: userPrompt }], temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chat({ systemPrompt, messages, temperature, maxTokens, model }) {
  return chatCompletionAt({ apiUrl: DEEPSEEK_API_URL, apiKey: process.env.DEEPSEEK_API_KEY, systemPrompt, messages, temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chatWithTools({ systemPrompt, messages, tools, maxTokens, model, temperature, signal }) {
  return chatWithToolsAt({ apiUrl: DEEPSEEK_API_URL, apiKey: process.env.DEEPSEEK_API_KEY, systemPrompt, messages, tools, maxTokens, model: model || DEFAULT_MODEL, temperature, signal });
}

module.exports = { generateJSON, chat, chatWithTools };
