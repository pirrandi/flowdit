// Wrapper de Groq sobre la lógica OpenAI-compatible genérica de
// openaiCompatible.js — Groq no tiene nada propio, solo fija su URL/key/
// modelo default. Ver ese archivo para la lógica real.

const { chatCompletionAt, chatWithToolsAt } = require('./openaiCompatible');

const GROQ_API_URL  = 'https://api.groq.com/openai/v1/chat/completions';
const DEFAULT_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';

function generateJSON({ systemPrompt, userPrompt, temperature, maxTokens, model }) {
  return chatCompletionAt({ apiUrl: GROQ_API_URL, apiKey: process.env.GROQ_API_KEY, systemPrompt, messages: [{ role: 'user', content: userPrompt }], temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chat({ systemPrompt, messages, temperature, maxTokens, model }) {
  return chatCompletionAt({ apiUrl: GROQ_API_URL, apiKey: process.env.GROQ_API_KEY, systemPrompt, messages, temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chatWithTools({ systemPrompt, messages, tools, maxTokens, model, temperature, signal }) {
  return chatWithToolsAt({ apiUrl: GROQ_API_URL, apiKey: process.env.GROQ_API_KEY, systemPrompt, messages, tools, maxTokens, model: model || DEFAULT_MODEL, temperature, signal });
}

module.exports = { generateJSON, chat, chatWithTools };
