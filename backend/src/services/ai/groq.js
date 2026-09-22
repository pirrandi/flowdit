// Wrapper de Groq sobre la lógica OpenAI-compatible genérica de
// openaiCompatible.js — Groq no tiene nada propio, solo fija su URL/key/
// modelo default. Ver ese archivo para la lógica real.

const { chatCompletionAt, chatWithToolsAt, listModelsAt } = require('./openaiCompatible');

const GROQ_API_URL  = 'https://api.groq.com/openai/v1/chat/completions';
// llama-3.3-70b-versatile was retired by Groq; gpt-oss-120b is the closest
// current replacement (large, supports tool use + JSON mode).
const DEFAULT_MODEL = process.env.GROQ_MODEL || 'openai/gpt-oss-120b';

function generateJSON({ systemPrompt, userPrompt, temperature, maxTokens, model, apiKey }) {
  return chatCompletionAt({ apiUrl: GROQ_API_URL, apiKey: apiKey || process.env.GROQ_API_KEY, systemPrompt, messages: [{ role: 'user', content: userPrompt }], temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chat({ systemPrompt, messages, temperature, maxTokens, model, apiKey }) {
  return chatCompletionAt({ apiUrl: GROQ_API_URL, apiKey: apiKey || process.env.GROQ_API_KEY, systemPrompt, messages, temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chatWithTools({ systemPrompt, messages, tools, maxTokens, model, temperature, signal, apiKey }) {
  return chatWithToolsAt({ apiUrl: GROQ_API_URL, apiKey: apiKey || process.env.GROQ_API_KEY, systemPrompt, messages, tools, maxTokens, model: model || DEFAULT_MODEL, temperature, signal });
}

// Groq's /models also lists non-chat models (Whisper transcription, TTS,
// moderation/guard) that would break this app if picked as a chat model —
// excluidos acá, no en listModelsAt (es ruido específico de Groq, no una
// preocupación general de la API OpenAI-compatible).
const NON_CHAT_MODEL = /whisper|tts|guard/i;

async function listModels({ apiKey } = {}) {
  const models = await listModelsAt({ apiUrl: GROQ_API_URL, apiKey: apiKey || process.env.GROQ_API_KEY });
  return models.filter(m => !NON_CHAT_MODEL.test(m.id));
}

module.exports = { generateJSON, chat, chatWithTools, listModels };
