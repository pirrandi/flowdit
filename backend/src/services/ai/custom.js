// Wrapper "custom" sobre la lógica OpenAI-compatible genérica de
// openaiCompatible.js — pensado para runtimes locales (Ollama, LM Studio,
// vLLM) o cualquier otro servidor que hable el mismo protocolo de
// chat-completions. Configurado enteramente por env vars (CUSTOM_API_URL/
// CUSTOM_API_KEY/CUSTOM_MODEL), a nivel de quien hostea Flowdit — igual que
// GROQ_API_KEY/DEEPSEEK_API_KEY, NO por proyecto vía la UI. A propósito: un
// base_url elegible desde el frontend por cualquier editor de un proyecto
// sería un vector de SSRF (el backend haría fetch() a lo que sea que el
// usuario escriba); un único slot "custom" fijado por el operador evita eso
// mientras sigue cubriendo el caso real ("quiero apuntar Flowdit a mi Ollama
// local") — ver AI_PENTEST_AGENT.md § Multi-proveedor.
//
// La mayoría de servidores locales no exigen API key — CUSTOM_API_KEY cae a
// 'not-needed' si no está seteada, para no chocar con el chequeo de
// chatCompletionAt/chatWithToolsAt (que sí la exige para los proveedores
// hosteados).

const { chatCompletionAt, chatWithToolsAt, listModelsAt } = require('./openaiCompatible');

const CUSTOM_API_URL = process.env.CUSTOM_API_URL || '';
const CUSTOM_API_KEY = process.env.CUSTOM_API_KEY || 'not-needed';
const DEFAULT_MODEL  = process.env.CUSTOM_MODEL || '';

function assertConfigured() {
  if (!CUSTOM_API_URL) throw new Error('Custom AI provider not configured (set CUSTOM_API_URL)');
}

function generateJSON({ systemPrompt, userPrompt, temperature, maxTokens, model }) {
  assertConfigured();
  return chatCompletionAt({ apiUrl: CUSTOM_API_URL, apiKey: CUSTOM_API_KEY, systemPrompt, messages: [{ role: 'user', content: userPrompt }], temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chat({ systemPrompt, messages, temperature, maxTokens, model }) {
  assertConfigured();
  return chatCompletionAt({ apiUrl: CUSTOM_API_URL, apiKey: CUSTOM_API_KEY, systemPrompt, messages, temperature, maxTokens, model: model || DEFAULT_MODEL });
}

function chatWithTools({ systemPrompt, messages, tools, maxTokens, model, temperature, signal, toolMode }) {
  assertConfigured();
  return chatWithToolsAt({ apiUrl: CUSTOM_API_URL, apiKey: CUSTOM_API_KEY, systemPrompt, messages, tools, maxTokens, model: model || DEFAULT_MODEL, temperature, signal, toolMode });
}

function listModels() {
  assertConfigured();
  // Muchos runtimes locales (Ollama, LM Studio) no implementan /models, o
  // lo implementan distinto — listModelsAt tira un error claro en ambos
  // casos (URL no derivable, o el fetch/response falla), que la ruta
  // convierte en la respuesta de error que el fallback del frontend espera.
  return listModelsAt({ apiUrl: CUSTOM_API_URL, apiKey: CUSTOM_API_KEY });
}

module.exports = { generateJSON, chat, chatWithTools, listModels };
