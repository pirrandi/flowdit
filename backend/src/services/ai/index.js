const groq      = require('./groq');
const anthropic = require('./anthropic');
const deepseek  = require('./deepseek');
const kimi      = require('./kimi');
const custom    = require('./custom');
const { resolveProjectApiKey } = require('../../utils/aiKeys');

const PROVIDERS = { groq, anthropic, deepseek, kimi, custom };
const DEFAULT_PROVIDER = 'groq';

function resolve(provider) {
  return PROVIDERS[provider] || PROVIDERS[DEFAULT_PROVIDER];
}

// Chokepoint único para la resolución de key por-proyecto: un caller pasa
// `project` (la fila de projects/el `effective` de agentLoop.js) en vez de
// resolver la key él mismo — así un call site nuevo que se olvide de esto
// no cae en silencio a la key global del host sin que nadie se entere. Un
// `apiKey` explícito (ver routes/ai.js /models, que la necesita cruda para
// la cache key) sigue pisando a `project`.
function resolveApiKey(provider, opts) {
  if (opts.apiKey) return opts.apiKey;
  if (opts.project) return resolveProjectApiKey(opts.project, provider);
  return undefined;
}

function generateJSON(provider, opts) {
  return resolve(provider).generateJSON({ ...opts, apiKey: resolveApiKey(provider, opts) });
}

function chat(provider, opts) {
  return resolve(provider).chat({ ...opts, apiKey: resolveApiKey(provider, opts) });
}

function chatWithTools(provider, opts) {
  return resolve(provider).chatWithTools({ ...opts, apiKey: resolveApiKey(provider, opts) });
}

function listModels(provider, opts) {
  return resolve(provider).listModels({ ...opts, apiKey: resolveApiKey(provider, opts) });
}

module.exports = { generateJSON, chat, chatWithTools, listModels, PROVIDERS: Object.keys(PROVIDERS) };
