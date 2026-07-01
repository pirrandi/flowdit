const groq      = require('./groq');
const anthropic = require('./anthropic');

const PROVIDERS = { groq, anthropic };
const DEFAULT_PROVIDER = 'groq';

function resolve(provider) {
  return PROVIDERS[provider] || PROVIDERS[DEFAULT_PROVIDER];
}

function generateJSON(provider, opts) {
  return resolve(provider).generateJSON(opts);
}

function chat(provider, opts) {
  return resolve(provider).chat(opts);
}

module.exports = { generateJSON, chat, PROVIDERS: Object.keys(PROVIDERS) };
