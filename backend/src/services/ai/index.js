const groq      = require('./groq');
const anthropic = require('./anthropic');
const deepseek  = require('./deepseek');
const kimi      = require('./kimi');
const custom    = require('./custom');

const PROVIDERS = { groq, anthropic, deepseek, kimi, custom };
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

function chatWithTools(provider, opts) {
  return resolve(provider).chatWithTools(opts);
}

module.exports = { generateJSON, chat, chatWithTools, PROVIDERS: Object.keys(PROVIDERS) };
