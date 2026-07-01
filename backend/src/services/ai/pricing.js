// USD per 1M tokens.
// Anthropic prices confirmed against platform.claude.com/docs/en/pricing (cached 2026-06-24).
// Groq prices are commonly-published figures for these models — Groq changes pricing
// more often than Anthropic, verify at console.groq.com/settings/billing if it matters.
const PRICING = {
  anthropic: {
    'claude-opus-4-8':  { input: 5,    output: 25 },
    'claude-sonnet-5':  { input: 3,    output: 15 },
    'claude-haiku-4-5': { input: 1,    output: 5  },
  },
  groq: {
    'llama-3.3-70b-versatile': { input: 0.59, output: 0.79 },
    'llama-3.1-8b-instant':    { input: 0.05, output: 0.08 },
  },
};

// Returns null (unknown cost) instead of guessing when the model isn't in the table above —
// e.g. a custom GROQ_MODEL/ANTHROPIC_MODEL override that isn't one of the presets.
function estimateCost(provider, model, inputTokens, outputTokens) {
  const rate = PRICING[provider]?.[model];
  if (!rate) return null;
  return (inputTokens / 1e6) * rate.input + (outputTokens / 1e6) * rate.output;
}

module.exports = { estimateCost };
