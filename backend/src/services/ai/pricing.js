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
  // llama-3.3-70b-versatile / llama-3.1-8b-instant were retired by Groq.
  // gpt-oss prices confirmed against console.groq.com/docs/model/openai/... 2026-09-15.
  groq: {
    'openai/gpt-oss-120b': { input: 0.15,  output: 0.60 },
    'openai/gpt-oss-20b':  { input: 0.075, output: 0.30 },
  },
  // Kimi K3 (Moonshot AI) — confirmado contra platform.kimi.ai, 2026-08-14:
  // $3.00/M input (cache-miss), $0.30/M (cache-hit), $15.00/M output. Sin
  // forma de saber acá si un request puntual pegó en caché, así que se usa
  // la tarifa de cache-miss (más cara) para `input` — sobreestima antes que
  // subestimar, mismo criterio que "no adivinar un costo" de más abajo.
  kimi: {
    'kimi-k3': { input: 3, output: 15 },
  },
  // DeepSeek tiene tarifa peak/off-peak (off-peak es la mitad, madrugada UTC
  // China) — confirmado contra api-docs.deepseek.com/quick_start/pricing,
  // 2026-09-21. Sin forma de saber acá en qué franja cae un request puntual,
  // así que se usa la tarifa peak (más cara) para ambos, mismo criterio de
  // sobreestimar-antes-que-subestimar que Kimi arriba.
  deepseek: {
    'deepseek-flash':  { input: 0.30, output: 1.20 },
    'deepseek-v4-pro': { input: 1.32, output: 3.96 },
  },
  // custom: sin entrada a propósito, y para siempre — es un modelo local
  // autohosteado, no tiene un precio por token que estimar.
};

// Returns null (unknown cost) instead of guessing when the model isn't in the table above —
// e.g. a custom GROQ_MODEL/ANTHROPIC_MODEL override that isn't one of the presets.
function estimateCost(provider, model, inputTokens, outputTokens) {
  const rate = PRICING[provider]?.[model];
  if (!rate) return null;
  return (inputTokens / 1e6) * rate.input + (outputTokens / 1e6) * rate.output;
}

module.exports = { estimateCost };
