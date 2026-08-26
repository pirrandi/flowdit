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
  // Kimi K3 (Moonshot AI) — confirmado contra platform.kimi.ai, 2026-08-14:
  // $3.00/M input (cache-miss), $0.30/M (cache-hit), $15.00/M output. Sin
  // forma de saber acá si un request puntual pegó en caché, así que se usa
  // la tarifa de cache-miss (más cara) para `input` — sobreestima antes que
  // subestimar, mismo criterio que "no adivinar un costo" de más abajo.
  kimi: {
    'kimi-k3': { input: 3, output: 15 },
  },
  // deepseek: sin entrada a propósito — no se confirmaron precios actuales
  // al agregar el proveedor. `estimateCost` ya devuelve null (costo
  // desconocido) para lo que no está en esta tabla, que es preferible a
  // adivinar un número y mostrar un costo estimado incorrecto en /ai/usage.
  // Agregar acá cuando se verifique contra api-docs.deepseek.com/quick_start/pricing.
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
