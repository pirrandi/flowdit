const db = require('../../db');
const { estimateCost } = require('./pricing');

async function logUsage({ projectId, userId, provider, model, action, inputTokens, outputTokens, sessionId = null }) {
  try {
    const cost = estimateCost(provider, model, inputTokens, outputTokens);
    await db.query(
      `INSERT INTO ai_usage (project_id, user_id, provider, model, action, input_tokens, output_tokens, cost_usd, session_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [projectId, userId, provider, model, action, inputTokens, outputTokens, cost, sessionId]
    );
  } catch (err) {
    // Never let usage logging break the actual AI response
    console.error('AI usage log error:', err.message);
  }
}

module.exports = { logUsage };
