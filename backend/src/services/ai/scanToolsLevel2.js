// Nivel 2 — acción activa/potencialmente destructiva. tier: 2 → agentLoop.js
// las frena en `waiting_approval` y SOLO las ejecuta si el pentester
// aprueba explícitamente (ver resolveGatedCall en agentLoop.js) — a
// diferencia de Nivel 0/1, el `execute()` de estas tools nunca corre desde
// `advance()` directamente.
//
// Deliberadamente NO hay exploits "enlatados" por CVE acá — run_exploit_poc
// es genérica: el agente arma la secuencia de requests, esta tool solo la
// ejecuta y reporta. Intentar mantener una biblioteca de exploits reales
// sería una tarea sin fin y un riesgo de seguridad en sí mismo.

const { assertTargetInScope, describeFetchError } = require('./targetScope');

async function sendRequest(target, { method = 'GET', path, scheme = 'https', headers = {}, body = null }) {
  const url = `${scheme}://${target.host}${path.startsWith('/') ? '' : '/'}${path}`;
  let response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: body != null ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    return { url, method, error: `request failed: ${describeFetchError(err)}` };
  }
  const text = await response.text();
  return {
    url, method, status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    body_preview: text.slice(0, 3000),
  };
}

const scanToolsLevel2 = [
  {
    name: 'send_http_request',
    tier: 2,
    description:
      'Send an arbitrary HTTP request (any method, custom headers/body) to a ' +
      'target. This is the most flexible and highest-impact tool available — ' +
      'requires explicit pentester approval before it runs, and the exact ' +
      'request is shown to them verbatim before approval. Use this for anything ' +
      'GET/HEAD via fetch_endpoint cannot do.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] },
        path: { type: 'string', description: 'URL path, e.g. "/api/users/1"' },
        scheme: { type: 'string', enum: ['https', 'http'] },
        headers: { type: 'object', description: 'Optional extra request headers' },
        body: { type: 'string', description: 'Optional request body (raw string, or JSON-stringify it yourself)' },
      },
      required: ['target_id', 'method', 'path'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);
      return sendRequest(target, input);
    },
  },

  {
    name: 'test_payload',
    tier: 2,
    description:
      'Send a single crafted test payload against one parameter (query string, ' +
      'JSON body field, or header) and return the raw response for you to ' +
      'analyze — this tool does NOT decide whether something is vulnerable, ' +
      'it only delivers the payload and reports back exactly what happened. ' +
      'Requires explicit pentester approval, with the exact payload shown to ' +
      'them before it runs.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string' },
        path: { type: 'string' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
        scheme: { type: 'string', enum: ['https', 'http'] },
        param_location: { type: 'string', enum: ['query', 'body_json', 'header'] },
        param_name: { type: 'string', description: 'Name of the query param / JSON field / header to inject into' },
        payload: { type: 'string', description: 'The exact payload string to send' },
        category: { type: 'string', description: 'What you are testing for, e.g. "SQLi", "XSS", "IDOR" — for the pentester\'s context in the approval prompt' },
      },
      required: ['target_id', 'path', 'method', 'param_location', 'param_name', 'payload'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);

      let path = input.path;
      let headers = {};
      let body = null;

      if (input.param_location === 'query') {
        const sep = path.includes('?') ? '&' : '?';
        path = `${path}${sep}${encodeURIComponent(input.param_name)}=${encodeURIComponent(input.payload)}`;
      } else if (input.param_location === 'body_json') {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify({ [input.param_name]: input.payload });
      } else if (input.param_location === 'header') {
        headers[input.param_name] = input.payload;
      }

      const result = await sendRequest(target, { method: input.method, path, scheme: input.scheme, headers, body });
      return { ...result, category: input.category || null, injected: { location: input.param_location, name: input.param_name, payload: input.payload } };
    },
  },

  {
    name: 'run_exploit_poc',
    tier: 2,
    description:
      'Execute a sequence of one or more HTTP requests you construct yourself ' +
      'to attempt a specific exploit or technique (e.g. a known CVE, an auth ' +
      'bypass chain). There is no built-in exploit database — you build the ' +
      'exact request sequence based on your own knowledge; this tool only ' +
      'executes it and reports each response. Requests run in order, but ' +
      'responses are NOT automatically threaded between steps (no variable ' +
      'extraction) — if step 2 needs a token from step 1\'s response, read it ' +
      'from the returned body_preview and pass it explicitly. Highest-risk ' +
      'tool available — requires explicit pentester approval, with the full ' +
      'request sequence shown to them before anything runs.',
    input_schema: {
      type: 'object',
      properties: {
        target_id: { type: 'string' },
        technique: { type: 'string', description: 'What you are attempting, e.g. "CVE-2023-XXXXX" or "JWT algorithm confusion"' },
        request_sequence: {
          type: 'array', minItems: 1, maxItems: 10,
          items: {
            type: 'object',
            properties: {
              method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] },
              path: { type: 'string' },
              scheme: { type: 'string', enum: ['https', 'http'] },
              headers: { type: 'object' },
              body: { type: 'string' },
            },
            required: ['method', 'path'],
          },
        },
      },
      required: ['target_id', 'technique', 'request_sequence'],
    },
    async execute(input, ctx) {
      const target = await assertTargetInScope(input.target_id, ctx.projectId);
      const results = [];
      for (const req of input.request_sequence) {
        results.push(await sendRequest(target, req)); // secuencial, a propósito — ver nota sobre no encadenar variables entre pasos
      }
      return { technique: input.technique, steps: results };
    },
  },
];

module.exports = { scanToolsLevel2 };
