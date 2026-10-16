// Lógica compartida por CUALQUIER proveedor que hable el formato de
// chat-completions de OpenAI — Groq, DeepSeek, y la inmensa mayoría de
// runtimes locales (Ollama, LM Studio, vLLM). Extraído de groq.js cuando se
// agregó el segundo proveedor real (DeepSeek) — antes de eso vivía ahí
// mismo y "Groq" y "OpenAI-compatible genérico" eran, en la práctica, la
// misma cosa con nombres confusos.
//
// Cada función toma `apiUrl`/`apiKey` como parámetros — nunca asume un
// proveedor específico. Un wrapper por proveedor (ver groq.js, deepseek.js)
// solo fija esos dos valores + el modelo default.

// Reintenta ante un 429 (rate limit) en vez de tirar directo — encontrado en
// vivo con Kimi K3 en su tier gratuito (RPM: 3, concurrency: 1): un solo
// 429 mataba el thread entero, cuando en la mayoría de los casos alcanza
// con esperar un toque. Usa el header Retry-After si el proveedor lo manda
// (Kimi sí), si no backoff exponencial. El sleep() escucha `signal` para
// poder abortarse igual que un fetch normal — sin esto, pausar la sesión
// justo durante la espera se quedaría colgado hasta que termine el timeout.
//
// Bug real encontrado probando esto mismo con Kimi (RPM:3): con un tope de
// 4 reintentos (~15s acumulados de espera), un thread que ya venía de
// encadenar 8-9 tool calls sin pausa se quedaba sin presupuesto de retry
// mucho antes de que la ventana de rate limit del proveedor volviera a
// tener lugar — 3 requests/60s puede necesitar bastante más de 15s para
// destrabarse. Subido a un tope mucho más generoso porque cada espera
// individual (Retry-After) suele ser corta — varios reintentos cortos
// seguidos es justo lo que hace falta para "esperar a que la ventana
// libere lugar", no una sola espera larga.
const MAX_429_RETRIES = 20;

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new DOMException('Aborted', 'AbortError')); return; }
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      reject(new DOMException('Aborted', 'AbortError'));
    }, { once: true });
  });
}

async function fetchWithRetry(apiUrl, options) {
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(apiUrl, options);
    if (response.status !== 429 || attempt >= MAX_429_RETRIES) return response;
    const retryAfter = Number(response.headers.get('retry-after'));
    const delayMs = retryAfter > 0 ? retryAfter * 1000 : Math.min(2 ** attempt * 1000, 20000);
    console.log(`Rate limited (429) — retry ${attempt + 1}/${MAX_429_RETRIES} in ${delayMs}ms`);
    await sleep(delayMs, options.signal);
  }
}

// `messages` usa el formato canónico de agentLoop.js:
//   { role: 'user'|'assistant', content: string }
//   { role: 'assistant', toolCalls: [{ id, name, input }] }
//   { role: 'tool', toolCallId, name, result }
function toOpenAIMessages(messages) {
  return messages.map(m => {
    if (m.role === 'tool') {
      return { role: 'tool', tool_call_id: m.toolCallId, content: JSON.stringify(m.result) };
    }
    if (m.toolCalls) {
      const msg = {
        role: 'assistant',
        tool_calls: m.toolCalls.map(tc => ({
          id: tc.id, type: 'function',
          function: { name: tc.name, arguments: JSON.stringify(tc.input) },
        })),
      };
      // Solo si el proveedor lo devolvió (modelos "thinking"): DeepSeek
      // rechaza con 400 un historial con tool calls sin su reasoning_content.
      if (typeof m.reasoningContent === 'string') msg.reasoning_content = m.reasoningContent;
      return msg;
    }
    return { role: m.role, content: m.content };
  });
}

// Chat plano (sin tools) — usado por generateJSON/chat de cada proveedor,
// que a su vez alimentan las rutas existentes /ai/generate y /ai/chat
// (no relacionadas al scanner — sugerencias de campos, chat de preguntas).
async function chatCompletionAt({ apiUrl, apiKey, systemPrompt, messages, temperature = 0.4, maxTokens = 1024, model, extraBody }) {
  if (!apiKey) throw new Error('API key not configured');

  const response = await fetchWithRetry(apiUrl, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [{ role: 'system', content: systemPrompt }, ...messages],
      temperature,
      max_tokens: maxTokens,
      ...extraBody,
    }),
  });

  if (!response.ok) {
    const errBody = await response.text();
    console.error('OpenAI-compatible provider error:', errBody);
    // Antes tirábamos un 'AI service error' genérico y descartábamos el
    // cuerpo real (rate limit, API key inválida, modelo inexistente,
    // request malformado...) — quedaba en la consola del backend y en
    // ningún otro lado, ni el pentester ni el propio modelo podían saber
    // qué pasó. Ahora viaja en el mensaje, truncado para no inflar el
    // evento con un error body gigante.
    throw new Error(`AI service error (${response.status}): ${errBody.slice(0, 300)}`);
  }

  const data = await response.json();
  return {
    text: data.choices?.[0]?.message?.content || '',
    model,
    usage: {
      inputTokens:  data.usage?.prompt_tokens     || 0,
      outputTokens: data.usage?.completion_tokens || 0,
    },
  };
}

// ── Modo texto (fallback sin tool-calling nativo) ───────────────────────
// Para modelos locales débiles que no soportan tool-calling estructurado
// de forma confiable aunque el servidor lo exponga (ver ROADMAP.md). En vez
// de `tools`/`tool_calls` nativos, describimos las tools en el system
// prompt y le pedimos al modelo que responda con una línea
// `ACTION: tool_name({...})`, parseada a mano. `toolMode: 'text'` es
// opt-in por proyecto (columna `ai_tool_mode`, default `'native'`) — el
// camino nativo de arriba queda intacto sea cual sea este modo.
function buildToolInstructions(tools) {
  const list = tools.map(t =>
    `- ${t.name}: ${t.description}\n  parameters (JSON Schema): ${JSON.stringify(t.input_schema)}`
  ).join('\n');
  // En inglés, igual que el resto del system prompt (más confiable con
  // modelos chicos/locales, que son justo los que usan este modo).
  return [
    'You do not have native tool-calling available. To call a tool, your response must be EXACTLY this line and nothing else:',
    'ACTION: tool_name({"key": "value"})',
    'The argument must be valid JSON, on the same line, inside the parentheses. Only one tool call per response — never two ACTION lines in the same response.',
    'If you do not need to call any tool, answer normally in plain text — do not use the ACTION format for that.',
    '',
    'Available tools:',
    list,
  ].join('\n');
}

// El historial en modo texto no usa `tool_calls`/`role:'tool'` nativos —
// se re-serializa como el propio modelo lo escribió (ACTION: ...) y como
// texto plano, para que sus turnos previos sirvan de few-shot de su propio
// formato. Un tool call por turno asistente, igual que arriba.
function toTextModeMessages(messages) {
  return messages.map(m => {
    if (m.toolCalls) {
      const tc = m.toolCalls[0];
      return { role: 'assistant', content: `ACTION: ${tc.name}(${JSON.stringify(tc.input)})` };
    }
    if (m.role === 'tool') {
      return { role: 'user', content: `[result of ${m.name}]: ${JSON.stringify(m.result)}` };
    }
    return { role: m.role, content: m.content };
  });
}

// Extrae { name, input } de una respuesta con `ACTION: name({...})` en
// algún punto del texto. Escaneo de llaves balanceadas para el JSON en vez
// de una regex codiciosa — el argumento puede tener objetos anidados.
function parseTextAction(text) {
  const idx = text.indexOf('ACTION:');
  if (idx === -1) return null;

  const rest = text.slice(idx + 'ACTION:'.length).trimStart();
  const nameMatch = rest.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\(/);
  if (!nameMatch) return null;

  const jsonStart = nameMatch[0].length;
  if (rest[jsonStart] !== '{') return null;

  let depth = 0, jsonEnd = -1;
  for (let i = jsonStart; i < rest.length; i++) {
    if (rest[i] === '{') depth++;
    else if (rest[i] === '}') {
      depth--;
      if (depth === 0) { jsonEnd = i; break; }
    }
  }
  if (jsonEnd === -1) return null;

  try {
    return { name: nameMatch[1], input: JSON.parse(rest.slice(jsonStart, jsonEnd + 1)) };
  } catch {
    return null;
  }
}

// Chat con tools — usado por agentLoop.js. Ver anthropic.js para el
// equivalente nativo de Anthropic (formato distinto, misma forma de salida
// { type: 'text'|'tool_use', ... } para que el loop no sepa la diferencia).
async function chatWithToolsAt({ apiUrl, apiKey, systemPrompt, messages, tools, maxTokens = 4096, model, temperature = 0.4, signal, toolMode = 'native', extraBody }) {
  if (!apiKey) throw new Error('API key not configured');

  const isTextMode = toolMode === 'text';

  const body = {
    model,
    messages: [
      { role: 'system', content: isTextMode ? `${systemPrompt}\n\n${buildToolInstructions(tools)}` : systemPrompt },
      ...(isTextMode ? toTextModeMessages(messages) : toOpenAIMessages(messages)),
    ],
    temperature,
    max_tokens: maxTokens,
    ...extraBody,
  };
  if (!isTextMode) {
    // scanTools.js define { name, description, input_schema } — el
    // formato OpenAI-compatible espera "parameters", no "input_schema",
    // y envuelve todo en { type: 'function', function: {...} }.
    body.tools = tools.map(t => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.input_schema } }));
  }

  // `fetch` nativo entiende AbortSignal directo — si `signal` ya viene
  // abortado (o se aborta mientras la request está en vuelo, incluido
  // durante la espera de un retry en fetchWithRetry), rechaza con un error
  // `name === 'AbortError'`, que agentLoop.js detecta sin que haga falta
  // envolverlo acá.
  const response = await fetchWithRetry(apiUrl, {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    signal,
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errBody = await response.text();
    console.error('OpenAI-compatible provider error:', errBody);
    // Antes tirábamos un 'AI service error' genérico y descartábamos el
    // cuerpo real (rate limit, API key inválida, modelo inexistente,
    // request malformado...) — quedaba en la consola del backend y en
    // ningún otro lado, ni el pentester ni el propio modelo podían saber
    // qué pasó. Ahora viaja en el mensaje, truncado para no inflar el
    // evento con un error body gigante.
    throw new Error(`AI service error (${response.status}): ${errBody.slice(0, 300)}`);
  }

  const data = await response.json();
  const choice = data.choices?.[0];
  const usage = {
    inputTokens:  data.usage?.prompt_tokens     || 0,
    outputTokens: data.usage?.completion_tokens || 0,
  };

  if (isTextMode) {
    const content = choice?.message?.content || '';
    const action = parseTextAction(content);
    if (action) {
      return { type: 'tool_use', toolCalls: [{ id: `text-${Date.now()}`, name: action.name, input: action.input }], usage, model };
    }
    return { type: 'text', text: content, usage, model };
  }

  const toolCalls = choice?.message?.tool_calls;
  if (toolCalls?.length) {
    const result = {
      type: 'tool_use',
      toolCalls: toolCalls.map(tc => {
        // Un JSON roto en los argumentos antes tiraba acá y mataba el thread
        // entero; ahora viaja marcado y agentLoop.js le devuelve al modelo un
        // tool.result de error para que lo corrija.
        try {
          const input = JSON.parse(tc.function?.arguments || '{}');
          if (input && typeof input === 'object' && !Array.isArray(input)) return { id: tc.id, name: tc.function?.name, input };
        } catch { /* cae abajo */ }
        return { id: tc.id, name: tc.function?.name, input: {}, invalidArguments: tc.function?.arguments ?? '' };
      }),
      usage, model,
    };
    if (typeof choice.message.reasoning_content === 'string') result.reasoningContent = choice.message.reasoning_content;
    return result;
  }

  return { type: 'text', text: choice?.message?.content || '', usage, model };
}

// Deriva la URL de /models a partir de la URL de /chat/completions ya
// configurada por cada proveedor (GROQ_API_URL, DEEPSEEK_API_URL, etc.) —
// evita mantener una segunda constante de URL por proveedor solo para
// esto. Tira un error claro (en vez de armar un request mal formado) si la
// URL no termina donde se espera — un CUSTOM_API_URL con otra forma cae acá.
function deriveModelsUrl(apiUrl) {
  const stripped = apiUrl.replace(/\/+$/, '');
  const suffix = '/chat/completions';
  if (!stripped.endsWith(suffix)) {
    throw new Error(`Cannot derive a /models endpoint from ${apiUrl}`);
  }
  return stripped.slice(0, -suffix.length) + '/models';
}

// Lista de modelos disponibles — mismo shape de respuesta OpenAI-compatible
// que /chat/completions ({ data: [{ id, ... }] }), así que un solo GET
// alcanza para Groq/DeepSeek/Kimi/custom (Anthropic tiene su propio
// listModels en anthropic.js, formato y auth distintos).
async function listModelsAt({ apiUrl, apiKey }) {
  if (!apiKey) throw new Error('No API key configured for this provider');

  const response = await fetch(deriveModelsUrl(apiUrl), {
    headers: { 'Authorization': `Bearer ${apiKey}` },
  });

  if (!response.ok) {
    const errBody = await response.text();
    throw new Error(`AI service error (${response.status}): ${errBody.slice(0, 300)}`);
  }

  const data = await response.json();
  return (data.data || [])
    .map(m => ({ id: m.id }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

module.exports = { toOpenAIMessages, chatCompletionAt, chatWithToolsAt, parseTextAction, listModelsAt };
