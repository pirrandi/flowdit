// ── views/settings.js ─────────────────────────────────────────────────

async function renderSettings() {
  const container = document.getElementById('view-settings');
  if (!state.currentProject) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">${icon('inbox', { size: 28 })}</div><div class="empty-title">No project selected</div></div>`;
    return;
  }

  const p       = state.currentProject;
  const pid     = p.id;
  const isOwner = p.member_role === 'owner';
  const [aiUsage, orgs] = isOwner ? await Promise.all([
    request('GET', `/projects/${pid}/ai/usage`).catch(() => null),
    api.organizations.list().catch(() => []),
  ]) : [null, []];

  container.innerHTML = `
    <div class="page-header">
      <div>
        <div class="page-title">Settings</div>
        <div class="page-subtitle">// ${esc(p.name)}</div>
      </div>
    </div>

    ${isOwner ? `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start">

      <!-- Left column: General + Timeline -->
      <div style="display:flex;flex-direction:column;gap:12px">

        <div class="members-card">
          <div class="members-card-title">General</div>
          <div style="display:flex;flex-direction:column;gap:10px">
            <div>
              <div class="form-label" style="margin-bottom:4px">Project Name</div>
              <input type="text" class="form-input" id="cfg-name" value="${esc(p.name)}">
            </div>
            <div>
              <div class="form-label" style="margin-bottom:4px">Target / Scope</div>
              <input type="text" class="form-input" id="cfg-target" value="${esc(p.target||'')}" placeholder="https://target.com">
            </div>
            <div>
              <div class="form-label" style="margin-bottom:4px">Description</div>
              <textarea class="form-input note-textarea" id="cfg-desc" rows="3" style="resize:vertical">${esc(p.description||'')}</textarea>
            </div>
            <div>
              <button class="btn btn-prim" onclick="saveGeneral()">Guardar</button>
            </div>
          </div>
        </div>

        <div class="members-card">
          <div class="members-card-title">Timeline</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 14px">
            Fechas clave del engagement. Se usan para calcular los días restantes en el dashboard.
          </p>
          <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:14px">
            ${dateField('tl-start',  'Inicio pentesting', p.date_start)}
            ${dateField('tl-end',    'Fin pentesting',    p.date_end)}
            ${dateField('tl-report', 'Entrega reporte',   p.date_report)}
          </div>
          <button class="btn btn-prim" onclick="saveTimeline()">Guardar fechas</button>
        </div>

        <div class="members-card">
          <div class="members-card-title">AI Provider</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 14px">
            Motor de IA usado para redactar hallazgos, resúmenes y el chat asistente en este proyecto.
          </p>
          <div style="display:flex;flex-direction:column;gap:10px">
            <div>
              <div class="form-label" style="margin-bottom:4px">Proveedor</div>
              <select class="form-input" id="cfg-ai-provider" onchange="setAiProvider(this.value)">
                <option value="groq"      ${(p.ai_provider||'groq')==='groq'      ? 'selected' : ''}>Groq (GPT-OSS 120B)</option>
                <option value="anthropic" ${p.ai_provider==='anthropic'           ? 'selected' : ''}>Anthropic (Claude)</option>
                <option value="deepseek"  ${p.ai_provider==='deepseek'            ? 'selected' : ''}>DeepSeek</option>
                <option value="kimi"      ${p.ai_provider==='kimi'                ? 'selected' : ''}>Kimi K3 (Moonshot AI)</option>
                <option value="custom"    ${p.ai_provider==='custom'              ? 'selected' : ''}>Custom / Local (Ollama, LM Studio...)</option>
              </select>
            </div>
            <div>
              <div class="form-label" style="margin-bottom:4px">Modelo</div>
              <select class="form-input" id="cfg-ai-model" onchange="setAiModel(this.value)">
                ${buildAiModelPlaceholder(p.ai_model)}
              </select>
            </div>
            ${(p.ai_provider || 'groq') !== 'custom' ? `
            <div>
              <div class="form-label" style="margin-bottom:4px">API Key propia (opcional)</div>
              <div style="display:flex;gap:6px;align-items:center">
                <input type="password" class="form-input" id="cfg-ai-apikey"
                  placeholder="Dejar en blanco para usar la del servidor" style="flex:1;font-size:12px">
                <button class="btn btn-ghost" style="flex-shrink:0;font-size:11px;padding:6px 12px" onclick="saveAiApiKey()">Set</button>
              </div>
              <p style="font-family:var(--mono);font-size:10px;color:var(--t3);margin:4px 0 0;line-height:1.5">
                ${p.ai_api_keys_set?.[p.ai_provider || 'groq'] ? 'Key configurada para este proveedor. Ingresá una nueva para reemplazarla, o "Set" en blanco para volver a la del servidor.' : 'Sin key propia — usando la key global del servidor para este proveedor.'}
              </p>
            </div>` : ''}
            ${p.ai_provider === 'custom' ? `
            <div>
              <div class="form-label" style="margin-bottom:4px">Tool-calling</div>
              <select class="form-input" id="cfg-ai-tool-mode" onchange="setAiToolMode(this.value)">
                <option value="native" ${(p.ai_tool_mode||'native')==='native' ? 'selected' : ''}>Nativo (tools/tool_calls estructurados)</option>
                <option value="text"   ${p.ai_tool_mode==='text'               ? 'selected' : ''}>Texto plano (fallback ACTION: tool(args) — para modelos que no soportan tool-calling)</option>
              </select>
            </div>` : ''}
            <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding-top:4px;border-top:1px solid var(--b1)">
              <div>
                <div style="font-size:13px;font-weight:600;margin-bottom:2px">AI Agent — modo sin restricciones</div>
                <div style="font-family:var(--mono);font-size:11px;color:var(--t3)">
                  El AI Agent manda requests activos (send_http_request/test_payload/run_exploit_poc) Y crea hallazgos (propose_finding) sin pedir tu aprobación antes — trabaja de punta a punta sin frenarse a preguntar. El scope autorizado (targets con scope='in') sigue siendo un límite duro, no lo relaja este toggle.
                </div>
              </div>
              <button class="setting-toggle ${p.ai_autonomous_requests?'on':''}"
                onclick="toggleProjectFlag('ai_autonomous_requests',${!p.ai_autonomous_requests})">
                <span class="setting-toggle-knob"></span>
              </button>
            </div>
            <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;padding-top:4px;border-top:1px solid var(--b1)">
              <div>
                <div style="font-size:13px;font-weight:600;margin-bottom:2px">AI Agent — un agente a la vez</div>
                <div style="font-family:var(--mono);font-size:11px;color:var(--t3)">
                  Sin sub-agentes en paralelo — todo corre secuencial, un solo hilo. Más lento, pero evita romper con proveedores de rate limit/concurrencia bajos (ej. tiers gratuitos) y consume menos tokens de punta a punta.
                </div>
              </div>
              <button class="setting-toggle ${p.ai_single_agent?'on':''}"
                onclick="toggleProjectFlag('ai_single_agent',${!p.ai_single_agent})">
                <span class="setting-toggle-knob"></span>
              </button>
            </div>
          </div>
        </div>

        <div class="members-card">
          <div class="members-card-title">GitHub Integration</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 14px">
            Envía un ticket como issue de GitHub con un click. Es de una sola vía — el estado no se sincroniza de vuelta, solo queda el link como referencia.
          </p>
          <div style="display:flex;flex-direction:column;gap:10px">
            <div>
              <div class="form-label" style="margin-bottom:4px">Repositorio</div>
              <input type="text" class="form-input" id="cfg-github-repo" placeholder="owner/repo"
                value="${esc(p.github_repo || '')}" onchange="saveGithubRepo(this.value)">
            </div>
            <div style="display:flex;gap:6px;align-items:center">
              <input type="password" class="form-input" id="cfg-github-pat"
                placeholder="Personal access token" style="flex:1;font-size:12px">
              <button class="btn btn-ghost" style="flex-shrink:0;font-size:11px;padding:6px 12px" onclick="saveGithubPat()">Set</button>
            </div>
            <p style="font-family:var(--mono);font-size:10px;color:var(--t3);margin:0;line-height:1.5">
              ${p.has_github_pat ? 'Token configurado. Ingresá uno nuevo para reemplazarlo.' : 'Sin token todavía — necesita permiso "Issues: Read and write" sobre el repo.'}
            </p>
          </div>
        </div>

        <div class="members-card">
          <div class="members-card-title">AI Usage</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 14px">
            Consumo estimado de IA en este proyecto, calculado localmente a partir de los tokens que reporta cada respuesta. No es el saldo de tu cuenta — para eso, mirá el dashboard del proveedor.
          </p>
          ${buildAiUsageCard(aiUsage)}
        </div>

        ${buildOrgMoveCard(p, orgs)}

        <div class="members-card" style="border-color:rgba(239,68,68,.25)">
          <div class="members-card-title" style="color:var(--c-crit)">Danger Zone</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 12px">
            Borrar el proyecto elimina todos los hallazgos, targets, metodología y datos asociados. Esta acción es irreversible.
          </p>
          <button class="btn-danger" onclick="deleteProject()">Eliminar proyecto</button>
        </div>

      </div>

      <!-- Right column: Client Portal -->
      <div style="display:flex;flex-direction:column;gap:12px">

        <div class="members-card">
          <div class="members-card-title">Client Portal</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 14px">
            Controla qué ve el cliente en su portal de solo lectura.
          </p>
          ${buildClientSettings(p)}
        </div>

      </div>
    </div>` : '<div style="font-family:var(--mono);font-size:11px;color:var(--t3)">Solo el owner puede ver la configuración del proyecto.</div>'}
  `;

  // Fetch-after-render: el select de modelo se pinta con un placeholder de
  // entrada (arriba) y se completa acá con la lista real del proveedor, sin
  // bloquear el resto de la página mientras responde.
  if (isOwner) loadAiModels(pid, p.ai_provider || 'groq', p.ai_model);
}

// ── helpers ───────────────────────────────────────────────────────────

// El listado de modelos ya no es una lista fija a mano (se desactualizaba
// en cuanto el proveedor retiraba un modelo — pasó dos veces en esta misma
// sesión con Groq y DeepSeek) — se pide en vivo a GET /ai/models. Este
// objeto solo cachea esa respuesta por proveedor durante la vida de la
// página, para no repetir el fetch cada vez que se cambia de proveedor y
// se vuelve.
const _modelListCache = {};

function buildAiModelPlaceholder(selected) {
  if (selected) return `<option value="${esc(selected)}" selected>${esc(selected)} (cargando…)</option>`;
  return `<option value="" selected disabled>Cargando modelos…</option>`;
}

function renderAiModelOptions(select, models, selected) {
  const opts = models.map(m =>
    `<option value="${esc(m.id)}" ${selected === m.id ? 'selected' : ''}>${esc(m.id)}</option>`
  ).join('');
  select.innerHTML = `<option value="" ${!selected ? 'selected' : ''}>Predeterminado (.env)</option>${opts}`;
}

// IDs conocidos al 2026-09-22 (espejo de backend/src/services/ai/pricing.js)
// — solo para el fallback de abajo cuando el fetch en vivo a /ai/models
// falla (sin key todavía, key recién revocada, proveedor caído). No se usa
// mientras el fetch funcione; existe únicamente para que un proyecto sin
// key configurada todavía no se quede sin ningún modelo para elegir.
const AI_MODELS_FALLBACK = {
  groq:      ['openai/gpt-oss-120b', 'openai/gpt-oss-20b'],
  anthropic: ['claude-opus-4-8', 'claude-sonnet-5', 'claude-haiku-4-5'],
  deepseek:  ['deepseek-flash', 'deepseek-v4-pro'],
  kimi:      ['kimi-k3'],
};

// Si el listado en vivo falla, el proyecto no debe quedar sin poder elegir
// modelo. Para los proveedores hosteados conocidos, se cae a la lista
// estática de arriba (sigue siendo un <select>). 'custom' (runtimes locales
// sin /models, ver services/ai/custom.js) no tiene lista posible — ahí se
// reemplaza el <select> por un <input> de texto libre, mismo id
// (cfg-ai-model) y mismo onchange, para que setAiModel() no tenga que saber
// cuál de los dos está renderizado.
function renderAiModelFallback(select, provider, selected) {
  const known = AI_MODELS_FALLBACK[provider];
  if (known?.length) {
    const opts = known.map(id => `<option value="${esc(id)}" ${selected === id ? 'selected' : ''}>${esc(id)}</option>`).join('');
    select.outerHTML = `
      <select class="form-input" id="cfg-ai-model" onchange="setAiModel(this.value)">
        <option value="" ${!selected ? 'selected' : ''}>Predeterminado (.env)</option>${opts}
      </select>
      <p style="font-family:var(--mono);font-size:10px;color:var(--t3);margin:4px 0 0;line-height:1.5">
        No se pudo obtener el listado en vivo — mostrando modelos conocidos. Verificá la API key para la lista actualizada.
      </p>`;
    return;
  }
  select.outerHTML = `
    <input type="text" class="form-input" id="cfg-ai-model" style="font-size:12px"
      placeholder="ID del modelo (ej. deepseek-flash)" value="${esc(selected || '')}"
      onchange="setAiModel(this.value)">
    <p style="font-family:var(--mono);font-size:10px;color:var(--t3);margin:4px 0 0;line-height:1.5">
      No se pudo obtener el listado de modelos de este proveedor — verificá su API key. Podés escribir el ID del modelo manualmente.
    </p>`;
}

async function loadAiModels(pid, provider, selected) {
  // Keyed por proyecto+proveedor: una key propia de un proyecto puede
  // exponer un listado de modelos distinto al de otro proyecto usando el
  // mismo proveedor (o la key global) — cachear solo por `provider` mezclaba
  // el listado de un proyecto con el de otro al cambiar de contexto.
  const cacheKey = `${pid}:${provider}`;
  const cached = _modelListCache[cacheKey];
  if (cached) {
    const select = document.getElementById('cfg-ai-model');
    if (select) renderAiModelOptions(select, cached, selected);
    return;
  }
  try {
    const { models } = await request('GET', `/projects/${pid}/ai/models?provider=${provider}`);
    _modelListCache[cacheKey] = models;
    // renderSettings() puede haber vuelto a correr (cambio de proveedor,
    // otro guardado) mientras este fetch estaba en vuelo — re-leer el
    // elemento en vez de guardar la referencia de antes del await.
    const select = document.getElementById('cfg-ai-model');
    if (select) renderAiModelOptions(select, models, selected);
  } catch (e) {
    const select = document.getElementById('cfg-ai-model');
    if (select) renderAiModelFallback(select, provider, selected);
  }
}

function buildAiUsageCard(usage) {
  if (!usage || !usage.totals.calls) {
    return `<p style="font-family:var(--mono);font-size:11px;color:var(--t3)">Sin uso de IA registrado todavía en este proyecto.</p>`;
  }
  const fmt$ = n => `$${Number(n).toFixed(4)}`;
  const rows = usage.byModel.map(m => `
    <div class="client-setting-row" style="padding:6px 0">
      <div>
        <div style="font-size:12px;font-weight:600">${esc(m.model)}</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--t3)">${esc(m.provider)} · ${m.calls} llamadas · ${(m.input_tokens+m.output_tokens).toLocaleString()} tokens</div>
      </div>
      <div style="font-family:var(--mono);font-size:12px;color:var(--t2)">${m.cost_usd != null ? fmt$(m.cost_usd) : '—'}</div>
    </div>`).join('');

  return `
    <div style="font-size:20px;font-weight:700;margin-bottom:2px">${fmt$(usage.totals.cost_usd)}</div>
    <div style="font-family:var(--mono);font-size:11px;color:var(--t3);margin-bottom:12px">
      ${usage.totals.calls} llamadas · ${(usage.totals.input_tokens+usage.totals.output_tokens).toLocaleString()} tokens
    </div>
    <div style="display:flex;flex-direction:column;gap:2px;border-top:1px solid var(--b1);padding-top:6px">${rows}</div>`;
}

function dateField(id, label, val) {
  const fmt = d => d ? d.slice(0,10) : '';
  return `
    <div>
      <div style="font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);margin-bottom:4px">${label}</div>
      <input type="date" id="${id}" class="form-input" value="${fmt(val)}">
    </div>`;
}

function buildClientSettings(p) {
  const toggle = (flag, label, desc) => {
    const on = !!p[flag];
    return `
      <div class="client-setting-row">
        <div>
          <div style="font-size:13px;font-weight:600;margin-bottom:2px">${label}</div>
          <div style="font-family:var(--mono);font-size:11px;color:var(--t3)">${desc}</div>
        </div>
        <button class="setting-toggle ${on?'on':''}" onclick="toggleProjectFlag('${flag}',${!on})">
          <span class="setting-toggle-knob"></span>
        </button>
      </div>`;
  };

  const logoBg    = p.logo_bg || 'light';
  const previewBg = logoBg === 'dark' ? '#1e1e1e' : '#ffffff';
  const previewBd = logoBg === 'dark' ? 'rgba(255,255,255,.08)' : 'rgba(0,0,0,.09)';

  const logoPreview = p.logo_url
    ? `<div style="background:${previewBg};border:1px solid ${previewBd};border-radius:var(--r);padding:8px 14px;display:flex;align-items:center;justify-content:center;min-width:80px">
         <img src="${esc(p.logo_url)}" style="height:36px;max-width:120px;object-fit:contain">
       </div>`
    : `<div style="height:52px;width:90px;border-radius:var(--r);background:var(--bg3);border:1px dashed var(--b2);display:flex;align-items:center;justify-content:center">
         <span style="font-family:var(--mono);font-size:10px;color:var(--t3)">no logo</span>
       </div>`;

  const bgToggle = p.logo_url ? `
    <div style="display:flex;gap:4px;margin-top:4px">
      <button onclick="setLogoBg('light')" style="font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:var(--r);border:1px solid ${logoBg==='light'?'var(--a)':'var(--b1)'};background:${logoBg==='light'?'var(--a-dim)':'transparent'};color:${logoBg==='light'?'var(--a)':'var(--t3)'};cursor:pointer">${icon('zap',{size:11})} Light</button>
      <button onclick="setLogoBg('dark')"  style="font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:var(--r);border:1px solid ${logoBg==='dark' ?'var(--a)':'var(--b1)'};background:${logoBg==='dark' ?'var(--a-dim)':'transparent'};color:${logoBg==='dark' ?'var(--a)':'var(--t3)'};cursor:pointer">${icon('circle',{size:11})} Dark</button>
    </div>` : '';

  return `
    <div style="display:flex;flex-direction:column;gap:2px">
      <div style="padding:0 0 14px;border-bottom:1px solid var(--b1);margin-bottom:4px">
        <div style="font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);margin-bottom:8px">Logo del proyecto</div>
        <div style="display:flex;align-items:center;gap:12px">
          ${logoPreview}
          <div style="display:flex;flex-direction:column;gap:6px">
            <label class="btn btn-ghost" style="cursor:pointer;display:inline-block;text-align:center">
              ${p.logo_url ? 'Cambiar' : 'Subir logo'}
              <input type="file" accept="image/*" style="display:none" onchange="onLogoFileChange(this)">
            </label>
            ${p.logo_url ? `<button class="btn" style="color:var(--c-crit);border-color:var(--c-crit-bg)" onclick="removeLogo()">Eliminar</button>` : ''}
            ${bgToggle}
          </div>
          <span style="font-family:var(--mono);font-size:10px;color:var(--t3);line-height:1.6">Visible en el portal<br>del cliente y sidebar.<br>PNG/JPG, max 1.5 MB.</span>
        </div>
      </div>
      ${toggle('client_view_enabled', 'Client portal activo',    'Permite acceso al portal mediante link')}
      ${toggle('show_findings',       'Mostrar hallazgos',       'Vulnerabilidades con severidad, descripción y remediación')}
      ${toggle('show_wstg_progress',  'Mostrar progreso WSTG',   'Progreso de testing por categoría en tiempo real')}
      ${toggle('show_wstg_notes',     'Mostrar notas WSTG',      'Notas escritas por los pentesters en cada test')}
      ${toggle('show_targets',        'Mostrar targets',         'Hosts en scope y su estado de auditoría')}
      ${toggle('show_activity',       'Mostrar actividad',       'Feed en tiempo real de acciones del pentester')}
      ${toggle('portal_hide_team_avatars', 'Ocultar avatares del equipo', 'En el portal, las fotos de perfil del equipo se reemplazan por iniciales')}
      ${toggle('portal_hide_log_times',    'Ocultar hora de los logs',    'El feed de actividad del portal no muestra la hora de cada acción')}
      ${toggle('tickets_enabled',     'Habilitar queries',       'El cliente puede abrir preguntas vinculadas a un hallazgo')}
      ${buildPortalLinkSection(p)}
    </div>`;
}

function buildPortalLinkSection(p) {
  const base = `${window.location.origin}${window.location.pathname.replace(/\/[^/]*$/, '')}/client-login`;
  const link = p.portal_token ? `${base}?token=${p.portal_token}` : null;

  return `
    <div style="margin-top:8px;padding-top:14px;border-top:1px solid var(--b1)">
      <div style="font-family:var(--mono);font-size:9px;text-transform:uppercase;letter-spacing:.1em;color:var(--t3);margin-bottom:10px">Access Link</div>

      ${link ? `
        <div style="display:flex;gap:6px;margin-bottom:10px;align-items:center">
          <input readonly class="form-input" value="${esc(link)}"
            style="flex:1;font-size:10px;font-family:var(--mono);color:var(--t2);cursor:text"
            onclick="this.select()">
          <button class="btn btn-ghost" style="flex-shrink:0;font-size:11px;padding:6px 12px" onclick="copyPortalLink('${esc(link)}')">Copy</button>
        </div>` : `
        <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 10px;line-height:1.6">
          No link generated yet. Click below to create one.
        </p>`}

      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button class="btn btn-ghost" style="font-size:11px;padding:6px 12px" onclick="regeneratePortalLink()">
          ${link ? 'Regenerate link' : 'Generate link'}
        </button>
        ${link ? `<span style="font-family:var(--mono);font-size:10px;color:var(--t3)">Regenerating invalidates the old link</span>` : ''}
      </div>

      ${link ? `
        <div style="margin-top:12px;display:flex;flex-direction:column;gap:8px">
          <div class="client-setting-row" style="padding:8px 0;border-bottom:none">
            <div>
              <div style="font-size:13px;font-weight:600;margin-bottom:2px">Require password</div>
              <div style="font-family:var(--mono);font-size:11px;color:var(--t3)">Client must enter a password to access the portal</div>
            </div>
            <button class="setting-toggle ${p.portal_require_password?'on':''}"
              onclick="toggleProjectFlag('portal_require_password',${!p.portal_require_password})">
              <span class="setting-toggle-knob"></span>
            </button>
          </div>
          ${p.portal_require_password ? `
            <div style="display:flex;gap:6px;align-items:center">
              <input type="password" class="form-input" id="portal-pw-input"
                placeholder="Set new password" style="flex:1;font-size:12px">
              <button class="btn btn-ghost" style="flex-shrink:0;font-size:11px;padding:6px 12px" onclick="savePortalPassword()">Set</button>
            </div>
            <p style="font-family:var(--mono);font-size:10px;color:var(--t3);margin:0;line-height:1.5">
              ${p.has_portal_password ? 'A password is currently set. Enter a new one to replace it.' : 'No password set yet.'}
            </p>` : ''}
        </div>` : ''}
    </div>`;
}

// ── actions ───────────────────────────────────────────────────────────

async function saveGeneral() {
  const name   = document.getElementById('cfg-name')?.value.trim();
  const target = document.getElementById('cfg-target')?.value.trim();
  const desc   = document.getElementById('cfg-desc')?.value.trim();
  if (!name) { showToast('El nombre no puede estar vacío', 'error'); return; }
  try {
    const updated = await api.projects.update(state.currentProject.id, { name, target, description: desc });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Guardado', 'success');
    renderSidenav();
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveTimeline() {
  const get = id => { const el = document.getElementById(id); return el?.value || null; };
  try {
    const updated = await api.projects.update(state.currentProject.id, {
      date_start:  get('tl-start'),
      date_end:    get('tl-end'),
      date_report: get('tl-report'),
    });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Fechas guardadas', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function setAiProvider(provider) {
  try {
    // Switching provider clears the chosen model — the old value may not exist on the new provider
    const updated = await api.projects.update(state.currentProject.id, { ai_provider: provider, ai_model: null });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Proveedor de IA actualizado', 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

async function setAiModel(model) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { ai_model: model || null });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Modelo actualizado', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function setAiToolMode(mode) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { ai_tool_mode: mode });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Modo de tool-calling actualizado', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveGithubRepo(repo) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { github_repo: repo.trim() || null });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Repositorio actualizado', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveGithubPat() {
  const input = document.getElementById('cfg-github-pat');
  const pat   = input?.value.trim();
  if (!pat) return;
  try {
    const updated = await api.projects.update(state.currentProject.id, { github_pat: pat });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Token guardado', 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

async function saveAiApiKey() {
  const input    = document.getElementById('cfg-ai-apikey');
  const key      = input?.value.trim() || '';
  const provider = state.currentProject.ai_provider || 'groq';
  try {
    const updated = await api.projects.update(state.currentProject.id, { ai_api_keys: { [provider]: key } });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    // Invalidar el cache del listado de modelos de este proyecto+proveedor —
    // si la key estaba mal (o no existía) y el fetch anterior había
    // fallado, un cache de fallo pegaría al usuario en el <input> manual
    // hasta refrescar.
    delete _modelListCache[`${state.currentProject.id}:${provider}`];
    showToast(key ? 'Key guardada' : 'Key eliminada — usando la del servidor', 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

async function toggleProjectFlag(flag, value) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { [flag]: value });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    renderSettings();
    showToast('Guardado', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function onLogoFileChange(input) {
  const file = input.files?.[0];
  if (!file) return;
  if (file.size > 1.5 * 1024 * 1024) { showToast('Imagen demasiado grande (max 1.5 MB)', 'error'); return; }
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const updated = await api.projects.update(state.currentProject.id, { logo_url: e.target.result });
      state.currentProject = { ...state.currentProject, ...updated };
      const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
      if (idx > -1) state.projects[idx] = state.currentProject;
      showToast('Logo guardado', 'success');
      renderSettings();
    } catch(e) { showToast(e.message, 'error'); }
  };
  reader.readAsDataURL(file);
}

async function removeLogo() {
  try {
    const updated = await api.projects.update(state.currentProject.id, { logo_url: null });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Logo eliminado', 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

async function setLogoBg(bg) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { logo_bg: bg });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

async function regeneratePortalLink() {
  if (!state.currentProject) return;
  const pid = state.currentProject.id;
  if (state.currentProject.portal_token) {
    if (!confirm('Regenerating the link will invalidate the current one. Clients with the old link will lose access. Continue?')) return;
  }
  try {
    const updated = await api.portal.regenerate(pid);
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === pid);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Portal link generated', 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

function copyPortalLink(link) {
  navigator.clipboard.writeText(link)
    .then(() => showToast('Link copied', 'success'))
    .catch(() => showToast('Could not copy to clipboard', 'error'));
}

async function savePortalPassword() {
  const pw = document.getElementById('portal-pw-input')?.value;
  if (!pw) { showToast('Enter a password first', 'error'); return; }
  const pid = state.currentProject.id;
  try {
    const updated = await api.portal.setPassword(pid, pw, true);
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === pid);
    if (idx > -1) state.projects[idx] = state.currentProject;
    showToast('Password set', 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

// Moving needs owner/admin on the destination org (the server enforces it),
// so only those orgs are offered.
function buildOrgMoveCard(p, orgs) {
  const current = orgs.find(o => o.id === p.organization_id)?.name
    || state.projects.find(x => x.id === p.id)?.organization_name
    || 'otra organización';
  const targets = orgs.filter(o => o.id !== p.organization_id && ['owner', 'admin'].includes(o.member_role));
  return `
    <div class="members-card">
      <div class="members-card-title">Organization</div>
      <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 12px">
        Pertenece a <strong style="color:var(--t1)">${esc(current)}</strong>. Al moverlo, los miembros del proyecto conservan su acceso; el acceso implícito de los owners/admins pasa de la organización actual a la nueva.
      </p>
      ${targets.length ? `
      <div style="display:flex;gap:6px;align-items:center">
        <select class="form-input" id="cfg-move-org" style="flex:1">
          ${targets.map(o => `<option value="${o.id}">${esc(o.name)}</option>`).join('')}
        </select>
        <button class="btn btn-ghost" style="flex-shrink:0;font-size:11px;padding:6px 12px" onclick="moveProjectToOrg()">Mover</button>
      </div>` : `
      <p style="font-family:var(--mono);font-size:10px;color:var(--t3);margin:0">
        No hay otra organización donde seas owner o admin.
      </p>`}
    </div>`;
}

async function moveProjectToOrg() {
  const sel = document.getElementById('cfg-move-org');
  const oid = sel?.value;
  if (!oid) return;
  const name = sel.options[sel.selectedIndex].text;
  if (!confirm(`¿Mover "${state.currentProject.name}" a ${name}?`)) return;
  try {
    const res = await api.projects.move(state.currentProject.id, oid);
    state.currentProject = { ...state.currentProject, organization_id: res.organization_id, organization_name: res.organization_name };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = { ...state.projects[idx], organization_id: res.organization_id, organization_name: res.organization_name };
    showToast(`Movido a ${res.organization_name}`, 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

async function deleteProject() {
  if (!confirm(`¿Eliminar "${state.currentProject.name}"? Esta acción no se puede deshacer.`)) return;
  try {
    await api.projects.delete(state.currentProject.id);
    state.projects = state.projects.filter(p => p.id !== state.currentProject.id);
    state.currentProject = state.projects[0] || null;
    localStorage.setItem('fd_project', state.currentProject?.id || '');
    window.location.href = 'projects';
  } catch(e) { showToast(e.message, 'error'); }
}

window.renderSettings       = renderSettings;
window.saveGeneral          = saveGeneral;
window.saveTimeline         = saveTimeline;
window.toggleProjectFlag    = toggleProjectFlag;
window.setAiProvider        = setAiProvider;
window.setAiModel           = setAiModel;
window.setAiToolMode        = setAiToolMode;
window.saveGithubRepo       = saveGithubRepo;
window.saveGithubPat        = saveGithubPat;
window.onLogoFileChange     = onLogoFileChange;
window.removeLogo           = removeLogo;
window.setLogoBg            = setLogoBg;
window.deleteProject        = deleteProject;
window.moveProjectToOrg     = moveProjectToOrg;
window.regeneratePortalLink = regeneratePortalLink;
window.copyPortalLink       = copyPortalLink;
window.savePortalPassword   = savePortalPassword;
