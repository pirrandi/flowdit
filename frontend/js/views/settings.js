// ── views/settings.js ─────────────────────────────────────────────────

async function renderSettings() {
  const container = document.getElementById('view-settings');
  if (!state.currentProject) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">◌</div><div class="empty-title">No project selected</div></div>';
    return;
  }

  const p       = state.currentProject;
  const pid     = p.id;
  const isOwner = p.member_role === 'owner';

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

        <div class="members-card" style="border-color:rgba(239,68,68,.25)">
          <div class="members-card-title" style="color:var(--c-crit)">Danger Zone</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 12px">
            Borrar el proyecto elimina todos los hallazgos, targets, metodología y datos asociados. Esta acción es irreversible.
          </p>
          <button class="btn-danger" onclick="deleteProject()">Eliminar proyecto</button>
        </div>

      </div>

      <!-- Right column: Client Portal + Extras -->
      <div style="display:flex;flex-direction:column;gap:12px">

        <div class="members-card">
          <div class="members-card-title">Client Portal</div>
          <p style="font-family:var(--mono);font-size:11px;color:var(--t3);margin:0 0 14px">
            Controla qué ve el cliente en su portal de solo lectura.
          </p>
          ${buildClientSettings(p)}
        </div>

        <div class="members-card" style="border-color:var(--b1)">
          <div class="members-card-title" style="color:var(--t3);font-size:12px">
            // extras
            <span style="font-family:var(--mono);font-size:9px;color:var(--t3);opacity:.5;font-weight:400;margin-left:6px">completely optional nonsense</span>
          </div>
          <div style="display:flex;flex-direction:column;gap:2px">
            ${buildFunSettings()}
          </div>
        </div>

      </div>
    </div>` : '<div style="font-family:var(--mono);font-size:11px;color:var(--t3)">Solo el owner puede ver la configuración del proyecto.</div>'}
  `;
}

// ── helpers ───────────────────────────────────────────────────────────

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
      <button onclick="setLogoBg('light')" style="font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:var(--r);border:1px solid ${logoBg==='light'?'var(--a)':'var(--b1)'};background:${logoBg==='light'?'var(--a-dim)':'transparent'};color:${logoBg==='light'?'var(--a)':'var(--t3)'};cursor:pointer">☀ Light</button>
      <button onclick="setLogoBg('dark')"  style="font-family:var(--mono);font-size:10px;padding:3px 8px;border-radius:var(--r);border:1px solid ${logoBg==='dark' ?'var(--a)':'var(--b1)'};background:${logoBg==='dark' ?'var(--a-dim)':'transparent'};color:${logoBg==='dark' ?'var(--a)':'var(--t3)'};cursor:pointer">◑ Dark</button>
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
      ${toggle('tickets_enabled',     'Habilitar queries',       'El cliente puede abrir preguntas vinculadas a un hallazgo')}
      ${buildPortalLinkSection(p)}
    </div>`;
}

function buildPortalLinkSection(p) {
  const base = `${window.location.origin}${window.location.pathname.replace(/\/[^/]*$/, '')}/client-login.html`;
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

function buildFunSettings() {
  if (!state.currentProject) return '';
  const s  = getFunSettings(state.currentProject.id);
  const ft = (key, emoji, label, desc) => {
    const on = !!s[key];
    return `<div class="client-setting-row">
      <div>
        <div style="font-size:13px;font-weight:600;margin-bottom:2px">${emoji} ${label}</div>
        <div style="font-family:var(--mono);font-size:11px;color:var(--t3)">${desc}</div>
      </div>
      <button class="setting-toggle ${on?'on':''}" onclick="toggleFunSetting('${key}',${!on})">
        <span class="setting-toggle-knob"></span>
      </button>
    </div>`;
  };
  return `
    ${ft('confetti', '🎉', 'Confetti at 100%', 'Confeti cuando la cobertura WSTG llega al 100%')}
    ${ft('neon',     '🌈', 'Neon mode',        'Glow en badges de severidad y barras de progreso')}
    ${ft('hacker',   '💀', 'Hacker vibes',     'Overlay de scanlines — máxima credibilidad en calls con el cliente')}
  `;
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
    showToast('✓ Guardado', 'success');
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
    showToast('✓ Fechas guardadas', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function toggleProjectFlag(flag, value) {
  try {
    const updated = await api.projects.update(state.currentProject.id, { [flag]: value });
    state.currentProject = { ...state.currentProject, ...updated };
    const idx = state.projects.findIndex(p => p.id === state.currentProject.id);
    if (idx > -1) state.projects[idx] = state.currentProject;
    renderSettings();
    showToast('✓ Guardado', 'success');
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
      showToast('✓ Logo guardado', 'success');
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

function toggleFunSetting(key, val) {
  if (!state.currentProject) return;
  setFunSetting(state.currentProject.id, key, val);
  renderSettings();
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
    showToast('✓ Portal link generated', 'success');
    renderSettings();
  } catch(e) { showToast(e.message, 'error'); }
}

function copyPortalLink(link) {
  navigator.clipboard.writeText(link)
    .then(() => showToast('✓ Link copied', 'success'))
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
    showToast('✓ Password set', 'success');
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
    window.location.href = 'projects.html';
  } catch(e) { showToast(e.message, 'error'); }
}

window.renderSettings       = renderSettings;
window.saveGeneral          = saveGeneral;
window.saveTimeline         = saveTimeline;
window.toggleProjectFlag    = toggleProjectFlag;
window.onLogoFileChange     = onLogoFileChange;
window.removeLogo           = removeLogo;
window.setLogoBg            = setLogoBg;
window.buildFunSettings     = buildFunSettings;
window.toggleFunSetting     = toggleFunSetting;
window.deleteProject        = deleteProject;
window.regeneratePortalLink = regeneratePortalLink;
window.copyPortalLink       = copyPortalLink;
window.savePortalPassword   = savePortalPassword;
