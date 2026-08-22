// ── views/vulns.js ───────────────────────────────────────────────────
let _editingVulnId = null;

// ── TEMPLATE PICKER ──────────────────────────────────────────────────
const SEV_COLORS = { critical:'var(--c-crit)', high:'var(--c-high)', medium:'var(--c-med)', low:'var(--c-low)', info:'var(--c-info)' };
let _tplResults   = [];
let _tplFocusIdx  = -1;
let _tplDebounce  = null;

function _tplDot(sev) {
  return `<span style="width:7px;height:7px;border-radius:50%;background:${SEV_COLORS[sev]||'var(--t3)'};flex-shrink:0;display:inline-block"></span>`;
}

function tplSearch(q) {
  clearTimeout(_tplDebounce);
  _tplDebounce = setTimeout(async () => {
    try {
      _tplResults = await api.templates.search(q.trim());
      _tplFocusIdx = -1;
      _tplRender();
    } catch(e) { /* ignore */ }
  }, 200);
}

function _tplRender() {
  const dd = document.getElementById('tpl-dropdown');
  const inp = document.getElementById('tpl-search-input');
  if (!dd || !inp) return;

  if (_tplResults.length === 0) {
    dd.innerHTML = `<div class="tpl-empty">No templates found</div>`;
  } else {
    dd.innerHTML = _tplResults.map((t, i) => `
      <div class="tpl-item${i === _tplFocusIdx ? ' focused' : ''}" data-idx="${i}"
           onmousedown="tplApply(${i})">
        ${_tplDot(t.severity)}
        <span class="tpl-item-name">${esc(t.name)}</span>
        ${t.category ? `<span class="tpl-item-cat">${esc(t.category)}</span>` : ''}
        ${!t.is_builtin ? `<span class="tpl-item-own">mine</span>` : ''}
      </div>`).join('');
  }

  const rect = inp.getBoundingClientRect();
  dd.style.top      = (rect.bottom + 4) + 'px';
  dd.style.left     = rect.left + 'px';
  dd.style.width    = rect.width + 'px';
  dd.classList.add('open');
}

function _tplClose() {
  const dd = document.getElementById('tpl-dropdown');
  if (dd) dd.classList.remove('open');
  _tplResults = [];
  _tplFocusIdx = -1;
}

function tplKeydown(e) {
  if (!document.getElementById('tpl-dropdown')?.classList.contains('open')) return;
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    _tplFocusIdx = Math.min(_tplFocusIdx + 1, _tplResults.length - 1);
    _tplRender();
  } else if (e.key === 'ArrowUp') {
    e.preventDefault();
    _tplFocusIdx = Math.max(_tplFocusIdx - 1, 0);
    _tplRender();
  } else if (e.key === 'Enter' && _tplFocusIdx >= 0) {
    e.preventDefault();
    tplApply(_tplFocusIdx);
  } else if (e.key === 'Escape') {
    _tplClose();
  }
}

function tplApply(idx) {
  const t = _tplResults[idx];
  if (!t) return;

  document.getElementById('modal-vuln-name').value  = t.name;
  document.getElementById('modal-vuln-cat').value   = t.category || '';
  document.getElementById('modal-vuln-cwe').value   = t.cwe || '';
  document.getElementById('modal-vuln-sev').value   = t.severity;
  document.getElementById('modal-vuln-desc').value  = t.description || '';
  document.getElementById('modal-vuln-rem').value   = t.remediation || '';
  if (window.cselSync) window.cselSync();

  const inp = document.getElementById('tpl-search-input');
  if (inp) inp.value = '';
  _tplClose();
}

async function tplSaveCurrent() {
  const name = document.getElementById('modal-vuln-name').value.trim();
  if (!name) { showToast('Enter a name first', 'error'); return; }
  const data = {
    name,
    category:    document.getElementById('modal-vuln-cat').value.trim() || null,
    severity:    document.getElementById('modal-vuln-sev').value,
    cwe:         document.getElementById('modal-vuln-cwe').value.trim() || null,
    description: document.getElementById('modal-vuln-desc').value.trim() || null,
    remediation: document.getElementById('modal-vuln-rem').value.trim() || null,
  };
  try {
    await api.templates.save(data);
    showToast('Template saved', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

document.addEventListener('click', (e) => {
  if (!e.target.closest('#tpl-search-wrap')) _tplClose();
});

function numberedCode(text) {
  if (!text) return '';
  const lines = text.split('\n');
  const pad = String(lines.length).length;
  return lines.map((line, i) =>
    `<span class="code-line"><span class="line-num">${String(i + 1).padStart(pad, ' ')}</span>${esc(line)}</span>`
  ).join('\n');
}

// ── CVSS v3.1 ────────────────────────────────────────────────────────
const _CVSS_W = {
  AV:  { N:0.85, A:0.62, L:0.55, P:0.2  },
  AC:  { L:0.77, H:0.44 },
  PR_U:{ N:0.85, L:0.62, H:0.27 },
  PR_C:{ N:0.85, L:0.68, H:0.50 },
  UI:  { N:0.85, R:0.62 },
  CIA: { N:0,    L:0.22, H:0.56 },
};
let _cvss = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };
let _cvssModified = false;
let _cvssCleared  = false;

function _cvssRoundUp(x) {
  const i = Math.ceil(x * 100000);
  return (i % 10000 === 0) ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

function calcCVSSScore(m) {
  const av  = _CVSS_W.AV[m.AV]  ?? 0.85;
  const ac  = _CVSS_W.AC[m.AC]  ?? 0.77;
  const pr  = (m.S === 'U' ? _CVSS_W.PR_U : _CVSS_W.PR_C)[m.PR] ?? 0.85;
  const ui  = _CVSS_W.UI[m.UI]  ?? 0.85;
  const c   = _CVSS_W.CIA[m.C]  ?? 0;
  const ii  = _CVSS_W.CIA[m.I]  ?? 0;
  const a   = _CVSS_W.CIA[m.A]  ?? 0;
  const iscBase = 1 - (1-c)*(1-ii)*(1-a);
  const isc = m.S === 'U'
    ? 6.42 * iscBase
    : 7.52*(iscBase-0.029) - 3.25*Math.pow(iscBase-0.02, 15);
  const exp = 8.22 * av * ac * pr * ui;
  if (isc <= 0) return 0;
  const raw = m.S === 'U' ? Math.min(isc+exp,10) : Math.min(1.08*(isc+exp),10);
  return _cvssRoundUp(raw);
}

function buildCVSSVector(m) {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

function parseCVSSVector(vec) {
  if (!vec?.startsWith('CVSS:3.1/')) return null;
  const r = {};
  vec.replace('CVSS:3.1/','').split('/').forEach(p => { const [k,v]=p.split(':'); r[k]=v; });
  return r;
}

function _cvssColor(s) {
  if (s >= 9) return '#dc2626'; if (s >= 7) return '#f97316';
  if (s >= 4) return '#f59e0b'; if (s > 0)  return '#059669';
  return 'var(--t3)';
}
function _cvssLabel(s) {
  if (s >= 9) return 'Critical'; if (s >= 7) return 'High';
  if (s >= 4) return 'Medium';   if (s > 0)  return 'Low';
  return 'None';
}
function _cvssSevClass(s) {
  if (s >= 9) return 'critical'; if (s >= 7) return 'high';
  if (s >= 4) return 'medium';   if (s > 0)  return 'low';
  return 'info';
}

function setCVSSMetric(metric, value) {
  _cvss[metric] = value;
  _cvssModified = true;
  _cvssCleared  = false;
  const clrBtn  = document.getElementById('cvss-clear-btn');
  if (clrBtn) clrBtn.style.display = 'inline';
  _renderCVSSCalc();
}

function _renderCVSSCalc() {
  const score  = calcCVSSScore(_cvss);
  const vector = buildCVSSVector(_cvss);
  const color  = _cvssColor(score);
  const label  = _cvssLabel(score);

  const sd = document.getElementById('cvss-score-display');
  if (sd) sd.innerHTML = `
    <span style="font-family:var(--mono);font-size:26px;font-weight:800;color:${color};line-height:1">${score.toFixed(1)}</span>
    <span class="sev-badge sev-${_cvssSevClass(score)}" style="margin-left:4px">${label}</span>`;

  const vd = document.getElementById('cvss-vector-display');
  if (vd) vd.textContent = vector;

  const hp = document.getElementById('cvss-header-pill');
  if (hp) { hp.style.color = color; hp.textContent = `${score.toFixed(1)} · ${label}`; }

  ['AV','AC','PR','UI','S','C','I','A'].forEach(m => {
    document.querySelectorAll(`.cvss-btn[data-metric="${m}"]`).forEach(btn => {
      btn.classList.toggle('active', btn.dataset.value === _cvss[m]);
    });
  });
}

function toggleCVSSSection() {
  const body = document.getElementById('cvss-calc');
  const btn  = document.getElementById('cvss-toggle-btn');
  if (!body) return;
  const opening = body.style.display === 'none';
  body.style.display = opening ? 'block' : 'none';
  if (btn) btn.innerHTML = opening ? `${icon('chevron-down',{size:11})} close` : `${icon('chevron-right',{size:11})} open`;
  if (opening) _renderCVSSCalc();
}

function _initCVSS(vector) {
  const parsed = parseCVSSVector(vector);
  _cvss = parsed
    ? { AV:parsed.AV||'N', AC:parsed.AC||'L', PR:parsed.PR||'N',
        UI:parsed.UI||'N', S:parsed.S||'U',   C:parsed.C||'N',
        I:parsed.I||'N',   A:parsed.A||'N' }
    : { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };
  _cvssModified = !!vector;
  _cvssCleared  = false;

  const body  = document.getElementById('cvss-calc');
  const btn   = document.getElementById('cvss-toggle-btn');
  const clrBtn= document.getElementById('cvss-clear-btn');
  const hp    = document.getElementById('cvss-header-pill');
  if (body) body.style.display = vector ? 'block' : 'none';
  if (btn)  btn.innerHTML      = vector ? `${icon('chevron-down',{size:11})} close` : `${icon('chevron-right',{size:11})} open`;
  if (clrBtn) clrBtn.style.display = vector ? 'inline' : 'none';
  if (hp) {
    if (vector) {
      const s = calcCVSSScore(_cvss);
      hp.style.color = _cvssColor(s);
      hp.textContent = `${s.toFixed(1)} · ${_cvssLabel(s)}`;
    } else {
      hp.style.color = ''; hp.textContent = 'not scored';
    }
  }
  if (vector) _renderCVSSCalc();
}

function clearCVSS() {
  _cvssModified = true;
  _cvssCleared  = true;
  _cvss = { AV:'N', AC:'L', PR:'N', UI:'N', S:'U', C:'N', I:'N', A:'N' };
  const body   = document.getElementById('cvss-calc');
  const btn    = document.getElementById('cvss-toggle-btn');
  const clrBtn = document.getElementById('cvss-clear-btn');
  const hp     = document.getElementById('cvss-header-pill');
  if (body)   body.style.display   = 'none';
  if (btn)    btn.innerHTML         = `${icon('chevron-right',{size:11})} open`;
  if (clrBtn) clrBtn.style.display  = 'none';
  if (hp)     { hp.style.color = ''; hp.textContent = 'not scored'; }
}

async function copyCVSSVector() {
  await navigator.clipboard.writeText(buildCVSSVector(_cvss)).catch(()=>{});
  showToast('CVSS vector copied', 'info');
}

const SEVERITY_ORDER  = ['critical','high','medium','low','info'];

const SEVERITY_LABELS = { critical:'Critical', high:'High', medium:'Medium', low:'Low', info:'Info' };

function severityBadge(sev) {
  const s = sev || 'medium';
  return `<span class="sev-badge sev-${s}">${SEVERITY_LABELS[s]||s}</span>`;
}

const REMEDIATION_LABELS = { open: 'Open', remediated: 'Remediated', verified_closed: 'Verified Closed' };
const REMEDIATION_COLORS = { open: 'var(--t3)', remediated: 'var(--c-med)', verified_closed: 'var(--c-low)' };

function remediationBadge(status) {
  const s = status || 'open';
  const c = REMEDIATION_COLORS[s] || REMEDIATION_COLORS.open;
  return `<span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${c};background:${c}15;border:1px solid ${c}33;border-radius:4px;padding:1px 7px;flex-shrink:0">${REMEDIATION_LABELS[s]||s}</span>`;
}

function renderCustomVulns() {
  const container = document.getElementById('custom-content');
  if (!state.customVulns.length) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon">${icon('inbox', { size: 28 })}</div><div class="empty-title">No custom vulnerabilities</div><div class="empty-sub">Add findings, then write descriptions & export from the Export page</div><button class="btn btn-prim" style="margin-top:14px" onclick="openAddVulnModal()">+ Add Vulnerability</button></div>`;
    return;
  }
  const bySev = {};
  SEVERITY_ORDER.forEach(s => bySev[s] = []);
  state.customVulns.forEach(v => { const s = v.severity||'medium'; (bySev[s]||bySev['medium']).push(v); });

  container.innerHTML = '';
  SEVERITY_ORDER.forEach(sev => {
    if (!bySev[sev].length) return;
    const section = document.createElement('div');
    section.className = 'vuln-severity-section';
    section.innerHTML = `<div class="vuln-severity-header">
      <span class="sev-badge sev-${sev}">${SEVERITY_LABELS[sev]}</span>
      <span class="vuln-severity-count">${bySev[sev].length} finding${bySev[sev].length>1?'s':''}</span>
    </div>`;
    bySev[sev].forEach(v => section.appendChild(buildVulnCard(v)));
    container.appendChild(section);
  });
}

function buildVulnCard(v) {
  const isDone = v.status === 'done';
  const isFail = v.status === 'fail';
  const card   = document.createElement('div');
  card.className = `vuln-card ${isDone?'completed':''} ${isFail?'failed':''}`;
  card.id = `vuln-${v.id}`;

  const itemsH = (v.items||[]).length ? `<div class="items-section"><div class="items-label">Checklist</div>` +
    v.items.map((item, idx) => {
      const chk = v.checked_items?.[idx] || false;
      return `<div class="item-row">
        <div class="item-checkbox ${chk?'checked':''}" onclick="toggleCustomItem('${v.id}',${idx},this)">${chk?icon('check',{size:11}):''}</div>
        <span class="item-text ${chk?'done':''}">${esc(item)}</span>
      </div>`;
    }).join('') + '</div>' : '';

  const payH = (v.payloads||[]).length ? `<div class="payload-section"><div class="items-label">Payloads</div>` +
    v.payloads.map(p => `<div class="payload-row">
      <div class="payload-code">${esc(p)}</div>
      <button class="copy-btn" onclick="copyText(this,'${btoa(encodeURIComponent(p))}')">copy</button>
    </div>`).join('') + '</div>' : '';

  const noteH = v.notes ? `<div class="items-section"><div class="items-label">Notes</div>
    <div class="payload-code" style="color:var(--t2);white-space:pre-wrap">${esc(v.notes)}</div></div>` : '';

  const remStatus = v.remediation_status || 'open';
  const remActionsH = remStatus === 'open'
    ? `<button class="btn btn-ghost" style="font-size:11px;padding:4px 10px" onclick="setRemediationStatus('${v.id}','remediated')">Marcar como remediado</button>`
    : remStatus === 'remediated'
    ? `<button class="btn btn-prim" style="font-size:11px;padding:4px 10px" onclick="setRemediationStatus('${v.id}','verified_closed')">Verificar y cerrar</button>
       <button class="btn btn-ghost" style="font-size:11px;padding:4px 10px;color:var(--c-crit)" onclick="setRemediationStatus('${v.id}','open')">Reabrir</button>`
    : `<button class="btn btn-ghost" style="font-size:11px;padding:4px 10px;color:var(--c-crit)" onclick="setRemediationStatus('${v.id}','open')">Reabrir</button>`;

  const remTrailH = [
    v.remediated_at ? `Remediado: ${new Date(v.remediated_at).toLocaleDateString()}` : '',
    v.verified_at   ? `Verificado: ${new Date(v.verified_at).toLocaleDateString()}${v.verifier_username ? ' por ' + esc(v.verifier_username) : ''}` : '',
  ].filter(Boolean).join(' · ');

  const remH2 = `<div class="items-section">
    <div class="items-label">Remediation Status</div>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
      ${remediationBadge(remStatus)}
      ${remActionsH}
    </div>
    ${remTrailH ? `<div style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-bottom:8px">${remTrailH}</div>` : ''}
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end">
      <div>
        <div style="font-family:var(--mono);font-size:9px;text-transform:uppercase;color:var(--t3);margin-bottom:3px">Fecha retest</div>
        <input type="date" class="form-input" style="font-size:11px" value="${v.retest_date ? v.retest_date.slice(0,10) : ''}" onchange="setRetestDate('${v.id}', this.value)">
      </div>
      <div style="flex:1;min-width:180px">
        <div style="font-family:var(--mono);font-size:9px;text-transform:uppercase;color:var(--t3);margin-bottom:3px">Notas retest</div>
        <input type="text" class="form-input" style="font-size:11px" placeholder="Notas del reintento..." value="${esc(v.retest_notes||'')}" onblur="setRetestNotes('${v.id}', this.value)">
      </div>
    </div>
  </div>`;

  const descH = v.description ? `<div class="items-section"><div class="items-label">Description</div>
    <div class="md-body" style="color:var(--t2)">${renderMd(v.description)}</div></div>` : '';
  const remH  = v.remediation ? `<div class="items-section"><div class="items-label">Remediation</div>
    <div class="md-body" style="color:var(--c-low)">${renderMd(v.remediation)}</div></div>` : '';
  const evidH = (v.evidence||[]).length ? `<div class="items-section">
    <div class="items-label">Evidence (${v.evidence.length})</div>
    <div class="evidence-thumbs">${v.evidence.map((img,i) =>
      `<img src="${img.data}" class="evidence-thumb" alt="${esc(img.name||'')}" onclick="openEvidenceViewer('${v.id}',${i})">`
    ).join('')}</div></div>` : '';

  const proofs = (v.http_proofs || []);
  const httpH = proofs.length ? `<div class="items-section">
    <div class="items-label">HTTP Proofs (${proofs.length})</div>
    ${proofs.map((pr, i) => {
      const included = pr.include !== false;
      return `
      <div class="http-proof" id="http-proof-${v.id}-${i}">
        <div class="http-proof-head">
          <span class="http-proof-method">${esc(pr.method || 'HTTP')}</span>
          <span class="http-proof-label" onclick="document.getElementById('http-proof-${v.id}-${i}').querySelector('.http-proof-body').classList.toggle('open')">Proof #${i+1}</span>
          <label class="http-proof-include" title="Incluir en reporte" onclick="event.stopPropagation()">
            <input type="checkbox" ${included ? 'checked' : ''} onchange="toggleHttpProofInclude('${v.id}',${i},this.checked)">
            <span>reporte</span>
          </label>
          <button class="http-proof-edit-btn" onclick="editHttpProof('${v.id}',${i})" title="Editar">${icon('square-pen',{size:11})}</button>
          <span class="http-proof-toggle" onclick="document.getElementById('http-proof-${v.id}-${i}').querySelector('.http-proof-body').classList.toggle('open')">${icon('chevron-right',{size:11})}</span>
        </div>
        <div class="http-proof-body">
          ${pr.request ? `<div class="http-proof-section-label">Request</div><pre class="http-proof-code">${numberedCode(pr.request)}</pre>` : ''}
          ${pr.response ? `<div class="http-proof-section-label">Response</div><pre class="http-proof-code">${numberedCode(pr.response)}</pre>` : ''}
          ${pr.annotation ? `<div class="http-proof-section-label" style="margin-top:10px">Anotación</div><div class="http-proof-annotation md-body">${renderMd(pr.annotation)}</div>` : ''}
        </div>
      </div>`;
    }).join('')}
  </div>` : '';

  const editorBadge = v.editor_username ? `
    <div class="last-editor" style="margin-left:auto">
      ${avatarHtml(v.editor_username, memberRoleColor(v.updated_by, v.editor_color||'#7c3aed'), 20, v.editor_avatar_url||null)}
      <span class="last-editor-name">${esc(v.editor_username)}</span>
      <span class="last-editor-time">${timeAgo(v.updated_at)}</span>
    </div>` : '';

  card.innerHTML = `
    <div class="vuln-header" onclick="toggleVulnBody('${v.id}',event)">
      <div class="test-check"
        style="${isDone?'background:var(--c-low);border-color:var(--c-low);color:var(--bg)':isFail?'background:var(--c-crit);border-color:var(--c-crit);color:#fff':''}"
        onclick="cycleVulnStatus('${v.id}',event)">${isDone?icon('check',{size:12}):isFail?icon('x',{size:12}):''}</div>
      <span class="vuln-tag">${esc(v.category||'Custom')}</span>
      ${severityBadge(v.severity)}
      ${v.cvss_score != null ? `<span style="font-family:var(--mono);font-size:10px;font-weight:700;color:${_cvssColor(+v.cvss_score)};background:${_cvssColor(+v.cvss_score)}15;border:1px solid ${_cvssColor(+v.cvss_score)}33;border-radius:4px;padding:1px 7px;flex-shrink:0">CVSS ${(+v.cvss_score).toFixed(1)}</span>` : ''}
      ${v.cwe ? `<span style="font-family:var(--mono);font-size:10px;font-weight:600;color:var(--t3);background:var(--bg2);border:1px solid var(--b1);border-radius:4px;padding:1px 7px;flex-shrink:0">${esc(v.cwe)}</span>` : ''}
      ${v.target_host ? `<span class="vuln-tag" style="color:var(--a);border-color:var(--a)33">${esc(v.target_host)}</span>` : ''}
      ${v.ai_generated ? `<span style="font-family:var(--mono);font-size:10px;font-weight:600;color:var(--a);background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.3);border-radius:4px;padding:1px 7px;flex-shrink:0;display:inline-flex;align-items:center;gap:3px" title="Propuesto por el AI Agent">${icon('sparkles',{size:10})}AI</span>` : ''}
      ${(v.remediation_status && v.remediation_status !== 'open') ? remediationBadge(v.remediation_status) : ''}
      <span class="vuln-name">${esc(v.name)}</span>
      ${editorBadge}
      <div class="vuln-actions">
        <button class="btn-icon edit" onclick="openEditVuln('${v.id}',event)">${icon('square-pen',{size:12})}</button>
        <button class="btn-icon delete" onclick="deleteVuln('${v.id}',event)">${icon('x',{size:12})}</button>
      </div>
    </div>
    <div class="vuln-body" id="vbody-${v.id}">${descH}${itemsH}${payH}${noteH}${remH}${remH2}${evidH}${httpH}</div>`;
  return card;
}

function openEvidenceViewer(vulnId, idx) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v?.evidence?.[idx]) return;
  const img = v.evidence[idx];
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:#000d;z-index:9999;display:flex;align-items:center;justify-content:center;cursor:zoom-out';
  overlay.innerHTML = `<div style="max-width:90vw;max-height:90vh;display:flex;flex-direction:column;gap:8px" onclick="event.stopPropagation()">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:#fff;font-family:var(--mono);font-size:11px">${esc(img.name||'evidence')}</span>
      <button onclick="this.closest('[style*=fixed]').remove()"
        style="background:none;border:none;color:#fff;cursor:pointer;padding:4px 8px">${icon('x',{size:20})}</button>
    </div>
    <img src="${img.data}" style="max-width:88vw;max-height:85vh;object-fit:contain;border-radius:8px">
  </div>`;
  overlay.addEventListener('click', () => overlay.remove());
  document.body.appendChild(overlay);
}

function toggleVulnBody(id, e) {
  if (e.target.closest('.vuln-actions,.test-check')) return;
  document.getElementById(`vbody-${id}`)?.classList.toggle('open');
}

async function cycleVulnStatus(id, e) {
  e.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  const next = v.status === 'done' ? 'fail' : v.status === 'fail' ? null : 'done';
  try {
    const updated = await api.vulns.update(state.currentProject.id, id, { status: next });
    Object.assign(v, updated);
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
  } catch(err) { showToast(err.message, 'error'); }
}

async function setRemediationStatus(vulnId, status) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  try {
    const updated = await api.vulns.setRemediation(state.currentProject.id, vulnId, { remediation_status: status });
    updated.verifier_username = status === 'verified_closed' ? state.user.username : null;
    Object.assign(v, updated);
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
    const msg = status === 'verified_closed' ? 'Verificado y cerrado' : status === 'remediated' ? 'Marcado como remediado' : 'Reabierto';
    showToast(msg, 'success');
  } catch(err) { showToast(err.message, 'error'); }
}

async function setRetestDate(vulnId, date) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  try {
    const updated = await api.vulns.setRemediation(state.currentProject.id, vulnId, {
      remediation_status: v.remediation_status || 'open', retest_date: date || null, retest_notes: v.retest_notes || null,
    });
    Object.assign(v, updated);
  } catch(err) { showToast(err.message, 'error'); }
}

async function setRetestNotes(vulnId, notes) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  try {
    const updated = await api.vulns.setRemediation(state.currentProject.id, vulnId, {
      remediation_status: v.remediation_status || 'open', retest_date: v.retest_date || null, retest_notes: notes,
    });
    Object.assign(v, updated);
  } catch(err) { showToast(err.message, 'error'); }
}

async function toggleCustomItem(vulnId, idx, el) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const cur = v.checked_items?.[idx] || false;
  const newChecked = { ...v.checked_items, [idx]: !cur };
  try {
    await api.vulns.update(state.currentProject.id, vulnId, { checked_items: newChecked });
    v.checked_items = newChecked;
    el.classList.toggle('checked', !cur);
    el.innerHTML = !cur ? icon('check',{size:11}) : '';
    el.nextElementSibling?.classList.toggle('done', !cur);
  } catch(err) { showToast(err.message, 'error'); }
}

// ── Modal (operational data only) ───────────────────────────────────
function openAddVulnModal() {
  _editingVulnId = null;
  document.getElementById('modal-title').textContent       = 'Add Vulnerability';
  document.getElementById('modal-vuln-name').value         = '';
  document.getElementById('modal-vuln-cat').value          = '';
  document.getElementById('modal-vuln-cwe').value          = '';
  document.getElementById('modal-vuln-sev').value          = 'medium';
  document.getElementById('modal-vuln-notes').value        = '';
  document.getElementById('modal-vuln-desc').value         = '';
  document.getElementById('modal-vuln-rem').value          = '';
  populateTargetSelect(null);
  document.getElementById('modal-items-list').innerHTML    = '';
  document.getElementById('modal-payloads-list').innerHTML = '';
  document.getElementById('vuln-error').style.display      = 'none';
  addModalRow('modal-items-list', 'Check item...');
  addModalRow('modal-payloads-list', 'Payload...', true);
  _initCVSS(null);
  if (window.cselSync) window.cselSync();
  document.getElementById('vuln-modal').classList.add('open');
}

function openEditVuln(id, e) {
  e.stopPropagation();
  const v = state.customVulns.find(x => x.id === id);
  if (!v) return;
  _editingVulnId = id;
  document.getElementById('modal-title').textContent      = 'Edit Vulnerability';
  document.getElementById('modal-vuln-name').value        = v.name;
  document.getElementById('modal-vuln-cat').value         = v.category || '';
  document.getElementById('modal-vuln-cwe').value         = v.cwe || '';
  document.getElementById('modal-vuln-sev').value         = v.severity || 'medium';
  document.getElementById('modal-vuln-notes').value       = v.notes || '';
  document.getElementById('modal-vuln-desc').value        = v.description || '';
  document.getElementById('modal-vuln-rem').value         = v.remediation || '';
  populateTargetSelect(v.target_id || null);
  document.getElementById('vuln-error').style.display     = 'none';
  const iList = document.getElementById('modal-items-list');
  const pList = document.getElementById('modal-payloads-list');
  iList.innerHTML = ''; pList.innerHTML = '';
  (v.items||[]).forEach(item => { addModalRow('modal-items-list','Check item...'); iList.lastChild.querySelector('input').value = item; });
  if (!v.items?.length) addModalRow('modal-items-list','Check item...');
  (v.payloads||[]).forEach(p => { addModalRow('modal-payloads-list','Payload...',true); pList.lastChild.querySelector('textarea').value = p; });
  if (!v.payloads?.length) addModalRow('modal-payloads-list','Payload...',true);
  _initCVSS(v.cvss_vector || null);
  if (window.cselSync) window.cselSync();
  document.getElementById('vuln-modal').classList.add('open');
}

function addModalRow(containerId, ph, isTextarea = false) {
  const row = document.createElement('div');
  row.className = 'dynamic-row';
  const field = isTextarea
    ? `<textarea class="dynamic-textarea" placeholder="${esc(ph)}"></textarea>`
    : `<input type="text" class="dynamic-input" placeholder="${esc(ph)}">`;
  row.innerHTML = `${field}<button class="btn-remove" onclick="this.parentElement.remove()">${icon('x',{size:11})}</button>`;
  document.getElementById(containerId).appendChild(row);
}

function closeVulnModal() {
  document.getElementById('vuln-modal').classList.remove('open');
  _editingVulnId = null;
}

async function saveVuln() {
  const name     = document.getElementById('modal-vuln-name').value.trim();
  const category = document.getElementById('modal-vuln-cat').value.trim();
  const cwe      = document.getElementById('modal-vuln-cwe').value.trim();
  const severity = document.getElementById('modal-vuln-sev').value;
  const notes    = document.getElementById('modal-vuln-notes').value;
  const err      = document.getElementById('vuln-error');
  const btn      = document.getElementById('vuln-save-btn');
  if (!name) { err.textContent = 'Name is required'; err.style.display = 'block'; return; }
  const description = document.getElementById('modal-vuln-desc').value;
  const remediation = document.getElementById('modal-vuln-rem').value;
  const items    = [...document.querySelectorAll('#modal-items-list .dynamic-input')].map(i => i.value.trim()).filter(Boolean);
  const payloads = [...document.querySelectorAll('#modal-payloads-list .dynamic-textarea')].map(i => i.value.trim()).filter(Boolean);
  btn.disabled = true;
  try {
    const target_id = document.getElementById('modal-vuln-target')?.value || null;
    const payload = { name, category: category||'Custom', severity, items, payloads, notes, description, remediation, target_id: target_id||null, cwe: cwe||null };
    if (_cvssModified) {
      if (_cvssCleared) {
        payload.cvss_vector = null;
        payload.cvss_score  = null;
      } else {
        payload.cvss_vector = buildCVSSVector(_cvss);
        payload.cvss_score  = calcCVSSScore(_cvss);
      }
    }
    if (_editingVulnId) {
      const updated = await api.vulns.update(state.currentProject.id, _editingVulnId, payload);
      const idx = state.customVulns.findIndex(v => v.id === _editingVulnId);
      if (idx > -1) state.customVulns[idx] = { ...state.customVulns[idx], ...updated };
    } else {
      const created = await api.vulns.create(state.currentProject.id, payload);
      state.customVulns.push(created);
    }
    closeVulnModal();
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
    showToast('Saved', 'success');
  } catch(e) { err.textContent = e.message; err.style.display = 'block'; }
  finally { btn.disabled = false; }
}

// ── AI helpers ───────────────────────────────────────────────────────
async function _aiGenerate(type, context, btnId, btnLabel) {
  const btn = document.getElementById(btnId);
  if (btn) { btn.disabled = true; btn.classList.add('loading'); btn.textContent = '…'; }
  try {
    return await request('POST', `/projects/${state.currentProject.id}/ai/generate`, { type, context });
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove('loading'); btn.innerHTML = `${icon('sparkles',{size:11})} ${btnLabel}`.trim(); }
  }
}

function _collectVulnContext() {
  const targetSel = document.getElementById('modal-vuln-target');
  const targetHost = targetSel?.selectedOptions?.[0]?.text?.replace(/^[^\s]+\s/, '') || '';
  const payloads = [...document.querySelectorAll('#modal-payloads-list .dynamic-textarea')]
    .map(i => i.value.trim()).filter(Boolean);
  return {
    name:        document.getElementById('modal-vuln-name').value.trim(),
    category:    document.getElementById('modal-vuln-cat').value.trim(),
    notes:       document.getElementById('modal-vuln-notes').value.trim(),
    description: document.getElementById('modal-vuln-desc').value.trim(),
    target:      targetHost === '— No target —' ? '' : targetHost,
    payloads,
  };
}

async function aiDraft() {
  const ctx = _collectVulnContext();
  if (!ctx.name) { showToast('Enter a name first', 'error'); return; }
  try {
    const result = await _aiGenerate('vuln-draft', ctx, 'ai-draft-btn', 'Draft');
    if (result.name)        document.getElementById('modal-vuln-name').value = result.name;
    if (result.category)    document.getElementById('modal-vuln-cat').value  = result.category;
    if (result.severity)    { document.getElementById('modal-vuln-sev').value  = result.severity; if (window.cselSync) window.cselSync(); }
    if (result.description) document.getElementById('modal-vuln-desc').value = result.description;
    if (result.remediation) document.getElementById('modal-vuln-rem').value  = result.remediation;
    showToast('Draft generated', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiRemediation() {
  const ctx = _collectVulnContext();
  if (!ctx.name && !ctx.description) { showToast('Add a name or description first', 'error'); return; }
  try {
    const result = await _aiGenerate('remediation', ctx, 'ai-rem-btn', 'Suggest');
    if (result.remediation) document.getElementById('modal-vuln-rem').value = result.remediation;
    showToast('Remediation generated', 'success');
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiSeverity() {
  const ctx = _collectVulnContext();
  if (!ctx.name) { showToast('Enter a name first', 'error'); return; }
  try {
    const result = await _aiGenerate('severity-suggest', { name: ctx.name, category: ctx.category }, 'ai-sev-btn', 'Suggest');
    if (result.severity) {
      document.getElementById('modal-vuln-sev').value = result.severity;
      if (window.cselSync) window.cselSync();
      showToast(`${result.severity.charAt(0).toUpperCase() + result.severity.slice(1)}${result.reason ? ' — ' + result.reason : ''}`, 'success');
    }
  } catch(e) { showToast(e.message, 'error'); }
}

async function aiCWE() {
  const ctx = _collectVulnContext();
  if (!ctx.name) { showToast('Enter a name first', 'error'); return; }
  try {
    const result = await _aiGenerate('cwe', ctx, 'ai-cwe-btn', '');
    if (result.cwe) {
      document.getElementById('modal-vuln-cwe').value = result.cwe;
      showToast(`${result.cwe}${result.cwe_name ? ' — ' + result.cwe_name : ''}`, 'success');
    }
  } catch(e) { showToast(e.message, 'error'); }
}

async function deleteVuln(id, e) {
  e.stopPropagation();
  if (!confirm('Delete this vulnerability?')) return;
  try {
    await api.vulns.delete(state.currentProject.id, id);
    state.customVulns = state.customVulns.filter(v => v.id !== id);
    renderCustomVulns();
    if (typeof updateDashboard === 'function') updateDashboard();
    showToast('Deleted', 'error');
  } catch(err) { showToast(err.message, 'error'); }
}

function populateTargetSelect(selectedId) {
  const sel = document.getElementById('modal-vuln-target');
  if (!sel) return;
  const inScope = (state.targets||[]).filter(t => t.scope==='in');
  sel.innerHTML = '<option value="">— No target —</option>' +
    inScope.map(t => `<option value="${t.id}" ${t.id===selectedId?'selected':''}>${esc(t.host)}</option>`).join('');
  if (window.reinitCsel) window.reinitCsel('modal-vuln-target');
}

// ── Import Scan ─────────────────────────────────────────────────────────
let _importFile = null;

function openImportModal() {
  _importFile = null;
  document.getElementById('import-filename').textContent     = '';
  document.getElementById('import-error').textContent        = '';
  document.getElementById('import-file-input').value         = '';
  document.getElementById('import-submit-btn').style.display = 'none';
  document.getElementById('import-idle').style.display       = '';
  document.getElementById('import-loading').style.display    = 'none';
  document.getElementById('import-result').style.display     = 'none';
  document.getElementById('import-modal').classList.add('open');
}

function closeImportModal() {
  document.getElementById('import-modal').classList.remove('open');
}

function handleImportFile(file) {
  if (!file) return;
  const ext = file.name.toLowerCase();
  if (!ext.endsWith('.xml') && !ext.endsWith('.nessus')) {
    document.getElementById('import-error').textContent = 'Please select an XML or .nessus file.';
    return;
  }
  _importFile = file;
  document.getElementById('import-filename').textContent    = file.name;
  document.getElementById('import-error').textContent       = '';
  document.getElementById('import-submit-btn').style.display = '';
}

function handleImportDrop(e) {
  e.preventDefault();
  document.getElementById('import-drop-zone').style.borderColor = 'var(--br1)';
  const file = e.dataTransfer?.files?.[0];
  if (file) handleImportFile(file);
}

async function submitImport() {
  if (!_importFile) return;
  const pid = state.currentProject?.id;
  document.getElementById('import-idle').style.display       = 'none';
  document.getElementById('import-loading').style.display    = '';
  document.getElementById('import-submit-btn').style.display = 'none';

  try {
    const res = await api.import.scan(pid, _importFile);
    document.getElementById('import-loading').style.display  = 'none';
    document.getElementById('import-result').style.display   = '';

    const toolName = { burp: 'Burp Suite', nessus: 'Nessus', zap: 'OWASP ZAP', nmap: 'Nmap' }[res.format] || 'scanner';
    // Nmap no reporta vulnerabilidades — a diferencia de los otros 3
    // formatos, puebla puertos/servicios directamente (ver import.js
    // parseNmap), así que "imported" cuenta puertos, no findings.
    const unit = res.format === 'nmap' ? 'port' : 'finding';
    let text = `Imported <strong>${res.imported}</strong> ${unit}${res.imported !== 1 ? 's' : ''} from ${toolName}`;
    if (res.targets_created > 0)
      text += ` · Created <strong>${res.targets_created}</strong> new target${res.targets_created !== 1 ? 's' : ''}`;
    document.getElementById('import-result-msg').innerHTML = text;

    // Reportado tarde en revisión: un import podía crear targets nuevos
    // (cualquiera de los 4 formatos) sin que state.targets se enterara —
    // quedaban invisibles en el resto de la app (selector de la AI Agent,
    // conteos del dashboard, etc.) hasta un reload completo de la página.
    const [freshVulns, freshTargets] = await Promise.all([api.vulns.list(pid), api.targets.list(pid)]);
    state.customVulns = freshVulns.vulns || freshVulns;
    state.targets = freshTargets;
    renderCustomVulns();
    showToast(`Imported ${res.imported} ${unit}${res.imported !== 1 ? 's' : ''} from ${toolName}`, 'success');
  } catch (err) {
    document.getElementById('import-loading').style.display    = 'none';
    document.getElementById('import-idle').style.display       = '';
    document.getElementById('import-error').textContent        = err.message || 'Import failed';
    document.getElementById('import-submit-btn').style.display = '';
  }
}

async function toggleHttpProofInclude(vulnId, idx, checked) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const proofs = (v.http_proofs || []).map((p, i) => i === idx ? { ...p, include: checked } : p);
  v.http_proofs = proofs;
  await api.vulns.update(state.currentProject.id, vulnId, { http_proofs: proofs });
}

function editHttpProof(vulnId, idx) {
  const v = state.customVulns.find(x => x.id === vulnId);
  if (!v) return;
  const proof = (v.http_proofs || [])[idx];
  if (!proof) return;

  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:9999;display:flex;align-items:center;justify-content:center';

  const modal = document.createElement('div');
  modal.style.cssText = 'background:var(--bg2);border:1px solid var(--b2);border-radius:10px;padding:20px;width:700px;max-width:95vw;max-height:90vh;display:flex;flex-direction:column;gap:12px';

  const taStyle = 'width:100%;font-family:var(--mono);font-size:11px;background:var(--bg);border:1px solid var(--b2);border-radius:6px;color:var(--t1);padding:8px;resize:vertical;line-height:1.5;box-sizing:border-box';

  const reqTA = document.createElement('textarea');
  reqTA.style.cssText = taStyle; reqTA.style.height = '180px';
  reqTA.value = proof.request || '';

  const resTA = document.createElement('textarea');
  resTA.style.cssText = taStyle; resTA.style.height = '180px';
  resTA.value = proof.response || '';

  const annTA = document.createElement('textarea');
  annTA.style.cssText = taStyle; annTA.style.height = '80px'; annTA.style.fontFamily = 'inherit';
  annTA.placeholder = 'Ej: El parámetro `name` en la línea 3 se refleja sin sanitizar. Payload: `<script>alert(1)</script>`';
  annTA.value = proof.annotation || '';

  modal.innerHTML = `
    <div style="font-size:13px;font-weight:600;color:var(--t1)">
      Editar HTTP Proof #${idx+1}
      <span style="font-family:var(--mono);font-size:10px;color:var(--t3);margin-left:8px">${esc(proof.method||'HTTP')}</span>
    </div>
    <div style="overflow-y:auto;flex:1;display:flex;flex-direction:column;gap:10px;min-height:0">
      <div>
        <div class="http-proof-section-label" style="margin-bottom:4px">Request</div>
        <div id="hp-req-slot"></div>
      </div>
      <div>
        <div class="http-proof-section-label" style="margin-bottom:4px">Response</div>
        <div id="hp-res-slot"></div>
      </div>
      <div>
        <div class="http-proof-section-label" style="margin-bottom:4px">Anotación <span style="text-transform:none;letter-spacing:0;font-size:9px;color:var(--t3)">(markdown)</span></div>
        <div id="hp-ann-slot"></div>
      </div>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;flex-shrink:0">
      <button id="hp-cancel" style="padding:6px 14px;background:var(--bg3);border:1px solid var(--b2);border-radius:6px;color:var(--t2);font-size:12px;cursor:pointer">Cancelar</button>
      <button id="hp-save"   style="padding:6px 14px;background:var(--a);border:none;border-radius:6px;color:#fff;font-size:12px;cursor:pointer;font-weight:600">Guardar</button>
    </div>`;

  modal.querySelector('#hp-req-slot').appendChild(reqTA);
  modal.querySelector('#hp-res-slot').appendChild(resTA);
  modal.querySelector('#hp-ann-slot').appendChild(annTA);
  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  modal.querySelector('#hp-cancel').onclick = () => overlay.remove();
  overlay.onclick = e => { if (e.target === overlay) overlay.remove(); };

  modal.querySelector('#hp-save').onclick = async () => {
    const proofs = (v.http_proofs || []).map((p, i) =>
      i === idx ? { ...p, request: reqTA.value, response: resTA.value, annotation: annTA.value } : p
    );
    v.http_proofs = proofs;
    await api.vulns.update(state.currentProject.id, vulnId, { http_proofs: proofs });
    overlay.remove();
    const card = document.getElementById(`vuln-${vulnId}`);
    if (card) card.replaceWith(buildVulnCard(v));
  };
}

window.setCVSSMetric      = setCVSSMetric;
window.toggleCVSSSection  = toggleCVSSSection;
window.copyCVSSVector     = copyCVSSVector;
window.clearCVSS          = clearCVSS;
window.renderCustomVulns  = renderCustomVulns;
window.buildVulnCard      = buildVulnCard;
window.openEvidenceViewer = openEvidenceViewer;
window.toggleVulnBody     = toggleVulnBody;
window.cycleVulnStatus    = cycleVulnStatus;
window.toggleCustomItem   = toggleCustomItem;
window.setRemediationStatus = setRemediationStatus;
window.setRetestDate         = setRetestDate;
window.setRetestNotes        = setRetestNotes;
window.openAddVulnModal   = openAddVulnModal;
window.openEditVuln       = openEditVuln;
window.addModalRow        = addModalRow;
window.closeVulnModal     = closeVulnModal;
window.saveVuln           = saveVuln;
window.deleteVuln         = deleteVuln;
window.severityBadge      = severityBadge;
window.SEVERITY_ORDER     = SEVERITY_ORDER;
window.SEVERITY_LABELS    = SEVERITY_LABELS;
window.aiDraft            = aiDraft;
window.aiRemediation      = aiRemediation;
window.aiCWE              = aiCWE;
window.aiSeverity         = aiSeverity;
window.openImportModal        = openImportModal;
window.closeImportModal       = closeImportModal;
window.handleImportFile       = handleImportFile;
window.handleImportDrop       = handleImportDrop;
window.submitImport           = submitImport;
window.toggleHttpProofInclude = toggleHttpProofInclude;
window.editHttpProof          = editHttpProof;