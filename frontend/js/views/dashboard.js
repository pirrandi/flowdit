// ── views/dashboard.js ───────────────────────────────────────────────

let _confettiFired = false;
let _vulnIdMap = {};
let _drwPayloads = []; // current drawer's payloads, indexed by onclick

function copyDrwPayload(i) {
  const p = _drwPayloads[i];
  if (p == null) return;
  navigator.clipboard.writeText(p).then(() => showToast('Copied', 'info'));
}
window.copyDrwPayload = copyDrwPayload;

function _parseCVSS(vec) {
  if (!vec?.startsWith('CVSS:3.1/')) return null;
  const r = {};
  vec.replace('CVSS:3.1/','').split('/').forEach(p => { const [k,v] = p.split(':'); r[k] = v; });
  return r;
}

// ── VULN DRAWER ───────────────────────────────────────────────────────

function _mountVulnDrawer() {
  if (document.getElementById('vuln-drw')) return;
  const bd = document.createElement('div');
  bd.className = 'drw-backdrop';
  bd.id = 'vuln-drw-backdrop';
  bd.onclick = closeVulnDrawer;

  const drw = document.createElement('div');
  drw.className = 'drw';
  drw.id = 'vuln-drw';
  drw.innerHTML = `
    <div class="drw-head" id="vuln-drw-head"></div>
    <div class="drw-body" id="vuln-drw-body"></div>
  `;
  document.body.appendChild(bd);
  document.body.appendChild(drw);
}

function openVulnDrawer(vulnId) {
  _mountVulnDrawer();
  const vuln    = (state.customVulns || []).find(v => v.id === vulnId);
  if (!vuln) return;
  const vid     = _vulnIdMap[vulnId] || '—';
  const sev     = vuln.severity || 'medium';
  const stMap   = { done: { cls:'done', label:`${icon('check',{size:11})} confirmed` }, fail: { cls:'fail', label:`${icon('x',{size:11})} vulnerable` } };
  const st      = stMap[vuln.status] || { cls:'open', label:'open' };
  const cvss    = vuln.cvss_score ? String(parseFloat(vuln.cvss_score).toFixed(1)) : null;
  const target  = (state.targets || []).find(t => t.id === vuln.target_id);

  document.getElementById('vuln-drw-head').innerHTML = `
    <button class="drw-close" onclick="closeVulnDrawer()">${icon('x', { size: 16 })}</button>
    <div class="drw-id">
      <code>${vid}</code>
      <span class="sev ${sev}">${sev}</span>
      <span class="status ${st.cls}"><span class="dot"></span>${st.label}</span>
    </div>
    <div class="drw-title">${esc(vuln.name)}</div>
    <div class="drw-meta">
      ${cvss ? `<span style="font-family:var(--mono);font-size:11px;color:var(--t2)">CVSS <strong style="color:var(--t1)">${cvss}</strong></span>` : ''}
      ${vuln.cwe ? `<span style="font-family:var(--mono);font-size:11px;color:var(--t3)">${esc(vuln.cwe)}</span>` : ''}
      ${target ? `<span style="font-family:var(--mono);font-size:11px;color:var(--t3)">${esc(target.host)}</span>` : ''}
    </div>
  `;

  const body = document.getElementById('vuln-drw-body');
  let html = '';

  // ── CVSS breakdown ───────────────────────────────────────────────────
  if (cvss && vuln.cvss_vector) {
    const m = _parseCVSS(vuln.cvss_vector);
    if (m) {
      const rows = [
        { group: 'Exploitability' },
        { label: 'Attack Vector',       val: { N:'Network', A:'Adjacent Network', L:'Local', P:'Physical' }[m.AV], risk: { N:3, A:2, L:1, P:0 }[m.AV] },
        { label: 'Attack Complexity',   val: { L:'Low', H:'High' }[m.AC], risk: { L:2, H:0 }[m.AC] },
        { label: 'Privileges Required', val: { N:'None', L:'Low', H:'High' }[m.PR], risk: { N:2, L:1, H:0 }[m.PR] },
        { label: 'User Interaction',    val: { N:'None', R:'Required' }[m.UI], risk: { N:2, R:0 }[m.UI] },
        { label: 'Scope',               val: { U:'Unchanged', C:'Changed' }[m.S],  risk: { C:2, U:0 }[m.S] },
        { group: 'Impact' },
        { label: 'Confidentiality',     val: { N:'None', L:'Low', H:'High' }[m.C], risk: { H:3, L:1, N:0 }[m.C] },
        { label: 'Integrity',           val: { N:'None', L:'Low', H:'High' }[m.I], risk: { H:3, L:1, N:0 }[m.I] },
        { label: 'Availability',        val: { N:'None', L:'Low', H:'High' }[m.A], risk: { H:3, L:1, N:0 }[m.A] },
      ];
      const riskColor = r => r >= 3 ? 'var(--c-crit)' : r === 2 ? 'var(--c-high)' : r === 1 ? 'var(--c-med)' : 'var(--t3)';
      const tableRows = rows.map(r => {
        if (r.group) return `<tr><td colspan="2" style="padding:8px 0 3px;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--t4);font-weight:700;border:none">${r.group}</td></tr>`;
        return `<tr>
          <td style="padding:4px 0;font-size:11px;color:var(--t2);border-bottom:1px solid var(--b1);width:55%">${r.label}</td>
          <td style="padding:4px 0;border-bottom:1px solid var(--b1)">
            <span style="font-family:var(--mono);font-size:11px;font-weight:600;color:${riskColor(r.risk)}">${r.val || '—'}</span>
          </td>
        </tr>`;
      }).join('');
      html += `<div class="drw-sec">
        <div class="drw-sec-label" style="display:flex;align-items:center;gap:8px">
          CVSS v3.1
          <span style="font-family:var(--mono);font-size:10px;color:var(--t3);font-weight:400">${esc(vuln.cvss_vector)}</span>
        </div>
        <table style="width:100%;border-collapse:collapse">${tableRows}</table>
      </div>`;
    }
  }

  if (vuln.description) {
    html += `<div class="drw-sec">
      <div class="drw-sec-label">Description</div>
      <div class="drw-prose">${renderMd(vuln.description)}</div>
    </div>`;
  }

  if (vuln.remediation) {
    html += `<div class="drw-sec">
      <div class="drw-sec-label">Remediation</div>
      <div class="drw-prose">${renderMd(vuln.remediation)}</div>
    </div>`;
  }

  // ── Checklist items ──────────────────────────────────────────────────
  const items = Array.isArray(vuln.items) ? vuln.items.filter(Boolean) : [];
  if (items.length) {
    const checked = vuln.checked_items || {};
    html += `<div class="drw-sec">
      <div class="drw-sec-label">Checklist</div>
      <div style="display:flex;flex-direction:column;gap:4px">
        ${items.map((item, i) => {
          const done = !!checked[i];
          return `<div style="display:flex;align-items:flex-start;gap:8px;padding:3px 0">
            <span style="width:14px;flex-shrink:0;color:${done ? 'var(--c-low)' : 'var(--t4)'};margin-top:1px">${done ? icon('check', { size: 12 }) : icon('circle', { size: 10 })}</span>
            <span style="font-size:12px;color:${done ? 'var(--t3)' : 'var(--t1)'};text-decoration:${done ? 'line-through' : 'none'}">${esc(item)}</span>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }

  // ── Payloads ─────────────────────────────────────────────────────────
  _drwPayloads = Array.isArray(vuln.payloads) ? vuln.payloads.filter(Boolean) : [];
  if (_drwPayloads.length) {
    html += `<div class="drw-sec">
      <div class="drw-sec-label">Payloads</div>
      <div style="display:flex;flex-direction:column;gap:6px">
        ${_drwPayloads.map((p, i) => `
          <div style="position:relative;background:var(--bg);border:1px solid var(--b1);border-radius:var(--r);padding:8px 48px 8px 10px">
            <pre style="margin:0;font-family:var(--mono);font-size:11px;color:var(--t1);white-space:pre-wrap;word-break:break-all;line-height:1.5">${esc(p)}</pre>
            <button onclick="copyDrwPayload(${i})"
              style="position:absolute;top:6px;right:6px;font-family:var(--mono);font-size:9px;color:var(--t3);background:var(--bg2);border:1px solid var(--b1);border-radius:var(--r-sm);padding:2px 6px;cursor:pointer">copy</button>
          </div>`).join('')}
      </div>
    </div>`;
  }

  if (vuln.notes) {
    html += `<div class="drw-sec">
      <div class="drw-sec-label">Notes</div>
      <div class="drw-prose">${renderMd(vuln.notes)}</div>
    </div>`;
  }

  const evidence = Array.isArray(vuln.evidence) ? vuln.evidence : [];
  if (evidence.length) {
    html += `<div class="drw-sec">
      <div class="drw-sec-label">Evidence (${evidence.length})</div>
      <div style="display:flex;flex-direction:column;gap:8px">
        ${evidence.map(ev => `
          <div style="border:1px solid var(--b1);border-radius:var(--r);overflow:hidden">
            ${ev.type === 'image' || ev.url?.match(/\.(png|jpg|jpeg|gif|webp)$/i) || ev.dataUrl
              ? `<img src="${esc(ev.dataUrl || ev.url)}" style="width:100%;display:block;max-height:300px;object-fit:contain;background:var(--bg)">`
              : `<div style="padding:8px 12px;font-family:var(--mono);font-size:10px;color:var(--t2)">${esc(ev.url||ev.name||'file')}</div>`}
            ${ev.caption ? `<div style="padding:6px 12px;font-size:11px;color:var(--t3);border-top:1px solid var(--b1)">${esc(ev.caption)}</div>` : ''}
          </div>`).join('')}
      </div>
    </div>`;
  }

  if (!html) {
    html = `<div style="color:var(--t3);font-size:12px;text-align:center;padding:32px 0">No additional details.</div>`;
  }

  html += `<div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--b1)">
    <a href="vulns?pid=${esc(state.currentProject?.id)}" class="btn btn-ghost" style="font-size:11px">
      Abrir en Findings ${icon('arrow-right', { size: 11 })}
    </a>
  </div>`;

  body.innerHTML = html;

  const _bd  = document.getElementById('vuln-drw-backdrop');
  const _drw = document.getElementById('vuln-drw');
  _drw.offsetHeight; // force reflow so the initial translateX(100%) is painted first
  _bd.classList.add('open');
  _drw.classList.add('open');
}

function closeVulnDrawer() {
  document.getElementById('vuln-drw-backdrop')?.classList.remove('open');
  document.getElementById('vuln-drw')?.classList.remove('open');
}

// ── FINDINGS OVER TIME (stacked area, cumulative by severity) ─────────
const SEV_COLOR = { critical:'var(--c-crit)', high:'var(--c-high)', medium:'var(--c-med)', low:'var(--c-low)', info:'var(--c-info)' };
const SEV_STACK = ['info','low','medium','high','critical']; // bottom → top
const TREND_W = 760, TREND_H = 150, TREND_PAD_TOP = 10, TREND_PAD_BOTTOM = 26, TREND_PAD_X = 4;
const TREND_PLOT_W = TREND_W - TREND_PAD_X * 2;
const TREND_PLOT_H = TREND_H - TREND_PAD_TOP - TREND_PAD_BOTTOM;

let _trendPoints = [];

function _dayKey(d) { return d.toISOString().slice(0, 10); }
function _fmtDay(key) {
  const [y, m, d] = key.split('-').map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { month:'short', day:'numeric' });
}
function _trendY(v, maxY) { return TREND_PAD_TOP + TREND_PLOT_H - (v / maxY) * TREND_PLOT_H; }

// A rect path with only its top corners rounded — the "data end" cap sits on
// the outermost segment of a stack; the segments below it stay square and are
// separated from their neighbor by a 2px surface gap (see BAR_GAP below).
function _roundedTopRect(x, y, w, h, r) {
  r = Math.min(r, h / 2, w / 2);
  if (r <= 0) return `M${x},${y} h${w} v${h} h${-w} Z`;
  return `M${x},${y+r} Q${x},${y} ${x+r},${y} H${x+w-r} Q${x+w},${y} ${x+w},${y+r} V${y+h} H${x} Z`;
}

function renderSeverityTrend(vulns) {
  if (!vulns.length) return '';

  const byDay = {};
  vulns.forEach(v => {
    const key = _dayKey(v.created_at ? new Date(v.created_at) : new Date());
    if (!byDay[key]) byDay[key] = { critical:0, high:0, medium:0, low:0, info:0 };
    const s = v.severity || 'medium';
    if (byDay[key][s] !== undefined) byDay[key][s]++;
  });

  // Grouped daily bars: each bar shows findings NEW that day (not a running
  // total), stacked by severity within the bar. A single day renders fine as
  // one bar — no need to fabricate an extra day like the line/area charts did.
  const days = Object.keys(byDay).sort();
  const totals = { critical:0, high:0, medium:0, low:0, info:0 };
  const slotW = TREND_PLOT_W / days.length;
  const points = days.map((day, i) => {
    const added = byDay[day];
    SEV_STACK.forEach(s => totals[s] += added[s]);
    const dayTotal = SEV_STACK.reduce((sum, s) => sum + added[s], 0);
    return { day, added, dayTotal, x: TREND_PAD_X + slotW * (i + 0.5) };
  });
  _trendPoints = points;

  const total    = SEV_STACK.reduce((sum, s) => sum + totals[s], 0);
  const niceMax  = Math.max(1, Math.max(...points.map(p => p.dayTotal)));
  const maxY     = Math.max(1, Math.ceil(niceMax * 1.15));
  const barW     = Math.min(24, slotW * 0.55);
  const BAR_GAP  = 2; // surface gap between stacked segments, never a stroke

  const bars = points.map(p => {
    const segs = SEV_STACK.filter(s => p.added[s] > 0);
    let acc = 0;
    return segs.map((s, si) => {
      const isBottom = si === 0;
      const isTop    = si === segs.length - 1;
      const rawY0 = _trendY(acc, maxY);
      acc += p.added[s];
      const rawY1 = _trendY(acc, maxY);
      const y1 = rawY1 + (isTop ? 0 : BAR_GAP / 2);
      const y0 = rawY0 - (isBottom ? 0 : BAR_GAP / 2);
      const h  = Math.max(0.5, y0 - y1);
      const x  = p.x - barW / 2;
      return isTop
        ? `<path class="trend-bar-seg" d="${_roundedTopRect(x, y1, barW, h, 4)}" fill="${SEV_COLOR[s]}"></path>`
        : `<rect class="trend-bar-seg" x="${x.toFixed(1)}" y="${y1.toFixed(1)}" width="${barW.toFixed(1)}" height="${h.toFixed(1)}" fill="${SEV_COLOR[s]}"></rect>`;
    }).join('');
  }).join('');

  const totalLabels = points.map(p =>
    `<text class="trend-bar-total" x="${p.x.toFixed(1)}" y="${(_trendY(p.dayTotal, maxY) - 6).toFixed(1)}">${p.dayTotal}</text>`
  ).join('');

  const gridLineYs = [niceMax * 0.5, niceMax].map(v => _trendY(v, maxY));

  const labelCount = Math.min(points.length, 5);
  const labelIdxs  = new Set();
  for (let i = 0; i < labelCount; i++) labelIdxs.add(Math.round(i * (points.length - 1) / (labelCount - 1 || 1)));

  return `
    <div class="section">
      <div class="section-head">
        <div class="section-title">Findings Over Time</div>
        <span style="font-size:10px;color:var(--t3)">${total} total</span>
      </div>
      <div class="section-body" style="position:relative">
        <svg class="trend-chart-svg" viewBox="0 0 ${TREND_W} ${TREND_H}" preserveAspectRatio="none" onmouseleave="hideTrendTooltip()">
          ${gridLineYs.map(y => `<line class="trend-grid-line" x1="${TREND_PAD_X}" x2="${TREND_W - TREND_PAD_X}" y1="${y.toFixed(1)}" y2="${y.toFixed(1)}"></line>`).join('')}
          <line class="trend-baseline" x1="${TREND_PAD_X}" x2="${TREND_W - TREND_PAD_X}" y1="${_trendY(0, maxY).toFixed(1)}" y2="${_trendY(0, maxY).toFixed(1)}"></line>
          <rect class="trend-hover-col" id="trend-cursor" x="0" y="${TREND_PAD_TOP}" width="${(barW + 10).toFixed(1)}" height="${TREND_PLOT_H}" rx="4"></rect>
          ${bars}
          ${totalLabels}
          ${points.map((p, i) => `<rect class="trend-hit" x="${(p.x - slotW/2).toFixed(1)}" y="0" width="${slotW.toFixed(1)}" height="${TREND_H}" onmouseenter="showTrendTooltip(${i}, event)"></rect>`).join('')}
          ${[...labelIdxs].map(i => `<text class="trend-axis-label" x="${points[i].x.toFixed(1)}" y="${TREND_H-6}" text-anchor="${i===0?'start':i===points.length-1?'end':'middle'}">${_fmtDay(points[i].day)}</text>`).join('')}
        </svg>
        <div class="trend-legend">
          ${SEV_STACK.filter(s => totals[s] > 0).map(s => `<span class="trend-legend-item"><span class="trend-legend-dot" style="background:${SEV_COLOR[s]}"></span>${s} (${totals[s]})</span>`).join('')}
        </div>
      </div>
    </div>
    <div class="chart-tooltip" id="trend-tooltip"></div>
  `;
}

function showTrendTooltip(i, evt) {
  const p = _trendPoints[i];
  const tip = document.getElementById('trend-tooltip');
  const cursor = document.getElementById('trend-cursor');
  if (!p || !tip) return;
  const rows = SEV_STACK.filter(s => p.added[s] > 0).map(s =>
    `<div class="chart-tooltip-row"><span><span class="dot" style="background:${SEV_COLOR[s]}"></span>${s}</span><span>${p.added[s]}</span></div>`
  ).join('');
  tip.innerHTML = `<div class="chart-tooltip-date">${_fmtDay(p.day)}</div>${rows || '<div class="chart-tooltip-row">No findings that day</div>'}`;
  tip.classList.add('show');
  const tipW = tip.offsetWidth, tipH = tip.offsetHeight;
  const left = (evt.clientX + 14 + tipW > window.innerWidth) ? evt.clientX - tipW - 14 : evt.clientX + 14;
  const top  = (evt.clientY + 14 + tipH > window.innerHeight) ? evt.clientY - tipH - 14 : evt.clientY + 14;
  tip.style.left = Math.max(4, left) + 'px';
  tip.style.top  = Math.max(4, top) + 'px';
  if (cursor) {
    const w = parseFloat(cursor.getAttribute('width'));
    cursor.setAttribute('x', p.x - w / 2);
    cursor.classList.add('active');
  }
}
function hideTrendTooltip() {
  const tip = document.getElementById('trend-tooltip');
  if (tip) tip.classList.remove('show');
  const cursor = document.getElementById('trend-cursor');
  if (cursor) cursor.classList.remove('active');
}
window.showTrendTooltip = showTrendTooltip;
window.hideTrendTooltip = hideTrendTooltip;

function updateDashboard() {
  if (!state.currentProject) return;

  // ── WSTG counts ───────────────────────────────────────────────
  let wDone=0, wFail=0, wTotal=0;
  WSTG_DATA.forEach(cat => cat.tests.forEach(t => {
    wTotal++;
    const s = state.wstgProgress[t.id]?.status;
    if (s === 'done') wDone++;
    if (s === 'fail') wFail++;
  }));

  // ── Vuln severity breakdown ───────────────────────────────────
  const vulns  = state.customVulns || [];
  const sevCount = { critical:0, high:0, medium:0, low:0, info:0 };
  vulns.forEach(v => { const s = v.severity||'medium'; if(sevCount[s]!==undefined) sevCount[s]++; });

  // ── Remediation progress ───────────────────────────────────────
  const remCount = { open:0, remediated:0, verified_closed:0 };
  vulns.forEach(v => { const s = v.remediation_status||'open'; if(remCount[s]!==undefined) remCount[s]++; });
  const remPct = vulns.length ? Math.round((remCount.remediated + remCount.verified_closed) / vulns.length * 100) : 0;

  // ── Sorted vulns + sequential IDs (VLN-01 = most critical) ────
  const _sevOrder = { critical:0, high:1, medium:2, low:3, info:4 };
  const sortedVulns = [...vulns].sort((a, b) =>
    (_sevOrder[a.severity||'medium'] ?? 2) - (_sevOrder[b.severity||'medium'] ?? 2)
  );
  _vulnIdMap = {};
  sortedVulns.forEach((v, i) => { _vulnIdMap[v.id] = `VLN-${String(i+1).padStart(2,'0')}`; });

  // ── Targets ───────────────────────────────────────────────────
  const targets = state.targets || [];
  const inScope = targets.filter(t => t.scope === 'in');

  const wPct = wTotal ? Math.round((wDone+wFail)/wTotal*100) : 0;
  const members = state.members || [];
  const tickets = state.tickets || [];

  // ── Fun settings ───────────────────────────────────────────────
  if (state.currentProject) {
    applyFunSettings(state.currentProject.id);
    if (wPct === 100 && !_confettiFired) {
      if (getFunSettings(state.currentProject.id).confetti) {
        _confettiFired = true;
        setTimeout(launchConfetti, 500);
      }
    }
    if (wPct < 100) _confettiFired = false;
  }

  // ── Update subtitle ───────────────────────────────────────────
  const sub = document.getElementById('dash-subtitle');
  if (sub) sub.textContent = `// ${state.currentProject.name} · ${wPct}% tested · ${vulns.length} findings`;

  // ── Render main content ───────────────────────────────────────
  const main = document.getElementById('dash-main');
  if (!main) return;

  const p   = state.currentProject;
  const pid = p.id;
  const critHigh = sevCount.critical + sevCount.high;

  // ── Risk score ────────────────────────────────────────────────
  const sevDefault = { critical:9.0, high:8.0, medium:5.0, low:2.0, info:0.1 };
  const maxCvss = vulns.length
    ? Math.max(...vulns.map(v => parseFloat(v.cvss_score) || sevDefault[v.severity||'medium'] || 0))
    : 0;
  const riskColor = maxCvss >= 9 ? 'var(--c-crit)' : maxCvss >= 7 ? 'var(--c-high)' : maxCvss >= 4 ? 'var(--c-med)' : 'var(--c-low)';

  main.innerHTML = `
    <!-- Stat row -->
    <div class="stat-row">
      <div class="stat-cell">
        <div class="stat-label">Total Findings</div>
        <div class="stat-val">${vulns.length}</div>
        <div class="stat-sub"><span class="stat-crit">${sevCount.critical} crit</span> · <span style="color:var(--c-high)">${sevCount.high} high</span></div>
        <div class="stat-bar"><div class="stat-bar-fill crit" style="width:${vulns.length ? Math.round(critHigh/vulns.length*100) : 0}%"></div></div>
      </div>
      <div class="stat-cell">
        <div class="stat-label">WSTG Coverage</div>
        <div class="stat-val">${wPct}%</div>
        <div class="stat-sub">${wDone+wFail} <span style="color:var(--t4)">/ ${wTotal} tested</span></div>
        <div class="stat-bar"><div class="stat-bar-fill" style="width:${wPct}%"></div></div>
      </div>
      <div class="stat-cell">
        <div class="stat-label">Targets in Scope</div>
        <div class="stat-val">${inScope.length}</div>
        <div class="stat-sub">${targets.length} total${targets.filter(t=>t.scope==='out').length ? ` · ${targets.filter(t=>t.scope==='out').length} out` : ''}</div>
        <div class="stat-bar"><div class="stat-bar-fill low" style="width:${targets.length ? Math.round(inScope.length/targets.length*100) : 0}%"></div></div>
      </div>
      <div class="stat-cell">
        <div class="stat-label">Days Remaining</div>
        ${(() => {
          if (!p.date_end) return `
            <div class="stat-val" style="color:var(--t3)">—</div>
            <div class="stat-sub"><a href="settings?pid=${pid}" style="color:var(--a);text-decoration:none">Set deadline ${icon('arrow-right', { size: 10 })}</a></div>
            <div class="stat-bar"></div>`;
          const parseDate = s => { const [y,m,d] = s.slice(0,10).split('-').map(Number); return new Date(y,m-1,d); };
          const today = new Date(); today.setHours(0,0,0,0);
          const end   = parseDate(p.date_end);
          const start = p.date_start ? parseDate(p.date_start) : null;
          const days  = Math.ceil((end - today) / 86400000);
          const total = start ? Math.ceil((end - start) / 86400000) : null;
          const pct   = (total && total > 0) ? Math.max(0, Math.min(100, Math.round((1 - days/total)*100))) : 0;
          const color = days < 0 ? 'var(--c-crit)' : days <= 3 ? 'var(--c-high)' : days <= 7 ? 'var(--c-med)' : 'var(--t1)';
          const label = days < 0 ? `${Math.abs(days)}d overdue` : days === 0 ? 'Today' : `${days}d left`;
          return `
            <div class="stat-val" style="color:${color}">${days < 0 ? '0' : days}</div>
            <div class="stat-sub"><span style="color:${color}">${label}</span>${total ? ` · ${pct}% elapsed` : ''}</div>
            <div class="stat-bar"><div class="stat-bar-fill${days<=3?' crit':days<=7?' high':''}" style="width:${pct}%"></div></div>`;
        })()}
      </div>
    </div>

    ${renderSeverityTrend(vulns)}

    <!-- Two-column grid -->
    <div style="display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:12px;align-items:start">

      <!-- LEFT: Findings + Targets -->
      <div>
        <div class="section">
          <div class="section-head">
            <div class="section-title">Recent Findings <span class="section-count">${vulns.length}</span></div>
            <a href="vulns?pid=${pid}" class="btn btn-ghost" style="font-size:10px;padding:2px 8px">view all ${icon('arrow-right', { size: 10 })}</a>
          </div>
          <div class="section-body bare">
            ${vulns.length === 0
              ? `<div class="empty-state" style="padding:28px 0"><div class="empty-icon">${icon('inbox', { size: 22 })}</div><div class="empty-sub">No findings yet — add one from the Findings page</div></div>`
              : `<table class="tbl">
                  <thead><tr>
                    <th>ID</th><th>Severity</th><th>Name</th><th>CVSS</th><th>Status</th>
                  </tr></thead>
                  <tbody>
                    ${sortedVulns.slice(0, 8).map(v => {
                      const sev     = v.severity || 'medium';
                      const st      = v.status;
                      const stLabel = st === 'done' ? 'confirmed' : st === 'fail' ? 'vuln found' : 'open';
                      const stCls   = st === 'done' ? 'resolved' : st === 'fail' ? 'in_progress' : 'open';
                      const cvss    = v.cvss_score != null ? parseFloat(v.cvss_score).toFixed(1) : '—';
                      const vid     = _vulnIdMap[v.id] || '—';
                      return `<tr class="click" onclick="openVulnDrawer('${v.id}')">
                        <td class="mono" style="color:var(--t3)">${vid}</td>
                        <td><span class="sev ${sev}">${sev}</span></td>
                        <td class="fw" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.name)}</td>
                        <td class="mono" style="color:${cvss !== '—' ? 'var(--t1)' : 'var(--t4)'}">${cvss}</td>
                        <td><span class="status ${stCls}"><span class="dot"></span>${stLabel}</span></td>
                      </tr>`;
                    }).join('')}
                  </tbody>
                </table>`
            }
          </div>
        </div>

        <div class="section">
          <div class="section-head">
            <div class="section-title">Targets <span class="section-count">${inScope.length}</span></div>
            <a href="targets?pid=${pid}" class="btn btn-ghost" style="font-size:10px;padding:2px 8px">manage ${icon('arrow-right', { size: 10 })}</a>
          </div>
          <div class="section-body bare">
            ${inScope.length === 0
              ? `<div class="empty-state" style="padding:28px 0"><div class="empty-icon">${icon('inbox', { size: 22 })}</div><div class="empty-sub">No targets in scope — add one from the Targets page</div></div>`
              : `<table class="tbl">
                  <thead><tr>
                    <th>Host</th>
                    <th style="width:70px">Type</th>
                    <th style="width:90px">Status</th>
                    <th style="width:80px">Findings</th>
                  </tr></thead>
                  <tbody>
                  ${inScope.map(t => {
                    const tVulns   = vulns.filter(v => v.target_id === t.id);
                    const vCount   = tVulns.length;
                    const sevOrder = ['critical','high','medium','low','info'];
                    const topSev   = vCount ? tVulns.sort((a,b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))[0].severity : null;
                    const stCls    = t.status || 'active';
                    const stLabel  = t.status || 'active';
                    return `<tr>
                      <td class="fw" style="max-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.host)}</td>
                      <td><span style="font-family:var(--mono);font-size:10px;color:var(--t3)">${t.type||'—'}</span></td>
                      <td><span class="status ${stCls}"><span class="dot"></span>${stLabel}</span></td>
                      <td>${vCount
                        ? `<span class="sev ${topSev}" style="font-size:9px">${vCount} finding${vCount>1?'s':''}</span>`
                        : `<span style="font-size:11px;color:var(--t4)">—</span>`}
                      </td>
                    </tr>`;
                  }).join('')}
                  </tbody>
                </table>`
            }
          </div>
        </div>

        <!-- Custom Methodologies -->
        ${(()=>{
          const activeProg = state.activeMethodProgress || {};
          const entries = Object.entries(activeProg);
          if (!entries.length) return '';
          return `<div class="section">
            <div class="section-head">
              <div class="section-title">Methodologies <span class="section-count">${entries.length}</span></div>
              <a href="methodology?pid=${pid}" class="btn btn-ghost" style="font-size:10px;padding:2px 8px">manage ${icon('arrow-right', { size: 10 })}</a>
            </div>
            <div class="section-body">
              <div style="display:flex;flex-direction:column;gap:10px">
                ${entries.map(([id, m]) => {
                  const pct     = m.total ? Math.round((m.done+m.fail)/m.total*100) : 0;
                  const pending = m.total - m.done - m.fail;
                  return `<div>
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
                      <span style="font-size:12px;font-weight:600">${esc(m.name)}</span>
                      <div style="display:flex;gap:10px;align-items:center">
                        <span style="font-size:11px;color:var(--c-low);display:inline-flex;align-items:center;gap:3px">${m.done} ${icon('check',{size:11})}</span>
                        ${m.fail ? `<span style="font-size:11px;color:var(--c-crit);display:inline-flex;align-items:center;gap:3px">${icon('triangle-alert',{size:11})} ${m.fail}</span>` : ''}
                        <span style="font-size:11px;color:var(--t3)">${pending} pending</span>
                        <span style="font-size:11px;font-weight:700;color:var(--t2)">${pct}%</span>
                      </div>
                    </div>
                    <div class="pbar"><div style="width:${pct}%;${m.fail?'background:var(--c-crit)':''}"></div></div>
                  </div>`;
                }).join('')}
              </div>
            </div>
          </div>`;
        })()}

        <!-- Client Queries -->
        ${(()=>{
          if (!p.tickets_enabled) return '';
          const open     = tickets.filter(t => t.status === 'open').length;
          const inReview = tickets.filter(t => t.status === 'in_review').length;
          const closed   = tickets.filter(t => t.status === 'closed').length;
          const recent   = tickets.filter(t => t.status !== 'closed').slice(0, 4);
          return `<div class="section">
            <div class="section-head">
              <div class="section-title">Client Queries <span class="section-count">${tickets.length}</span></div>
              <a href="tickets?pid=${pid}" class="btn btn-ghost" style="font-size:10px;padding:2px 8px">view all ${icon('arrow-right', { size: 10 })}</a>
            </div>
            <div class="section-body">
              <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:12px">
                <div style="background:var(--bg2);border:1px solid var(--b1);border-radius:var(--r);padding:10px;text-align:center">
                  <div style="font-size:20px;font-weight:700;color:${open?'var(--a)':'var(--t3)'}">${open}</div>
                  <div class="stat-label" style="margin-top:4px;margin-bottom:0">Open</div>
                </div>
                <div style="background:var(--bg2);border:1px solid var(--b1);border-radius:var(--r);padding:10px;text-align:center">
                  <div style="font-size:20px;font-weight:700;color:${inReview?'var(--c-high)':'var(--t3)'}">${inReview}</div>
                  <div class="stat-label" style="margin-top:4px;margin-bottom:0">In Review</div>
                </div>
                <div style="background:var(--bg2);border:1px solid var(--b1);border-radius:var(--r);padding:10px;text-align:center">
                  <div style="font-size:20px;font-weight:700;color:${closed?'var(--c-low)':'var(--t3)'}">${closed}</div>
                  <div class="stat-label" style="margin-top:4px;margin-bottom:0">Closed</div>
                </div>
              </div>
              ${recent.length
                ? recent.map(t => `<div class="dash-ticket-row" onclick="window.location.href='tickets?pid=${pid}'">
                    <div class="dash-ticket-dot" style="background:${t.status==='open'?'var(--a)':'var(--c-high)'}"></div>
                    <span style="font-size:12px;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.title)}</span>
                    ${t.reply_count ? `<span style="font-size:10px;color:var(--t3)">${t.reply_count} repl${t.reply_count===1?'y':'ies'}</span>` : ''}
                    <span style="font-size:10px;color:var(--t3)">${relativeDate(t.updated_at)}</span>
                  </div>`).join('')
                : `<div style="font-size:11px;color:var(--t3)">No open queries.</div>`
              }
            </div>
          </div>`;
        })()}
      </div>

      <!-- RIGHT: Severity + WSTG -->
      <div>
        <!-- Severity breakdown + Risk score -->
        <div class="section">
          <div class="section-head">
            <div class="section-title">Severity</div>
          </div>
          <div class="section-body">
            ${vulns.length === 0
              ? `<div class="empty-state" style="padding:20px 0"><div class="empty-icon">${icon('inbox', { size: 20 })}</div><div class="empty-sub">No findings yet</div></div>`
              : `<div style="text-align:center;margin-bottom:16px">
                  <div style="font-size:56px;font-weight:700;line-height:1;color:${riskColor};letter-spacing:-0.03em">${maxCvss > 0 ? maxCvss.toFixed(1) : '—'}</div>
                  <div style="font-size:9px;color:var(--t3);text-transform:uppercase;letter-spacing:.1em;margin-top:4px">Max CVSS Score</div>
                </div>
                <div style="display:flex;flex-direction:column;gap:6px">
                  ${['critical','high','medium','low','info'].map(s => {
                    const c = sevCount[s];
                    const maxCount = Math.max(1, ...Object.values(sevCount));
                    const pct = Math.round(c / maxCount * 100);
                    const colors = {critical:'var(--c-crit)',high:'var(--c-high)',medium:'var(--c-med)',low:'var(--c-low)',info:'var(--c-info)'};
                    return `<div style="display:flex;align-items:center;gap:8px">
                      <span class="sev ${s}" style="width:56px;justify-content:center;flex-shrink:0">${s}</span>
                      <div style="flex:1;height:4px;background:var(--b1);border-radius:2px;overflow:hidden">
                        <div style="height:100%;width:${pct}%;background:${colors[s]};border-radius:2px"></div>
                      </div>
                      <span style="font-size:10px;color:var(--t2);width:14px;text-align:right;flex-shrink:0">${c}</span>
                    </div>`;
                  }).join('')}
                </div>`
            }
          </div>
        </div>

        <!-- Remediation progress -->
        <div class="section">
          <div class="section-head">
            <div class="section-title">Remediation <span class="section-count">${remPct}%</span></div>
            <a href="vulns?pid=${pid}" class="btn btn-ghost" style="font-size:10px;padding:2px 8px">${icon('arrow-right', { size: 10 })}</a>
          </div>
          <div class="section-body">
            ${vulns.length === 0
              ? `<div class="empty-state" style="padding:20px 0"><div class="empty-icon">${icon('inbox', { size: 20 })}</div><div class="empty-sub">No findings yet</div></div>`
              : `<div style="display:flex;gap:16px;margin-bottom:12px">
                  <div><span style="font-size:18px;font-weight:700;color:var(--c-low)">${remCount.verified_closed}</span> <span style="font-size:9px;color:var(--t3)">verified</span></div>
                  <div><span style="font-size:18px;font-weight:700;color:var(--c-med)">${remCount.remediated}</span> <span style="font-size:9px;color:var(--t3)">remediated</span></div>
                  <div><span style="font-size:18px;font-weight:700;color:var(--t3)">${remCount.open}</span> <span style="font-size:9px;color:var(--t3)">open</span></div>
                </div>
                <div style="display:flex;height:4px;border-radius:2px;overflow:hidden;background:var(--b1)">
                  <div style="width:${vulns.length ? remCount.verified_closed/vulns.length*100 : 0}%;background:var(--c-low)"></div>
                  <div style="width:${vulns.length ? remCount.remediated/vulns.length*100 : 0}%;background:var(--c-med)"></div>
                </div>`
            }
          </div>
        </div>

        <!-- WSTG mini progress -->
        <div class="section">
          <div class="section-head">
            <div class="section-title">WSTG Progress <span class="section-count">${wPct}%</span></div>
            <a href="owstg?pid=${pid}" class="btn btn-ghost" style="font-size:10px;padding:2px 8px">${icon('arrow-right', { size: 10 })}</a>
          </div>
          <div class="section-body">
            <div style="display:flex;gap:16px;margin-bottom:12px">
              <div><span style="font-size:18px;font-weight:700;color:var(--c-low)">${wDone}</span> <span style="font-size:9px;color:var(--t3)">passed</span></div>
              <div><span style="font-size:18px;font-weight:700;color:var(--c-crit)">${wFail}</span> <span style="font-size:9px;color:var(--t3)">vuln</span></div>
              <div><span style="font-size:18px;font-weight:700;color:var(--t3)">${wTotal-wDone-wFail}</span> <span style="font-size:9px;color:var(--t3)">pending</span></div>
            </div>
            <div style="display:flex;flex-direction:column;gap:7px">
              ${WSTG_DATA.map(cat => {
                const t   = cat.tests.length;
                const d   = cat.tests.filter(x => state.wstgProgress[x.id]?.status === 'done').length;
                const f   = cat.tests.filter(x => state.wstgProgress[x.id]?.status === 'fail').length;
                const pct = t ? Math.round((d+f)/t*100) : 0;
                return `<div>
                  <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                    <span style="font-size:9px;color:var(--t3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${esc(cat.name)}</span>
                    ${f ? `<span style="font-size:9px;color:var(--c-crit);margin:0 4px;display:inline-flex;align-items:center;gap:2px">${icon('triangle-alert',{size:9})}${f}</span>` : ''}
                    <span style="font-size:9px;color:var(--t2);font-weight:600;margin-left:6px">${pct}%</span>
                  </div>
                  <div class="pbar"><div style="width:${pct}%;${f?'background:var(--c-crit)':''}"></div></div>
                </div>`;
              }).join('')}
            </div>
          </div>
        </div>

        <!-- Timeline -->
        <div class="section">
          <div class="section-head">
            <div class="section-title">Timeline</div>
            <a href="settings?pid=${pid}" class="btn btn-ghost" style="font-size:10px;padding:2px 8px">edit ${icon('arrow-right', { size: 10 })}</a>
          </div>
          <div class="section-body">
            ${(() => {
              const rows = [
                { label: 'Inicio',   date: p.date_start  },
                { label: 'Fin test', date: p.date_end    },
                { label: 'Reporte',  date: p.date_report },
              ];
              const today = new Date(); today.setHours(0,0,0,0);
              if (!p.date_start && !p.date_end && !p.date_report) {
                return `<div style="font-size:11px;color:var(--t3)">Sin fechas configuradas. <a href="settings?pid=${pid}" style="color:var(--a)">Configurar ${icon('arrow-right', { size: 10 })}</a></div>`;
              }
              return `<div style="display:flex;flex-direction:column;gap:10px">
                ${rows.map(r => {
                  if (!r.date) return `
                    <div style="display:flex;justify-content:space-between;align-items:center">
                      <span style="font-size:11px;color:var(--t3)">${r.label}</span>
                      <span style="font-size:11px;color:var(--t4)">—</span>
                    </div>`;
                  const parseD = s => { const [y,m,dd] = s.slice(0,10).split('-').map(Number); return new Date(y,m-1,dd); };
                  const d    = parseD(r.date);
                  const diff = Math.ceil((d - today) / 86400000);
                  const fmt  = d.toLocaleDateString('es-ES',{day:'2-digit',month:'short',year:'numeric'});
                  const hint = diff < 0 ? `hace ${Math.abs(diff)}d` : diff === 0 ? 'hoy' : `en ${diff}d`;
                  const hintColor = diff < 0 ? 'var(--c-crit)' : diff <= 3 ? 'var(--c-high)' : diff <= 7 ? 'var(--c-med)' : 'var(--t3)';
                  return `
                    <div style="display:flex;justify-content:space-between;align-items:center">
                      <span style="font-size:11px;color:var(--t2)">${r.label}</span>
                      <div style="text-align:right">
                        <div style="font-size:11px;font-weight:600;font-family:var(--mono)">${fmt}</div>
                        <div style="font-size:9px;color:${hintColor}">${hint}</div>
                      </div>
                    </div>`;
                }).join('')}
              </div>`;
            })()}
          </div>
        </div>
      </div>
    </div>

  `;

  if (typeof refreshTopbarProgress === 'function') refreshTopbarProgress();
}

window.updateDashboard  = updateDashboard;
window.openVulnDrawer   = openVulnDrawer;
window.closeVulnDrawer  = closeVulnDrawer;