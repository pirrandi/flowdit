// ── views/dashboard.js ───────────────────────────────────────────────

let _confettiFired = false;

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

  // ── PS counts ─────────────────────────────────────────────────
  let psDone=0, psTotal=0;
  PS_DATA.forEach(cat => cat.labs.forEach((_,i) => {
    psTotal++;
    if (state.psProgress[`${cat.id}_${i}`]) psDone++;
  }));

  // ── Vuln severity breakdown ───────────────────────────────────
  const vulns  = state.customVulns || [];
  const sevCount = { critical:0, high:0, medium:0, low:0, info:0 };
  vulns.forEach(v => { const s = v.severity||'medium'; if(sevCount[s]!==undefined) sevCount[s]++; });

  // ── Targets ───────────────────────────────────────────────────
  const targets = state.targets || [];
  const inScope = targets.filter(t => t.scope === 'in');
  const targetsWithFindings = new Set(vulns.filter(v=>v.target_id).map(v=>v.target_id));

  const wPct = wTotal ? Math.round((wDone+wFail)/wTotal*100) : 0;
  const pPct = psTotal ? Math.round(psDone/psTotal*100) : 0;

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

  const p = state.currentProject;

  main.innerHTML = `
    <!-- Engagement info bar -->
    <div class="dash-engagement">
      <div class="dash-eng-item">
        <span class="dash-eng-label">Target</span>
        <span class="dash-eng-value">${esc(p.target||'—')}</span>
      </div>
      ${p.description ? `<div class="dash-eng-item">
        <span class="dash-eng-label">Scope</span>
        <span class="dash-eng-value" style="font-size:11px">${esc(p.description)}</span>
      </div>` : ''}
      <div class="dash-eng-item">
        <span class="dash-eng-label">Started</span>
        <span class="dash-eng-value">${new Date(p.created_at).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'})}</span>
      </div>
      <div class="dash-eng-item">
        <span class="dash-eng-label">Status</span>
        <span class="dash-eng-value" style="color:${p.status==='active'?'var(--green)':p.status==='completed'?'var(--accent)':'var(--text3)'}">${p.status}</span>
      </div>
    </div>

    <!-- Severity + scope row -->
    <div class="dash-row" style="margin-bottom:16px">
      <!-- Severity breakdown -->
      <div class="dash-panel" style="flex:2">
        <div class="dash-panel-title">Findings by Severity</div>
        ${vulns.length === 0
          ? `<div class="empty-state" style="padding:16px 0;gap:4px"><div style="font-size:20px">✅</div><div class="empty-title" style="font-size:12px">No findings yet</div></div>`
          : `<div class="sev-breakdown">
              ${['critical','high','medium','low','info'].map(s => {
                const c = sevCount[s];
                const labels = {critical:'Critical',high:'High',medium:'Medium',low:'Low',info:'Info'};
                const emojis = {critical:'🔴',high:'🟠',medium:'🟡',low:'🔵',info:'⚪'};
                const pct = vulns.length ? Math.round(c/vulns.length*100) : 0;
                return `<div class="sev-row">
                  <span class="sev-badge sev-${s}" style="width:62px;text-align:center">${labels[s]}</span>
                  <div class="sev-bar-wrap">
                    <div class="sev-bar sev-bar-${s}" style="width:${pct}%"></div>
                  </div>
                  <span style="font-family:var(--mono);font-size:11px;color:var(--text2);min-width:20px;text-align:right">${c}</span>
                </div>`;
              }).join('')}
            </div>`
        }
      </div>

      <!-- Targets summary -->
      <div class="dash-panel" style="flex:1">
        <div class="dash-panel-title">Scope</div>
        ${inScope.length === 0
          ? `<div class="empty-state" style="padding:16px 0;gap:4px"><div style="font-size:20px">🎯</div><div class="empty-title" style="font-size:12px">No targets defined</div></div>`
          : `<div style="display:flex;flex-direction:column;gap:4px">
              ${inScope.map(t => {
                const icons = {domain:'🌐',ip:'🖥',cidr:'🔲',url:'🔗',other:'📌'};
                const hasFindings = targetsWithFindings.has(t.id);
                const vCount = vulns.filter(v=>v.target_id===t.id).length;
                return `<div class="dash-target-row">
                  <span style="font-size:11px">${icons[t.type]||'📌'}</span>
                  <span style="font-family:var(--mono);font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.host)}</span>
                  ${hasFindings ? `<span style="font-family:var(--mono);font-size:10px;color:var(--red);background:var(--red)15;border-radius:4px;padding:1px 5px">${vCount}</span>` : ''}
                </div>`;
              }).join('')}
              ${targets.filter(t=>t.scope==='out').length
                ? `<div style="font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:4px">${targets.filter(t=>t.scope==='out').length} out of scope</div>`
                : ''}
            </div>`
        }
      </div>
    </div>

    <!-- Progress section -->
    <div class="dash-row" style="margin-bottom:16px">
      <div class="dash-panel" style="flex:1">
        <div class="dash-panel-title">WSTG Progress
          <span style="font-family:var(--mono);font-size:11px;font-weight:400;color:var(--text3);margin-left:8px">${wDone+wFail}/${wTotal} tested</span>
        </div>
        <div style="display:flex;gap:16px;margin-bottom:10px">
          <div><span style="font-family:var(--mono);font-size:20px;font-weight:800;color:var(--green)">${wDone}</span>
            <span style="font-family:var(--mono);font-size:10px;color:var(--text3);display:block">passed</span></div>
          <div><span style="font-family:var(--mono);font-size:20px;font-weight:800;color:var(--red)">${wFail}</span>
            <span style="font-family:var(--mono);font-size:10px;color:var(--text3);display:block">vuln found</span></div>
          <div><span style="font-family:var(--mono);font-size:20px;font-weight:800;color:var(--text3)">${wTotal-wDone-wFail}</span>
            <span style="font-family:var(--mono);font-size:10px;color:var(--text3);display:block">pending</span></div>
        </div>
        <div class="progress-bar" style="margin-bottom:12px">
          <div class="progress-bar-fill" style="width:${wPct}%"></div>
        </div>
        <!-- WSTG by category -->
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:6px">
          ${WSTG_DATA.map(cat => {
            const t    = cat.tests.length;
            const d    = cat.tests.filter(x => state.wstgProgress[x.id]?.status === 'done').length;
            const f    = cat.tests.filter(x => state.wstgProgress[x.id]?.status === 'fail').length;
            const pct  = t ? Math.round((d+f)/t*100) : 0;
            return `<div class="dash-cat-card">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                <span style="font-family:var(--mono);font-size:9px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1">${esc(cat.name)}</span>
                ${f ? `<span style="font-family:var(--mono);font-size:9px;color:var(--red);margin-left:4px">⚠${f}</span>` : ''}
                <span style="font-family:var(--mono);font-size:10px;font-weight:700;color:var(--text2);margin-left:6px">${pct}%</span>
              </div>
              <div class="progress-bar" style="height:3px">
                <div class="progress-bar-fill" style="width:${pct}%;${f?'background:var(--red)':''}"></div>
              </div>
            </div>`;
          }).join('')}
        </div>
      </div>
    </div>

    <!-- Custom Methodologies section -->
    ${(()=>{
      const activeProg = state.activeMethodProgress || {};
      const entries = Object.entries(activeProg);
      if (!entries.length) return '';
      return `<div class="dash-row" style="margin-bottom:16px">
        <div class="dash-panel" style="flex:1">
          <div class="dash-panel-title">Custom Methodologies
            <a href="methodology.html" style="font-family:var(--mono);font-size:10px;color:var(--accent);text-decoration:none;font-weight:400;margin-left:8px">manage →</a>
          </div>
          <div style="display:flex;flex-direction:column;gap:10px">
            ${entries.map(([id, m]) => {
              const pct  = m.total ? Math.round((m.done+m.fail)/m.total*100) : 0;
              const pending = m.total - m.done - m.fail;
              return `<div>
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px">
                  <span style="font-size:12px;font-weight:600">${esc(m.name)}</span>
                  <div style="display:flex;gap:10px;align-items:center">
                    <span style="font-family:var(--mono);font-size:11px;color:var(--green)">${m.done} ✓</span>
                    ${m.fail ? `<span style="font-family:var(--mono);font-size:11px;color:var(--red)">⚠ ${m.fail}</span>` : ''}
                    <span style="font-family:var(--mono);font-size:11px;color:var(--text3)">${pending} pending</span>
                    <span style="font-family:var(--mono);font-size:11px;font-weight:700;color:var(--text2)">${pct}%</span>
                  </div>
                </div>
                <div class="progress-bar">
                  <div class="progress-bar-fill" style="width:${pct}%;${m.fail?'background:var(--red)':''}"></div>
                </div>
              </div>`;
            }).join('')}
          </div>
        </div>
      </div>`;
    })()}

    <!-- Client Queries panel -->
    ${(()=>{
      const tickets = state.tickets || [];
      if (!state.currentProject.tickets_enabled) return '';
      const pid = state.currentProject.id;
      const open      = tickets.filter(t => t.status === 'open').length;
      const inReview  = tickets.filter(t => t.status === 'in_review').length;
      const closed    = tickets.filter(t => t.status === 'closed').length;

      const recent = tickets.filter(t => t.status !== 'closed').slice(0, 4);
      const rows = recent.map(t => {
        const color = t.status === 'open' ? 'var(--accent)' : '#f59e0b';
        return `
          <div class="dash-ticket-row" onclick="window.location.href='tickets.html?pid=${pid}'">
            <div class="dash-ticket-dot" style="background:${color}"></div>
            <span style="font-size:12px;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(t.title)}</span>
            ${t.reply_count ? `<span style="font-family:var(--mono);font-size:10px;color:var(--text3)">💬 ${t.reply_count}</span>` : ''}
            <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">${relativeDate(t.updated_at)}</span>
          </div>`;
      }).join('');

      return `<div class="dash-row" style="margin-bottom:16px">
        <div class="dash-panel" style="flex:1">
          <div class="dash-panel-title">Client Queries
            <a href="tickets.html?pid=${pid}" style="font-family:var(--mono);font-size:10px;color:var(--accent);text-decoration:none;font-weight:400;margin-left:auto">view all →</a>
          </div>
          <div style="display:flex;gap:10px;margin-bottom:14px">
            <div class="dash-ticket-stat" style="border-color:#7c3aed44">
              <span style="font-size:20px;font-weight:800;color:${open?'#7c3aed':'var(--text3)'};font-family:var(--mono)">${open}</span>
              <span style="font-family:var(--mono);font-size:9px;color:var(--text3);text-transform:uppercase">Open</span>
            </div>
            <div class="dash-ticket-stat" style="border-color:#f59e0b44">
              <span style="font-size:20px;font-weight:800;color:${inReview?'#f59e0b':'var(--text3)'};font-family:var(--mono)">${inReview}</span>
              <span style="font-family:var(--mono);font-size:9px;color:var(--text3);text-transform:uppercase">In Review</span>
            </div>
            <div class="dash-ticket-stat" style="border-color:#22d3a344">
              <span style="font-size:20px;font-weight:800;color:${closed?'#22d3a3':'var(--text3)'};font-family:var(--mono)">${closed}</span>
              <span style="font-family:var(--mono);font-size:9px;color:var(--text3);text-transform:uppercase">Closed</span>
            </div>
          </div>
          ${recent.length
            ? rows
            : `<div style="font-family:var(--mono);font-size:11px;color:var(--text3);padding:4px 0">No open queries from the client.</div>`}
        </div>
      </div>`;
    })()}

    <!-- Recent findings + Team row -->
    <div class="dash-row">
      <!-- Recent custom vulns -->
      <div class="dash-panel" style="flex:2">
        <div class="dash-panel-title">Recent Findings
          <a href="vulns.html" style="font-family:var(--mono);font-size:10px;color:var(--accent);text-decoration:none;font-weight:400;margin-left:8px">view all →</a>
        </div>
        ${vulns.length === 0
          ? `<div class="empty-state" style="padding:12px 0;gap:4px"><div class="empty-title" style="font-size:12px">No custom findings yet</div></div>`
          : [...vulns].reverse().slice(0,6).map(v => {
              const icon = {domain:'🌐',ip:'🖥',cidr:'🔲',url:'🔗',other:'📌'};
              return `<div class="dash-finding-row">
                <span class="sev-badge sev-${v.severity||'medium'}" style="font-size:9px;flex-shrink:0">${v.severity||'medium'}</span>
                <span style="font-size:12px;font-weight:600;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.name)}</span>
                <span style="font-family:var(--mono);font-size:10px;color:${v.status==='done'?'var(--green)':v.status==='fail'?'var(--red)':'var(--text3)'};flex-shrink:0">${v.status==='done'?'✓ confirmed':v.status==='fail'?'✕ reproduced':'pending'}</span>
              </div>`;
            }).join('')
        }
      </div>

      <!-- Team -->
      <div class="dash-panel" style="flex:1">
        <div class="dash-panel-title">Team
          <a href="members.html" style="font-family:var(--mono);font-size:10px;color:var(--accent);text-decoration:none;font-weight:400;margin-left:8px">manage →</a>
        </div>
        <div style="display:flex;flex-direction:column;gap:6px">
          ${(state.members||[]).map(m => `
            <div style="display:flex;align-items:center;gap:8px">
              ${avatarHtml(m.username, roleColor(m.role), 24, m.avatar_url||null)}
              <span style="font-size:12px;flex:1">${esc(m.username)}</span>
              <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">${m.role}</span>
            </div>`).join('')}
        </div>
      </div>
    </div>`;

  if (typeof refreshTopbarProgress === 'function') refreshTopbarProgress();
}

window.updateDashboard = updateDashboard;