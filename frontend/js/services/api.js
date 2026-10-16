// ── api.js — all HTTP calls to the backend ───────────────────────────
const API_BASE = window.FLOWDIT_API || 'http://localhost:4000/api';

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const tokens = {
  get access()  { return localStorage.getItem('fd_access'); },
  get refresh() { return localStorage.getItem('fd_refresh'); },
  set(a, r)  { localStorage.setItem('fd_access', a); if (r) localStorage.setItem('fd_refresh', r); },
  clear()    {
    ['fd_access','fd_refresh','fd_user'].forEach(k => localStorage.removeItem(k));
    // Cached sidenav snapshot (page.js) dies with the session.
    try { sessionStorage.removeItem('fd_shell'); } catch {}
  },
};

// Portal session — stored in sessionStorage so it expires when the tab closes
const portalSession = {
  get token()     { return sessionStorage.getItem('fd_portal'); },
  get projectId() { return sessionStorage.getItem('fd_portal_pid'); },
  get name()      { return sessionStorage.getItem('fd_portal_name') || ''; },
  get email()     { return sessionStorage.getItem('fd_portal_email') || ''; },
  set(token, pid, name, email) {
    sessionStorage.setItem('fd_portal', token);
    sessionStorage.setItem('fd_portal_pid', pid);
    if (name)  sessionStorage.setItem('fd_portal_name',  name.trim());
    if (email) sessionStorage.setItem('fd_portal_email', email.trim());
  },
  clear() {
    ['fd_portal','fd_portal_pid','fd_portal_name','fd_portal_email'].forEach(k => sessionStorage.removeItem(k));
  },
  has() { return !!sessionStorage.getItem('fd_portal'); },
};

let _refreshPromise = null;

async function requestUpload(method, path, formData, retry = true) {
  const headers = {};
  if (tokens.access) headers['Authorization'] = `Bearer ${tokens.access}`;
  const res = await fetch(`${API_BASE}${path}`, { method, headers, body: formData });
  if (res.status === 401 && retry && tokens.refresh) {
    if (!_refreshPromise) {
      _refreshPromise = refreshTokens().finally(() => { _refreshPromise = null; });
    }
    const ok = await _refreshPromise;
    if (ok) return requestUpload(method, path, formData, false);
    tokens.clear();
    window.dispatchEvent(new Event('fd:logout'));
    throw new ApiError(401, 'Session expired');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.error || 'Request failed');
  return data;
}

async function request(method, path, body, retry = true) {
  const headers = { 'Content-Type': 'application/json' };
  // Portal session takes priority over regular user session
  if (portalSession.has()) {
    headers['Authorization'] = `Bearer ${portalSession.token}`;
  } else if (tokens.access) {
    headers['Authorization'] = `Bearer ${tokens.access}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method, headers,
    body: body != null ? JSON.stringify(body) : undefined,
  });

  // Don't attempt token refresh for portal sessions
  if (res.status === 401 && retry && tokens.refresh && !portalSession.has()) {
    if (!_refreshPromise) {
      _refreshPromise = refreshTokens().finally(() => { _refreshPromise = null; });
    }
    const ok = await _refreshPromise;
    if (ok) return request(method, path, body, false);
    tokens.clear();
    window.dispatchEvent(new Event('fd:logout'));
    throw new ApiError(401, 'Session expired');
  }

  if (res.status === 401 && portalSession.has()) {
    portalSession.clear();
    window.location.href = 'client-login.html';
    throw new ApiError(401, 'Session expired');
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.error || 'Request failed');
  return data;
}

async function refreshTokens() {
  try {
    const data = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: tokens.refresh }),
    }).then(r => r.json());
    if (data.accessToken) { tokens.set(data.accessToken, data.refreshToken); return true; }
    return false;
  } catch { return false; }
}

const api = {
  auth: {
    login:    (l, p)       => request('POST', '/auth/login',    { login:l, password:p }),
    logout:   ()           => request('POST', '/auth/logout', { refreshToken: tokens.refresh }).finally(() => tokens.clear()),
    me:            ()      => request('GET',   '/auth/me'),
    updateProfile: (d)    => request('PATCH', '/auth/me', d),
    setTokens: (a,r)       => tokens.set(a, r),
    clearTokens: ()        => tokens.clear(),
    hasSession: ()         => !!tokens.access,
    sso: {
      check:    (email)    => request('POST', '/auth/sso/check', { email }),
      exchange: (code)     => request('POST', '/auth/sso/exchange', { code }),
    },
    mfa: {
      status:  ()                     => request('GET',  '/auth/mfa/status'),
      setup:   ()                     => request('POST', '/auth/mfa/setup'),
      enable:  (code)                 => request('POST', '/auth/mfa/enable', { code }),
      disable: (password)             => request('POST', '/auth/mfa/disable', { password }),
      verify:  (challengeToken, code) => request('POST', '/auth/mfa/verify', { challengeToken, code }),
    },
  },
  projects: {
    list:    ()       => request('GET',    '/projects'),
    create:  (d)      => request('POST',   '/projects', d),
    get:     (id)     => request('GET',    `/projects/${id}`),
    update:  (id,d)   => request('PATCH',  `/projects/${id}`, d),
    delete:  (id)     => request('DELETE', `/projects/${id}`),
    join:    (token)  => request('POST',   '/projects/join', { token }),
    move:    (id,oid) => request('POST',   `/projects/${id}/move`, { organization_id: oid }),
  },
  organizations: {
    list:    ()       => request('GET',    '/organizations'),
    create:  (d)      => request('POST',   '/organizations', d),
    get:     (id)     => request('GET',    `/organizations/${id}`),
    update:  (id,d)   => request('PATCH',  `/organizations/${id}`, d),
    delete:  (id)     => request('DELETE', `/organizations/${id}`),
    join:    (token)  => request('POST',   '/organizations/join', { token }),
    members: {
      list:       (oid)         => request('GET',    `/organizations/${oid}/members`),
      changeRole: (oid,uid,role)=> request('PATCH',  `/organizations/${oid}/members/${uid}`, { role }),
      remove:     (oid,uid)     => request('DELETE', `/organizations/${oid}/members/${uid}`),
    },
    invites: {
      list:   (oid)             => request('GET',    `/organizations/${oid}/invites`),
      create: (oid, role, label)=> request('POST',   `/organizations/${oid}/invites`, { role, label }),
      revoke: (oid, id)         => request('DELETE', `/organizations/${oid}/invites/${id}`),
    },
    sso: {
      get:    (oid)      => request('GET',    `/organizations/${oid}/sso`),
      upsert: (oid, d)   => request('PUT',    `/organizations/${oid}/sso`, d),
      remove: (oid)      => request('DELETE', `/organizations/${oid}/sso`),
    },
  },
  members: {
    list:       (pid)         => request('GET',    `/projects/${pid}/members`),
    changeRole: (pid,uid,role)=> request('PATCH',  `/projects/${pid}/members/${uid}`, { role }),
    remove:     (pid,uid)     => request('DELETE', `/projects/${pid}/members/${uid}`),
  },
  invites: {
    list:   (pid)             => request('GET',    `/projects/${pid}/invites`),
    create: (pid, role, label)=> request('POST',   `/projects/${pid}/invites`, { role, label }),
    revoke: (pid, id)         => request('DELETE', `/projects/${pid}/invites/${id}`),
  },
  wstg: {
    getAll:    (pid)               => request('GET',   `/projects/${pid}/wstg`),
    setStatus: (pid, tid, status, testName) =>
                                      request('PATCH', `/projects/${pid}/wstg/${tid}/status`, { status, testName }),
    setNote:   (pid, tid, note, testName)   =>
                                      request('PATCH', `/projects/${pid}/wstg/${tid}/note`,   { note, testName }),
    setItem:   (pid, tid, idx, checked)     =>
                                      request('PATCH', `/projects/${pid}/wstg/${tid}/items/${idx}`, { checked }),
    setTarget: (pid, tid, targetId) =>
                                      request('PATCH', `/projects/${pid}/wstg/${tid}/target`, { target_id: targetId }),
    saveReport:(pid, tid, description, remediation) =>
                                      request('PATCH', `/projects/${pid}/wstg/${tid}/report`, { description, remediation }),
    setLink:   (pid, tid, vulnId)   =>
                                      request('PATCH', `/projects/${pid}/wstg/${tid}/link`,   { linked_vuln_id: vulnId }),
  },
  ps: {
    getAll:   (pid)                          => request('GET',   `/projects/${pid}/ps`),
    toggle:   (pid, catId, idx, done, labName) =>
                                               request('PATCH', `/projects/${pid}/ps/${catId}/${idx}`, { done, labName }),
    saveNote: (pid, catId, idx, note)        => request('PATCH', `/projects/${pid}/ps/${catId}/${idx}/note`, { note }),
  },
  vulns: {
    list:          (pid)       => request('GET',    `/projects/${pid}/vulns`),
    create:        (pid, d)    => request('POST',   `/projects/${pid}/vulns`, d),
    update:        (pid, id,d) => request('PATCH',  `/projects/${pid}/vulns/${id}`, d),
    delete:        (pid, id)   => request('DELETE', `/projects/${pid}/vulns/${id}`),
    setRemediation:(pid, id,d) => request('PATCH',  `/projects/${pid}/vulns/${id}/remediation`, d),
  },
  methodologies: {
    list:        ()                        => request('GET',    '/methodologies'),
    create:      (d)                       => request('POST',   '/methodologies', d),
    update:      (id, d)                   => request('PATCH',  `/methodologies/${id}`, d),
    delete:      (id)                      => request('DELETE', `/methodologies/${id}`),
    getProgress: (methodId, projectId)     => request('GET',    `/methodologies/${methodId}/progress/${projectId}`),
    setProgress: (methodId, projectId, testIdx, d) =>
                                              request('PATCH',  `/methodologies/${methodId}/progress/${projectId}/${testIdx}`, d),
    // project-active endpoints
    activate:        (methodId, projectId, active) =>
                                              request('PATCH',  `/methodologies/${methodId}/activate/${projectId}`, { active }),
    projectProgress: (projectId)             => request('GET',   `/methodologies/project-progress/${projectId}`),
  },
  targets: {
    list:   (pid)        => request('GET',    `/projects/${pid}/targets`),
    create: (pid, d)     => request('POST',   `/projects/${pid}/targets`, d),
    update: (pid, id, d) => request('PATCH',  `/projects/${pid}/targets/${id}`, d),
    delete: (pid, id)    => request('DELETE', `/projects/${pid}/targets/${id}`),
    // ports
    listPorts:     (pid, tid)        => request('GET',    `/projects/${pid}/targets/${tid}/ports`),
    addPort:       (pid, tid, d)     => request('POST',   `/projects/${pid}/targets/${tid}/ports`, d),
    updatePort:    (pid, tid, id, d) => request('PATCH',  `/projects/${pid}/targets/${tid}/ports/${id}`, d),
    deletePort:    (pid, tid, pid2)  => request('DELETE', `/projects/${pid}/targets/${tid}/ports/${pid2}`),
    // endpoints
    listEndpoints:  (pid, tid)       => request('GET',    `/projects/${pid}/targets/${tid}/endpoints`),
    addEndpoint:    (pid, tid, d)    => request('POST',   `/projects/${pid}/targets/${tid}/endpoints`, d),
    updateEndpoint: (pid, tid, id,d) => request('PATCH',  `/projects/${pid}/targets/${tid}/endpoints/${id}`, d),
    deleteEndpoint: (pid, tid, id)   => request('DELETE', `/projects/${pid}/targets/${tid}/endpoints/${id}`),
  },
  tickets: {
    list:   (pid)              => request('GET',    `/projects/${pid}/tickets`),
    get:    (pid, tid)         => request('GET',    `/projects/${pid}/tickets/${tid}`),
    create: (pid, d)           => request('POST',   `/projects/${pid}/tickets`, d),
    update: (pid, tid, d)      => request('PATCH',  `/projects/${pid}/tickets/${tid}`, d),
    delete: (pid, tid)         => request('DELETE', `/projects/${pid}/tickets/${tid}`),
    reply:  (pid, tid, body, extra) => request('POST', `/projects/${pid}/tickets/${tid}/replies`, { body, ...extra }),
    sendToGithub: (pid, tid) => request('POST', `/projects/${pid}/tickets/${tid}/github`),
  },
  activity: {
    list: (pid, limit=50) => request('GET', `/projects/${pid}/activity?limit=${limit}`),
  },
  // Internal task assignment. Leads create/edit/assign/delete; the assignee
  // (or a lead) changes status and comments — enforced server-side.
  tasks: {
    list:    (pid, q = {})    => request('GET',    `/projects/${pid}/tasks?${new URLSearchParams(q)}`),
    get:     (pid, tid)       => request('GET',    `/projects/${pid}/tasks/${tid}`),
    create:  (pid, d)         => request('POST',   `/projects/${pid}/tasks`, d),
    update:  (pid, tid, d)    => request('PATCH',  `/projects/${pid}/tasks/${tid}`, d),
    delete:  (pid, tid)       => request('DELETE', `/projects/${pid}/tasks/${tid}`),
    comment: (pid, tid, body) => request('POST',   `/projects/${pid}/tasks/${tid}/comments`, { body }),
  },
  me: {
    tasks: (includeDone = false) => request('GET', `/me/tasks${includeDone ? '?include_done=1' : ''}`),
    // Tokens personales para Claude Code (MCP). El token en claro solo viene
    // en la respuesta de create().
    apiTokens: {
      list:   ()   => request('GET',  '/me/api-tokens'),
      create: (d)  => request('POST', '/me/api-tokens', d),
      revoke: (id) => request('POST', `/me/api-tokens/${id}/revoke`),
    },
  },
  // Inbox de propuestas de Claude Code (hallazgos/notas pendientes de revisión).
  mcpProposals: {
    list:    (pid, status = 'pending') => request('GET',  `/projects/${pid}/mcp-proposals?status=${status}`),
    approve: (pid, id)                 => request('POST', `/projects/${pid}/mcp-proposals/${id}/approve`),
    reject:  (pid, id)                 => request('POST', `/projects/${pid}/mcp-proposals/${id}/reject`),
  },
  notifications: {
    list:        (q = {}) => request('GET',  `/notifications?${new URLSearchParams(q)}`),
    unreadCount: ()       => request('GET',  '/notifications/unread-count'),
    markRead:    (id)     => request('POST', `/notifications/${id}/read`),
    markAllRead: ()       => request('POST', '/notifications/read-all'),
  },
  whiteboard: {
    get:  (pid)       => request('GET', `/projects/${pid}/whiteboard`),
    save: (pid, data) => request('PUT', `/projects/${pid}/whiteboard`, { data }),
  },
  // Report builder configuration — cover metadata, section layout and the
  // per-finding editorial data (risk-matrix probability, remediation
  // priority, business impact, executive action, rewritten texts).
  reportConfig: {
    get:  (pid)       => request('GET', `/projects/${pid}/report-config`),
    save: (pid, data) => request('PUT', `/projects/${pid}/report-config`, { data }),
  },
  aiScan: {
    listSessions:  (pid)          => request('GET',    `/projects/${pid}/ai-scan/sessions`),
    getSession:    (pid, sid)     => request('GET',    `/projects/${pid}/ai-scan/sessions/${sid}`),
    createSession: (pid, data)    => request('POST',   `/projects/${pid}/ai-scan/sessions`, data),
    deleteSession: (pid, sid)     => request('DELETE', `/projects/${pid}/ai-scan/sessions/${sid}`),
    renameSession: (pid, sid, name) => request('PATCH', `/projects/${pid}/ai-scan/sessions/${sid}`, { name }),
    updateSession: (pid, sid, data) => request('PATCH', `/projects/${pid}/ai-scan/sessions/${sid}`, data),
  },
  import: {
    scan: (pid, file) => {
      const fd = new FormData();
      fd.append('file', file);
      return requestUpload('POST', `/projects/${pid}/import/scan`, fd);
    },
  },
  templates: {
    search: (q = '')  => request('GET',    `/templates?q=${encodeURIComponent(q)}`),
    save:   (d)       => request('POST',   `/templates`, d),
    delete: (id)      => request('DELETE', `/templates/${id}`),
  },
  compliance: {
    pciDss: () => request('GET', `/compliance/frameworks/pci-dss`),
  },
  reportTemplates: {
    list:   ()             => request('GET',    `/report-templates`),
    create: (name, data)   => request('POST',   `/report-templates`, { name, data }),
    update: (id, name, data) => request('PUT',  `/report-templates/${id}`, { name, data }),
    delete: (id)           => request('DELETE', `/report-templates/${id}`),
  },
  portal: {
    auth: (token, password) => fetch(`${API_BASE}/portal/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, password }),
    }).then(async r => {
      const d = await r.json();
      if (!r.ok) { const e = new ApiError(r.status, d.error || 'Auth failed'); e.data = d; throw e; }
      return d;
    }),
    links: {
      list:   (pid)       => request('GET',  `/projects/${pid}/portal/links`),
      create: (pid, data) => request('POST', `/projects/${pid}/portal/links`, data),
      revoke: (pid, id)   => request('POST', `/projects/${pid}/portal/links/${id}/revoke`),
    },
    setPassword: (pid, password, require_password) =>
                   request('PATCH', `/projects/${pid}`, { portal_password: password, portal_require_password: require_password }),
    session: portalSession,
  },
};

window.api           = api;
window.tokens        = tokens;
window.portalSession = portalSession;