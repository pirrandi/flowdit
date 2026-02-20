// ─────────────────────────────────────────────────────────────────────
// HackList API Client
// ─────────────────────────────────────────────────────────────────────

const API_BASE = window.HACKLIST_API || 'http://localhost:4000/api';

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Token storage
const tokens = {
  get access()  { return localStorage.getItem('hl_access'); },
  get refresh() { return localStorage.getItem('hl_refresh'); },
  set(access, refresh) {
    localStorage.setItem('hl_access', access);
    if (refresh) localStorage.setItem('hl_refresh', refresh);
  },
  clear() {
    localStorage.removeItem('hl_access');
    localStorage.removeItem('hl_refresh');
    localStorage.removeItem('hl_user');
  }
};

let _refreshPromise = null;

async function request(method, path, body, retry = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (tokens.access) headers['Authorization'] = `Bearer ${tokens.access}`;

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body != null ? JSON.stringify(body) : undefined,
  });

  // Token expired → try refresh once
  if (res.status === 401 && retry && tokens.refresh) {
    if (!_refreshPromise) {
      _refreshPromise = refreshTokens().finally(() => { _refreshPromise = null; });
    }
    const ok = await _refreshPromise;
    if (ok) return request(method, path, body, false);
    tokens.clear();
    window.dispatchEvent(new Event('hl:logout'));
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
    if (data.accessToken) {
      tokens.set(data.accessToken, data.refreshToken);
      return true;
    }
    return false;
  } catch { return false; }
}

const api = {
  // ── AUTH ─────────────────────────────────────────────────────────
  auth: {
    register: (username, email, password) =>
      request('POST', '/auth/register', { username, email, password }),
    login: (login, password) =>
      request('POST', '/auth/login', { login, password }),
    logout: () =>
      request('POST', '/auth/logout', { refreshToken: tokens.refresh }).finally(() => tokens.clear()),
    me: () => request('GET', '/auth/me'),
    setTokens: (access, refresh) => tokens.set(access, refresh),
    clearTokens: () => tokens.clear(),
    hasSession: () => !!tokens.access,
  },

  // ── PROJECTS ─────────────────────────────────────────────────────
  projects: {
    list:   ()         => request('GET',    '/projects'),
    create: (data)     => request('POST',   '/projects', data),
    get:    (id)       => request('GET',    `/projects/${id}`),
    update: (id, data) => request('PATCH',  `/projects/${id}`, data),
    delete: (id)       => request('DELETE', `/projects/${id}`),
    join:   (token)    => request('POST',   '/projects/join', { token }),
  },

  // ── MEMBERS ──────────────────────────────────────────────────────
  members: {
    list:       (pid)           => request('GET',    `/projects/${pid}/members`),
    changeRole: (pid, uid, role)=> request('PATCH',  `/projects/${pid}/members/${uid}`, { role }),
    remove:     (pid, uid)      => request('DELETE', `/projects/${pid}/members/${uid}`),
  },

  // ── INVITES ──────────────────────────────────────────────────────
  invites: {
    list:   (pid)              => request('GET',    `/projects/${pid}/invites`),
    send:   (pid, username, role='editor') =>
                                  request('POST',   `/projects/${pid}/invites`, { username, role }),
    cancel: (pid, inviteId)    => request('DELETE', `/projects/${pid}/invites/${inviteId}`),
  },

  // ── WSTG ─────────────────────────────────────────────────────────
  wstg: {
    getAll:    (pid)              => request('GET',   `/projects/${pid}/wstg`),
    setStatus: (pid, testId, status) =>
                                    request('PATCH', `/projects/${pid}/wstg/${testId}/status`, { status }),
    setNote:   (pid, testId, note)=> request('PATCH', `/projects/${pid}/wstg/${testId}/note`, { note }),
    setItem:   (pid, testId, idx, checked) =>
                                    request('PATCH', `/projects/${pid}/wstg/${testId}/items/${idx}`, { checked }),
  },

  // ── PORTSWIGGER ──────────────────────────────────────────────────
  ps: {
    getAll: (pid)                    => request('GET',   `/projects/${pid}/ps`),
    toggle: (pid, catId, labIdx, done) =>
                                       request('PATCH', `/projects/${pid}/ps/${catId}/${labIdx}`, { done }),
  },

  // ── CUSTOM VULNS ─────────────────────────────────────────────────
  vulns: {
    list:   (pid)       => request('GET',    `/projects/${pid}/vulns`),
    create: (pid, data) => request('POST',   `/projects/${pid}/vulns`, data),
    update: (pid, id, data) => request('PATCH', `/projects/${pid}/vulns/${id}`, data),
    delete: (pid, id)   => request('DELETE', `/projects/${pid}/vulns/${id}`),
  },
};

window.api    = api;
window.tokens = tokens;
