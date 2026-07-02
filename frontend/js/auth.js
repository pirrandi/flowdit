// ── auth.js — only used by index.html ────────────────────────────────

async function boot() {
  if (api.auth.hasSession()) {
    try {
      await api.auth.me();
      window.location.href = await resolveHome();
      return;
    } catch {
      api.auth.clearTokens();
    }
  }
  hide('loading-overlay');
  document.getElementById('login-screen').style.display = 'flex';

  const ssoError = new URLSearchParams(window.location.search).get('ssoError');
  if (ssoError) {
    const err = document.getElementById('login-error');
    err.textContent = ssoError;
    err.style.display = 'block';
  }
}

async function resolveHome() {
  return 'projects.html';
}

function switchAuthTab(tab, btn) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('login-form').style.display    = tab === 'login'    ? '' : 'none';
  document.getElementById('register-form').style.display = tab === 'register' ? '' : 'none';
}

let _ssoStartUrl = null;

function onLoginIdentifierChange() {
  // Editing the field after an SSO offer was shown invalidates it — revert
  // to the normal password flow until the next blur re-checks.
  if (_ssoStartUrl) {
    _ssoStartUrl = null;
    document.getElementById('login-sso-cta').style.display = 'none';
    document.getElementById('login-pass-group').style.display = '';
    document.getElementById('login-btn').style.display = '';
  }
}

async function checkSsoForIdentifier() {
  const identifier = document.getElementById('login-user').value.trim();
  if (!identifier.includes('@')) return;
  try {
    const res = await api.auth.sso.check(identifier);
    if (!res.available) return;
    _ssoStartUrl = res.startUrl;
    document.getElementById('login-sso-btn').textContent = `Continue with ${res.organizationName}`;
    document.getElementById('login-sso-cta').style.display = '';
    document.getElementById('login-pass-group').style.display = 'none';
    document.getElementById('login-btn').style.display = 'none';
  } catch { /* SSO check failing silently just leaves the normal password flow available */ }
}

function continueWithSso() {
  if (!_ssoStartUrl) return;
  window.location.href = `${window.FLOWDIT_API}${_ssoStartUrl}`;
}

async function doLogin() {
  const login = document.getElementById('login-user').value.trim();
  const pass  = document.getElementById('login-pass').value;
  const err   = document.getElementById('login-error');
  const btn   = document.getElementById('login-btn');
  err.style.display = 'none';
  btn.disabled = true; btn.textContent = 'Connecting...';
  try {
    const data = await api.auth.login(login, pass);
    api.auth.setTokens(data.accessToken, data.refreshToken);
    localStorage.setItem('fd_user', JSON.stringify(data.user));
    window.location.href = await resolveHome();
  } catch(e) {
    err.textContent = e.message;
    err.style.display = 'block';
  } finally {
    btn.disabled = false; btn.textContent = 'Access Terminal';
  }
}

async function doRegister() {
  const user  = document.getElementById('reg-user').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const pass  = document.getElementById('reg-pass').value;
  const pass2 = document.getElementById('reg-pass2').value;
  const err   = document.getElementById('reg-error');
  const btn   = document.getElementById('reg-btn');
  err.style.display = 'none';
  if (pass !== pass2) { err.textContent = 'Passwords do not match'; err.style.display = 'block'; return; }
  btn.disabled = true; btn.textContent = 'Creating...';
  try {
    const data = await api.auth.register(user, email, pass);
    api.auth.setTokens(data.accessToken, data.refreshToken);
    localStorage.setItem('fd_user', JSON.stringify(data.user));
    window.location.href = await resolveHome();
  } catch(e) {
    err.textContent = e.message;
    err.style.display = 'block';
  } finally {
    btn.disabled = false; btn.textContent = 'Create Account';
  }
}

window.switchAuthTab           = switchAuthTab;
window.doLogin                 = doLogin;
window.doRegister              = doRegister;
window.onLoginIdentifierChange = onLoginIdentifierChange;
window.checkSsoForIdentifier   = checkSsoForIdentifier;
window.continueWithSso         = continueWithSso;

boot();
