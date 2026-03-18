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

window.switchAuthTab = switchAuthTab;
window.doLogin       = doLogin;
window.doRegister    = doRegister;

boot();
