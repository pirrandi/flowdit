// ── auth.js — only used by index.html ────────────────────────────────

async function boot() {
  if (api.auth.hasSession()) {
    try {
      await api.auth.me();
      window.location.href = await resolveHome();
      return;
    } catch (err) {
      if (err.status === 401) api.auth.clearTokens();
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
  return 'projects';
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

let _mfaChallengeToken = null;

async function doLogin() {
  const login = document.getElementById('login-user').value.trim();
  const pass  = document.getElementById('login-pass').value;
  const err   = document.getElementById('login-error');
  const btn   = document.getElementById('login-btn');
  err.style.display = 'none';
  btn.disabled = true; btn.textContent = 'Connecting...';
  try {
    const data = await api.auth.login(login, pass);
    if (data.mfaRequired) {
      _mfaChallengeToken = data.challengeToken;
      document.getElementById('login-form').style.display = 'none';
      document.getElementById('login-mfa-form').style.display = '';
      document.getElementById('login-mfa-code').value = '';
      document.getElementById('login-mfa-error').style.display = 'none';
      document.getElementById('login-mfa-code').focus();
      return;
    }
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

function cancelMfaChallenge() {
  _mfaChallengeToken = null;
  document.getElementById('login-mfa-form').style.display = 'none';
  document.getElementById('login-form').style.display = '';
  document.getElementById('login-pass').value = '';
}

async function doVerifyMfa() {
  const code = document.getElementById('login-mfa-code').value.trim();
  const err  = document.getElementById('login-mfa-error');
  const btn  = document.getElementById('login-mfa-btn');
  err.style.display = 'none';
  if (!code) return;
  btn.disabled = true; btn.textContent = 'Verifying...';
  try {
    const data = await api.auth.mfa.verify(_mfaChallengeToken, code);
    api.auth.setTokens(data.accessToken, data.refreshToken);
    localStorage.setItem('fd_user', JSON.stringify(data.user));
    window.location.href = await resolveHome();
  } catch(e) {
    err.textContent = e.message;
    err.style.display = 'block';
  } finally {
    btn.disabled = false; btn.textContent = 'Verify';
  }
}

window.doLogin                 = doLogin;
window.onLoginIdentifierChange = onLoginIdentifierChange;
window.checkSsoForIdentifier   = checkSsoForIdentifier;
window.continueWithSso         = continueWithSso;
window.doVerifyMfa             = doVerifyMfa;
window.cancelMfaChallenge      = cancelMfaChallenge;

boot();
