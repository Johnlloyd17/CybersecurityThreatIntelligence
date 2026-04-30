/**
 * CTI Platform â€” Authentication Module
 * Shared auth utilities for CSRF, login, logout, session checks.
 */
const Auth = (() => {
  const API_BASE = 'php/api/auth.php';
  const LOGIN_PANEL_URL = 'index.php#hero-login-panel';

  async function fetchJSON(url, opts = {}) {
    const res = await fetch(url, { credentials: 'same-origin', ...opts });
    let data;
    try { data = await res.json(); } catch { data = {}; }
    if (!res.ok) throw { status: res.status, message: data.error || data.message || 'Request failed', ...data };
    return data;
  }

  async function getCsrfToken() {
    const { csrf_token } = await fetchJSON(`${API_BASE}?action=csrf`);
    return csrf_token;
  }

  async function login(email, password) {
    const token = await getCsrfToken();
    return fetchJSON(`${API_BASE}?action=login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, _csrf_token: token }),
    });
  }

  async function logout() {
    const token = await getCsrfToken();
    return fetchJSON(`${API_BASE}?action=logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ _csrf_token: token }),
    });
  }

  async function getSession() {
    try {
      return await fetchJSON(`${API_BASE}?action=session`);
    } catch {
      return null;
    }
  }

  /** Redirect unauthenticated users away from protected pages. */
  async function requireAuth() {
    const session = await getSession();
    if (!session || !session.user) {
      window.location.href = LOGIN_PANEL_URL;
      return null;
    }
    return session.user;
  }

  /** Redirect already-authenticated users away from public pages. */
  async function redirectIfAuth() {
    const session = await getSession();
    if (session && session.user) {
      window.location.href = 'dashboard.php';
    }
  }

  return { getCsrfToken, login, logout, getSession, requireAuth, redirectIfAuth };
})();
