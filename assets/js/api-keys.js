/**
 * CTI Platform — API Key Management
 * assets/js/api-keys.js
 *
 * Loads API configurations from the server (keys are NEVER returned in full),
 * renders cards with key status, and handles secure key submission/clearing.
 *
 * Security:
 *  - API keys submitted via POST with CSRF token
 *  - Keys stored server-side only; frontend never receives the raw value
 *  - Input fields are type="password" (browser doesn't cache/autofill plaintext)
 *  - Key inputs cleared from DOM immediately after successful submission
 */
document.addEventListener('DOMContentLoaded', async () => {

  const API_BASE  = 'php/api/api_keys.php';
  const AUTH_BASE = 'php/api/auth.php';

  const grid        = document.getElementById('apiCardsGrid');
  const toast       = document.getElementById('apiToast');
  const activeCount = document.getElementById('apisActiveCount');
  const loadStatus  = document.getElementById('apisLoadStatus');
  const analystNote = document.getElementById('analystNotice');

  // ── Determine current user role (already fetched by dashboard.js's auth gate)
  // Wait for dashboard.js to place the role in a data attribute on body, or
  // re-fetch the session directly (safe — read-only endpoint).
  let isAdmin = false;
  try {
    const sess = await fetch(`${AUTH_BASE}?action=session`, { credentials: 'same-origin' });
    const data = await sess.json();
    isAdmin = (data?.user?.role || '').toLowerCase() === 'admin';
  } catch { /* treat as non-admin */ }

  if (!isAdmin && analystNote) analystNote.classList.remove('hidden');

  // ── Fetch API list ────────────────────────────────────────────────────────
  let apis = [];
  try {
    const res  = await fetch(`${API_BASE}?action=list`, { credentials: 'same-origin' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Load failed.');
    apis = data.apis || [];
    if (loadStatus) loadStatus.textContent = `${apis.length} sources loaded`;
  } catch (err) {
    if (loadStatus) loadStatus.textContent = 'Failed to load';
    showToast('error', err.message || 'Could not load API configurations.');
    return;
  }

  // ── Render cards ──────────────────────────────────────────────────────────
  renderCards(apis);
  updateActiveCount(apis);

  // ────────────────────────────────────────────────────────────────────────────

  function renderCards(list) {
    if (!grid) return;
    grid.innerHTML = '';

    if (list.length === 0) {
      grid.innerHTML = '<p class="label" style="grid-column:1/-1;padding:2rem 0;">No API sources configured.</p>';
      return;
    }

    // Color cycle for API names
    const colorClasses = [
      'accent-text', 'secondary-text', 'tertiary-text',
      'accent-text', 'secondary-text', 'tertiary-text',
    ];

    list.forEach((api, idx) => {
      const colorClass = colorClasses[idx % colorClasses.length];
      const hasKey     = !!api.has_key;
      const isEnabled  = !!api.is_enabled;

      const card = document.createElement('div');
      card.className = 'card-holo api-config-card';
      card.dataset.slug = api.slug;

      card.innerHTML = `
        <div class="corner-tl"></div>
        <div class="corner-tr"></div>
        <div class="corner-bl"></div>
        <div class="corner-br"></div>

        <!-- Header row -->
        <div class="flex items-center justify-between mb-3">
          <h3 class="${colorClass} api-card-name">${escHtml(api.name)}</h3>
          <div class="flex items-center gap-2">
            ${isAdmin ? `
            <button class="btn btn-sm api-toggle-btn ${isEnabled ? 'btn-secondary' : 'btn-outline'}"
                    data-slug="${escHtml(api.slug)}"
                    data-enabled="${isEnabled ? '1' : '0'}"
                    title="${isEnabled ? 'Disable this API source' : 'Enable this API source'}"
                    aria-label="${isEnabled ? 'Disable' : 'Enable'} ${escHtml(api.name)}">
              ${isEnabled ? 'Enabled' : 'Disabled'}
            </button>` : `
            <span class="badge ${isEnabled ? 'badge-low' : 'badge-medium'}">${isEnabled ? '&#9679; Active' : '&#9675; Inactive'}</span>
            `}
          </div>
        </div>

        <!-- Description -->
        <p style="color:var(--muted-fg); font-size:0.8rem; margin-bottom:1rem;">${escHtml(api.description || '')}</p>

        <!-- Metadata row -->
        <div class="api-detail-grid mb-4">
          <div>
            <span class="label">Base URL</span>
            <br><span class="accent-text" style="font-size:0.75rem; word-break:break-all;">${escHtml(api.base_url)}</span>
          </div>
          <div>
            <span class="label">Rate Limit</span>
            <br><span>${escHtml(String(api.rate_limit ?? '—'))} req/min</span>
          </div>
          <div>
            <span class="label">Last Updated</span>
            <br><span class="label" style="color:var(--fg)">${api.updated_at ? escHtml(api.updated_at.slice(0, 10)) : '—'}</span>
          </div>
        </div>

        <!-- API Key section -->
        <div class="api-key-section">
          <div class="api-key-status flex items-center gap-2 mb-3" id="keyStatus-${escHtml(api.slug)}">
            <span class="label">API Key</span>
            ${hasKey
              ? `<span class="badge badge-low key-indicator">&#10003; Configured</span>`
              : `<span class="badge badge-medium key-indicator">&#9888; Not configured</span>`
            }
          </div>

          ${isAdmin ? `
          <!-- Key form (hidden by default, shown when Configure Key is clicked) -->
          <form class="api-key-form hidden" id="keyForm-${escHtml(api.slug)}"
                aria-label="API key form for ${escHtml(api.name)}"
                onsubmit="return false">
            <div class="input-group mb-3">
              <span class="prefix">&#128274;</span>
              <input
                type="password"
                class="input api-key-input"
                id="keyInput-${escHtml(api.slug)}"
                name="api_key"
                placeholder="Paste API key here..."
                maxlength="500"
                autocomplete="new-password"
                aria-label="API key for ${escHtml(api.name)}"
                spellcheck="false"
                data-lpignore="true"
              >
              <button class="btn btn-sm btn-ghost key-peek-btn"
                      type="button"
                      data-target="keyInput-${escHtml(api.slug)}"
                      aria-label="Toggle key visibility"
                      title="Show / hide key">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
            </div>
            <div class="flex gap-2" style="flex-wrap:wrap;">
              <button class="btn btn-sm btn-glitch api-key-save-btn"
                      type="submit"
                      data-slug="${escHtml(api.slug)}"
                      aria-label="Save API key for ${escHtml(api.name)}">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="20 6 9 17 4 12"/></svg>
                Save Key
              </button>
              ${hasKey ? `
              <button class="btn btn-sm btn-secondary api-key-clear-btn"
                      type="button"
                      data-slug="${escHtml(api.slug)}"
                      aria-label="Remove API key for ${escHtml(api.name)}">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>
                Clear Key
              </button>` : ''}
              <button class="btn btn-sm btn-ghost api-key-cancel-btn"
                      type="button"
                      data-slug="${escHtml(api.slug)}"
                      aria-label="Cancel">Cancel</button>
            </div>
          </form>

          <!-- Configure button (default visible for admin) -->
          <div class="api-key-actions" id="keyActions-${escHtml(api.slug)}">
            <button class="btn btn-sm api-configure-btn"
                    data-slug="${escHtml(api.slug)}"
                    aria-expanded="false">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 19.07a10 10 0 0 1 0-14.14"/></svg>
              ${hasKey ? 'Update Key' : 'Configure Key'}
            </button>
          </div>
          ` : ''}
        </div>
      `;

      grid.appendChild(card);
    });

    // Attach event listeners after rendering
    attachCardEvents();
  }

  // ── Card event delegation ──────────────────────────────────────────────────

  function attachCardEvents() {
    if (!grid) return;

    // "Configure Key" / "Update Key" button → show the form
    grid.querySelectorAll('.api-configure-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const slug = btn.dataset.slug;
        showKeyForm(slug);
      });
    });

    // "Cancel" → hide the form
    grid.querySelectorAll('.api-key-cancel-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const slug = btn.dataset.slug;
        hideKeyForm(slug);
      });
    });

    // "Save Key" — handle both form submit and button click
    grid.querySelectorAll('.api-key-form').forEach(form => {
      form.addEventListener('submit', (e) => {
        e.preventDefault();
        const slug = form.querySelector('.api-key-save-btn')?.dataset.slug;
        if (slug) handleSaveKey(slug);
      });
    });
    grid.querySelectorAll('.api-key-save-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        handleSaveKey(btn.dataset.slug);
      });
    });

    // "Clear Key" button
    grid.querySelectorAll('.api-key-clear-btn').forEach(btn => {
      btn.addEventListener('click', () => handleClearKey(btn.dataset.slug));
    });

    // Toggle enable/disable
    grid.querySelectorAll('.api-toggle-btn').forEach(btn => {
      btn.addEventListener('click', () => handleToggle(btn.dataset.slug, btn.dataset.enabled === '1'));
    });

    // Show/hide key peek buttons
    grid.querySelectorAll('.key-peek-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = document.getElementById(btn.dataset.target);
        if (!input) return;
        input.type = input.type === 'password' ? 'text' : 'password';
        btn.setAttribute('aria-label', input.type === 'password' ? 'Show key' : 'Hide key');
      });
    });
  }

  function showKeyForm(slug) {
    const form    = document.getElementById(`keyForm-${slug}`);
    const actions = document.getElementById(`keyActions-${slug}`);
    const btn     = grid?.querySelector(`.api-configure-btn[data-slug="${slug}"]`);
    if (form)    form.classList.remove('hidden');
    if (actions) actions.classList.add('hidden');
    if (btn)     btn.setAttribute('aria-expanded', 'true');
    // Focus the input
    const input = document.getElementById(`keyInput-${slug}`);
    if (input) setTimeout(() => input.focus(), 50);
  }

  function hideKeyForm(slug) {
    const form    = document.getElementById(`keyForm-${slug}`);
    const actions = document.getElementById(`keyActions-${slug}`);
    if (form) {
      form.classList.add('hidden');
      // Wipe the input value so the key isn't lingering in the DOM
      const input = form.querySelector('.api-key-input');
      if (input) input.value = '';
    }
    if (actions) actions.classList.remove('hidden');
  }

  // ── Save API key ───────────────────────────────────────────────────────────

  async function handleSaveKey(slug) {
    const input = document.getElementById(`keyInput-${slug}`);
    if (!input) return;

    const keyValue = input.value.trim();
    if (!keyValue) {
      showToast('error', 'Please enter an API key before saving.');
      input.focus();
      return;
    }

    const saveBtn = grid?.querySelector(`.api-key-save-btn[data-slug="${slug}"]`);
    setBtnLoading(saveBtn, true, 'Saving...');

    try {
      const csrf = await getCsrfToken();
      const res  = await fetch(`${API_BASE}?action=save`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slug, api_key: keyValue, _csrf_token: csrf }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Save failed.');

      showToast('success', `&#10003; API key saved for <strong>${slugToName(slug, apis)}</strong>.`);

      // Wipe key from DOM immediately — never leave it in the input
      input.value = '';
      // Ensure input is back to password type
      input.type = 'password';

      // Refresh the card to show updated status without a full page reload
      await refreshApiCard(slug);
    } catch (err) {
      showToast('error', err.message || 'Could not save API key.');
    } finally {
      setBtnLoading(saveBtn, false, 'Save Key');
    }
  }

  // ── Clear API key ──────────────────────────────────────────────────────────

  async function handleClearKey(slug) {
    if (!confirm(`Remove the API key for ${slugToName(slug, apis)}? This will disable the integration until a new key is provided.`)) {
      return;
    }

    const clearBtn = grid?.querySelector(`.api-key-clear-btn[data-slug="${slug}"]`);
    setBtnLoading(clearBtn, true, 'Clearing...');

    try {
      const csrf = await getCsrfToken();
      const res  = await fetch(`${API_BASE}?action=clear`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slug, _csrf_token: csrf }),
      });
      const data = await res.json();

      if (!res.ok) throw new Error(data.error || 'Clear failed.');

      showToast('success', `API key removed for <strong>${slugToName(slug, apis)}</strong>.`);
      await refreshApiCard(slug);
    } catch (err) {
      showToast('error', err.message || 'Could not clear API key.');
    } finally {
      setBtnLoading(clearBtn, false, 'Clear Key');
    }
  }

  // ── Toggle enable/disable ──────────────────────────────────────────────────

  async function handleToggle(slug, currentlyEnabled) {
    const newState = !currentlyEnabled;
    const toggleBtn = grid?.querySelector(`.api-toggle-btn[data-slug="${slug}"]`);
    setBtnLoading(toggleBtn, true, '...');

    try {
      const csrf = await getCsrfToken();
      const res  = await fetch(`${API_BASE}?action=toggle`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slug, enabled: newState, _csrf_token: csrf }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Toggle failed.');

      showToast('success', `${slugToName(slug, apis)} ${newState ? 'enabled' : 'disabled'}.`);
      await refreshApiCard(slug);
    } catch (err) {
      showToast('error', err.message || 'Could not update status.');
    } finally {
      setBtnLoading(toggleBtn, false, currentlyEnabled ? 'Enabled' : 'Disabled');
    }
  }

  // ── Re-fetch a single API card after a mutation ────────────────────────────

  async function refreshApiCard(slug) {
    try {
      const res  = await fetch(`${API_BASE}?action=list`, { credentials: 'same-origin' });
      const data = await res.json();
      if (!res.ok) return;

      apis = data.apis || [];
      const updated = apis.find(a => a.slug === slug);
      if (!updated) return;

      // Re-render only the updated card
      const oldCard = grid?.querySelector(`.api-config-card[data-slug="${slug}"]`);
      if (!oldCard) {
        // Fallback: re-render all
        renderCards(apis);
        return;
      }

      // Create a temporary container, render all, then swap just this card
      const tmp = document.createElement('div');
      tmp.innerHTML = '';
      const colorClasses = ['accent-text', 'secondary-text', 'tertiary-text', 'accent-text', 'secondary-text', 'tertiary-text'];
      const idx  = apis.findIndex(a => a.slug === slug);
      const colorClass = colorClasses[idx % colorClasses.length];
      const hasKey     = !!updated.has_key;
      const isEnabled  = !!updated.is_enabled;

      const newCard = document.createElement('div');
      newCard.className = 'card-holo api-config-card';
      newCard.dataset.slug = updated.slug;
      newCard.innerHTML = buildCardInnerHTML(updated, colorClass, hasKey, isEnabled);

      oldCard.replaceWith(newCard);
      updateActiveCount(apis);
      attachCardEvents();
      hideKeyForm(slug);
    } catch { /* ignore refresh errors */ }
  }

  // Extracted inner HTML builder so we don't duplicate code
  function buildCardInnerHTML(api, colorClass, hasKey, isEnabled) {
    return `
      <div class="corner-tl"></div>
      <div class="corner-tr"></div>
      <div class="corner-bl"></div>
      <div class="corner-br"></div>
      <div class="flex items-center justify-between mb-3">
        <h3 class="${colorClass} api-card-name">${escHtml(api.name)}</h3>
        <div class="flex items-center gap-2">
          ${isAdmin ? `
          <button class="btn btn-sm api-toggle-btn ${isEnabled ? 'btn-secondary' : 'btn-outline'}"
                  data-slug="${escHtml(api.slug)}"
                  data-enabled="${isEnabled ? '1' : '0'}"
                  title="${isEnabled ? 'Disable' : 'Enable'} this API source"
                  aria-label="${isEnabled ? 'Disable' : 'Enable'} ${escHtml(api.name)}">
            ${isEnabled ? 'Enabled' : 'Disabled'}
          </button>` : `
          <span class="badge ${isEnabled ? 'badge-low' : 'badge-medium'}">${isEnabled ? '&#9679; Active' : '&#9675; Inactive'}</span>
          `}
        </div>
      </div>
      <p style="color:var(--muted-fg); font-size:0.8rem; margin-bottom:1rem;">${escHtml(api.description || '')}</p>
      <div class="api-detail-grid mb-4">
        <div>
          <span class="label">Base URL</span>
          <br><span class="accent-text" style="font-size:0.75rem; word-break:break-all;">${escHtml(api.base_url)}</span>
        </div>
        <div>
          <span class="label">Rate Limit</span>
          <br><span>${escHtml(String(api.rate_limit ?? '—'))} req/min</span>
        </div>
        <div>
          <span class="label">Last Updated</span>
          <br><span class="label" style="color:var(--fg)">${api.updated_at ? escHtml(api.updated_at.slice(0, 10)) : '—'}</span>
        </div>
      </div>
      <div class="api-key-section">
        <div class="api-key-status flex items-center gap-2 mb-3" id="keyStatus-${escHtml(api.slug)}">
          <span class="label">API Key</span>
          ${hasKey
            ? `<span class="badge badge-low key-indicator">&#10003; Configured</span>`
            : `<span class="badge badge-medium key-indicator">&#9888; Not configured</span>`
          }
        </div>
        ${isAdmin ? `
        <form class="api-key-form hidden" id="keyForm-${escHtml(api.slug)}"
              aria-label="API key form for ${escHtml(api.name)}"
              onsubmit="return false">
          <div class="input-group mb-3">
            <span class="prefix">&#128274;</span>
            <input
              type="password"
              class="input api-key-input"
              id="keyInput-${escHtml(api.slug)}"
              name="api_key"
              placeholder="Paste API key here..."
              maxlength="500"
              autocomplete="new-password"
              aria-label="API key for ${escHtml(api.name)}"
              spellcheck="false"
              data-lpignore="true"
            >
            <button class="btn btn-sm btn-ghost key-peek-btn"
                    type="button"
                    data-target="keyInput-${escHtml(api.slug)}"
                    aria-label="Toggle key visibility">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>
          <div class="flex gap-2" style="flex-wrap:wrap;">
            <button class="btn btn-sm btn-glitch api-key-save-btn" type="submit" data-slug="${escHtml(api.slug)}" aria-label="Save API key">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="20 6 9 17 4 12"/></svg>
              Save Key
            </button>
            ${hasKey ? `
            <button class="btn btn-sm btn-secondary api-key-clear-btn" type="button" data-slug="${escHtml(api.slug)}" aria-label="Remove API key">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>
              Clear Key
            </button>` : ''}
            <button class="btn btn-sm btn-ghost api-key-cancel-btn" type="button" data-slug="${escHtml(api.slug)}">Cancel</button>
          </div>
        </form>
        <div class="api-key-actions" id="keyActions-${escHtml(api.slug)}">
          <button class="btn btn-sm api-configure-btn" data-slug="${escHtml(api.slug)}" aria-expanded="false">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 19.07a10 10 0 0 1 0-14.14"/></svg>
            ${hasKey ? 'Update Key' : 'Configure Key'}
          </button>
        </div>
        ` : ''}
      </div>
    `;
  }

  // ── Utility functions ──────────────────────────────────────────────────────

  function updateActiveCount(list) {
    if (!activeCount) return;
    const active = list.filter(a => a.is_enabled).length;
    activeCount.textContent = `&#9679; ${active} / ${list.length} Active`;
  }

  async function getCsrfToken() {
    const res  = await fetch(`${AUTH_BASE}?action=csrf`, { credentials: 'same-origin' });
    const data = await res.json();
    return data.csrf_token;
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function slugToName(slug, list) {
    return list.find(a => a.slug === slug)?.name || slug;
  }

  function setBtnLoading(btn, loading, label) {
    if (!btn) return;
    btn.disabled = loading;
    btn.textContent = label;
  }

  function showToast(type, html) {
    if (!toast) return;
    toast.className = `api-toast api-toast-${type}`;
    toast.innerHTML = html;
    toast.classList.remove('hidden');

    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => {
      toast.classList.add('hidden');
    }, 5000);
  }

});
