/**
 * CTI Platform — Unified API Configuration
 * assets/js/api-config.js
 *
 * Database-driven tile grid + slide-out configuration panel.
 * Enhanced with clear status indicators and user-friendly design.
 */
document.addEventListener('DOMContentLoaded', async () => {

  const API_BASE  = 'php/api/api_keys.php';
  const AUTH_BASE = 'php/api/auth.php';

  /* ── DOM refs ──────────────────────────────────────────────────────────── */
  const grid          = document.getElementById('sfGrid');
  const search        = document.getElementById('sfSearch');
  const tabs          = document.querySelectorAll('#sfTabs .api-tab');
  const counter       = document.getElementById('sfResultCount');
  const filterHint    = document.getElementById('sfFilterHint');
  const elTotal       = document.getElementById('statTotal');
  const elEnabled     = document.getElementById('statEnabled');
  const elDisabled    = document.getElementById('statDisabled');
  const elConfigured  = document.getElementById('statConfigured');
  const elMissing     = document.getElementById('statMissing');
  const elFree        = document.getElementById('statFree');
  const elLoad        = document.getElementById('apisLoadStatus');
  const activeCount   = document.getElementById('apisActiveCount');
  const slideout      = document.getElementById('apiSlideout');
  const overlay       = document.getElementById('apiSlideoutOverlay');
  const toast         = document.getElementById('apiToast');
  const statusPills   = document.querySelectorAll('#statusFilters .status-pill');

  /* ── Category metadata ─────────────────────────────────────────────── */
  const CAT_META = {
    threat:    { label: 'Threat Intel',    color: 'crimson' },
    network:   { label: 'IP & Network',   color: '' },
    dns:       { label: 'Domain & DNS',   color: '' },
    malware:   { label: 'Malware',        color: 'crimson' },
    osint:     { label: 'OSINT',          color: 'rose' },
    leaks:     { label: 'Leaks',          color: 'crimson' },
    identity:  { label: 'Identity',       color: 'rose' },
    infra:     { label: 'Infrastructure', color: '' },
    blocklist: { label: 'Blocklists',     color: 'crimson' },
    extract:   { label: 'Extractors',     color: 'rose' },
    tools:     { label: 'Tools',          color: '' },
    uncategorized: { label: 'Other',      color: 'dim' },
  };

  /* ── Color cycling per category ─────────────────────────────────────── */
  const catColors = {};
  let cidx = 0;
  const cycle = ['', 'crimson', 'rose'];
  for (const cat in CAT_META) {
    catColors[cat] = CAT_META[cat].color || cycle[cidx % 3];
    if (!CAT_META[cat].color) cidx++;
  }

  /* ── State ────────────────────────────────────────────────────────────── */
  let modules      = [];
  let activeCat    = 'all';
  let activeStatus = 'all';
  let isAdmin      = false;

  /* ── SVG icons ─────────────────────────────────────────────────────── */
  const lockSvg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
  const checkSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>';
  const xSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
  const warnSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';

  /* ── Helpers ────────────────────────────────────────────────────────── */
  function abbr(name) {
    if (name.startsWith('Tool - ')) return name.slice(7, 9).toUpperCase();
    const clean = name.replace(/[^a-zA-Z0-9 ]/g, ' ').replace(/\s+/g, ' ').trim();
    const w = clean.split(' ');
    if (w.length === 1) return w[0].slice(0, 2).toUpperCase();
    return (w[0][0] + w[1][0]).toUpperCase();
  }

  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  }

  /** Compute a user-friendly status for each module */
  function getModuleStatus(m) {
    if (!m.requires_key) return 'free';
    if (m.has_key && m.is_enabled) return 'enabled';
    if (m.has_key && !m.is_enabled) return 'disabled';
    return 'missing'; // requires key but none configured
  }

  /** Status badge HTML for a tile */
  function getStatusBadge(m) {
    const status = getModuleStatus(m);
    switch (status) {
      case 'enabled':
        return `<span class="sf-tile-badge sf-badge-enabled" title="Enabled &amp; Configured">${checkSvg} On</span>`;
      case 'disabled':
        return `<span class="sf-tile-badge sf-badge-disabled" title="Configured but Disabled">${xSvg} Off</span>`;
      case 'missing':
        return `<span class="sf-tile-badge sf-badge-missing" title="API Key Required">${warnSvg} Key needed</span>`;
      case 'free':
        return `<span class="sf-tile-badge sf-badge-free" title="Free — No API Key Required">${checkSvg} Free</span>`;
    }
  }

  /** Status dot for the tile corner */
  function getStatusDot(m) {
    const status = getModuleStatus(m);
    const map = {
      enabled:  '<span class="sf-tile-status sf-status-configured"></span>',
      disabled: '<span class="sf-tile-status sf-status-disabled"></span>',
      missing:  '<span class="sf-tile-status sf-status-missing"></span>',
      free:     '<span class="sf-tile-status sf-status-free"></span>',
    };
    return map[status] || '';
  }

  /** Check if a module passes the current status filter */
  function passesStatusFilter(m) {
    if (activeStatus === 'all') return true;
    const status = getModuleStatus(m);
    if (activeStatus === 'configured') return status === 'enabled' || status === 'disabled';
    return status === activeStatus;
  }

  /* ── Determine role ────────────────────────────────────────────────── */
  try {
    const sess = await fetch(`${AUTH_BASE}?action=session`, { credentials: 'same-origin' });
    const data = await sess.json();
    isAdmin = (data?.user?.role || '').toLowerCase() === 'admin';
  } catch { /* treat as non-admin */ }

  /* ── Fetch modules from DB ──────────────────────────────────────────── */
  try {
    const res  = await fetch(`${API_BASE}?action=list`, { credentials: 'same-origin' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Load failed.');
    modules = data.apis || [];
    if (elLoad) elLoad.textContent = `${modules.length} modules loaded`;
  } catch (err) {
    if (elLoad) elLoad.textContent = 'Failed to load';
    showToast('error', err.message || 'Could not load API configurations.');
    return;
  }

  /* ── Init display ──────────────────────────────────────────────────── */
  updateStats();
  updateTabCounts();
  render();

  /* ══════════════════════════════════════════════════════════════════════
     STATS
     ══════════════════════════════════════════════════════════════════════ */

  function updateStats() {
    const total      = modules.length;
    const free       = modules.filter(m => !m.requires_key).length;
    const keyed      = total - free;
    const enabled    = modules.filter(m => m.is_enabled && m.has_key).length;
    const disabled   = modules.filter(m => m.has_key && !m.is_enabled).length;
    const configured = modules.filter(m => !!m.has_key).length;
    const missing    = modules.filter(m => m.requires_key && !m.has_key).length;

    if (elTotal)      elTotal.textContent      = total;
    if (elEnabled)    elEnabled.textContent     = enabled;
    if (elDisabled)   elDisabled.textContent    = disabled;
    if (elConfigured) elConfigured.textContent  = configured;
    if (elMissing)    elMissing.textContent     = missing;
    if (elFree)       elFree.textContent        = free;
    if (activeCount)  activeCount.innerHTML     = `&#9679; ${enabled} Active`;

    // Update status pill counts
    const counts = { all: total, enabled, disabled, configured, missing, free };
    statusPills.forEach(pill => {
      const st = pill.dataset.status;
      const countSpan = pill.querySelector('.status-pill-count');
      if (countSpan) {
        countSpan.textContent = counts[st] ?? '';
      } else if (counts[st] !== undefined) {
        // Append count span if not yet created
        const span = document.createElement('span');
        span.className = 'status-pill-count';
        span.textContent = counts[st];
        pill.appendChild(span);
      }
    });
  }

  function updateTabCounts() {
    const counts = { all: modules.length };
    modules.forEach(m => {
      counts[m.category] = (counts[m.category] || 0) + 1;
    });
    tabs.forEach(tab => {
      const cat = tab.dataset.cat;
      const countEl = tab.querySelector('.api-tab-count');
      if (countEl && counts[cat] !== undefined) {
        countEl.textContent = counts[cat];
      }
    });
  }

  /* ══════════════════════════════════════════════════════════════════════
     TILE GRID RENDERING
     ══════════════════════════════════════════════════════════════════════ */

  function render() {
    if (!grid) return;
    const q = (search ? search.value : '').toLowerCase().trim();
    let html = '';
    let shown = 0;
    let lastCat = '';

    // Sort modules by category, then name
    const sorted = [...modules].sort((a, b) => {
      const catOrder = Object.keys(CAT_META);
      const ai = catOrder.indexOf(a.category);
      const bi = catOrder.indexOf(b.category);
      if (ai !== bi) return ai - bi;
      return a.name.localeCompare(b.name);
    });

    for (const m of sorted) {
      // Category filter
      if (activeCat !== 'all' && m.category !== activeCat) continue;
      // Status filter
      if (!passesStatusFilter(m)) continue;
      // Search filter
      const catLabel = (CAT_META[m.category] || CAT_META.uncategorized).label;
      if (q && m.name.toLowerCase().indexOf(q) === -1
           && catLabel.toLowerCase().indexOf(q) === -1
           && (m.description || '').toLowerCase().indexOf(q) === -1) continue;

      // Category header when showing all
      if (activeCat === 'all' && !q && m.category !== lastCat) {
        // Check if any modules in this category pass the status filter
        const catModules = sorted.filter(x => x.category === m.category && passesStatusFilter(x));
        if (catModules.length === 0) continue;
        lastCat = m.category;
        const meta = CAT_META[m.category] || CAT_META.uncategorized;
        const catEnabled = catModules.filter(x => getModuleStatus(x) === 'enabled').length;
        const colorVar = catColors[m.category] === 'crimson' ? 'accent-secondary' : catColors[m.category] === 'rose' ? 'accent-tertiary' : 'accent';
        html += `<div class="sf-cat-header">
          <span class="sf-cat-title" style="color:var(--${colorVar})">${esc(meta.label)}</span>
          <span class="sf-cat-count">${catModules.length} modules</span>
          ${catEnabled > 0 ? `<span class="sf-cat-active">${catEnabled} active</span>` : ''}
        </div>`;
      }

      const status = getModuleStatus(m);
      const abbrColor = catColors[m.category] || '';
      const statusBadge = getStatusBadge(m);
      const statusDot = getStatusDot(m);

      html += `<div class="sf-tile sf-tile-${status}" data-slug="${esc(m.slug)}" data-cat="${esc(m.category)}" data-status="${status}" role="button" tabindex="0" title="Click to configure ${esc(m.name)}">` +
        statusDot +
        `<span class="sf-tile-abbr ${abbrColor}">${abbr(m.name)}</span>` +
        `<span class="sf-tile-body">` +
          `<span class="sf-tile-name" title="${esc(m.name)}">${esc(m.name)}</span>` +
          `<span class="sf-tile-meta">` +
            `<span class="sf-tile-cat">${esc(catLabel)}</span>` +
            statusBadge +
          `</span>` +
        `</span>` +
        (m.requires_key ? `<span class="sf-tile-key" title="Requires API Key">${lockSvg}</span>` : '') +
        `</div>`;
      shown++;
    }

    if (shown === 0) {
      const filterName = activeStatus !== 'all' ? ` with status "${activeStatus}"` : '';
      html = `<div class="sf-empty">
        <div class="sf-empty-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        </div>
        <p>No modules match your filters${q ? ` for "${esc(q)}"` : ''}${filterName}.</p>
        <button class="btn btn-sm btn-ghost mt-2" id="clearFiltersBtn">Clear all filters</button>
      </div>`;
    }

    grid.innerHTML = html;
    if (counter) counter.textContent = `Showing ${shown} of ${modules.length} modules`;
    if (filterHint) {
      const parts = [];
      if (activeCat !== 'all') parts.push(`Category: ${(CAT_META[activeCat] || CAT_META.uncategorized).label}`);
      if (activeStatus !== 'all') parts.push(`Status: ${activeStatus}`);
      if (q) parts.push(`Search: "${q}"`);
      filterHint.textContent = parts.length > 0 ? parts.join(' | ') : '';
    }

    // Attach tile click handlers
    grid.querySelectorAll('.sf-tile').forEach(tile => {
      tile.addEventListener('click', () => openSlideout(tile.dataset.slug));
      tile.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openSlideout(tile.dataset.slug); }
      });
    });

    // Clear filters button
    const clearBtn = document.getElementById('clearFiltersBtn');
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        activeCat = 'all';
        activeStatus = 'all';
        if (search) search.value = '';
        tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
        tabs[0]?.classList.add('active');
        tabs[0]?.setAttribute('aria-selected', 'true');
        statusPills.forEach(p => p.classList.remove('active'));
        statusPills[0]?.classList.add('active');
        render();
      });
    }
  }

  /* ══════════════════════════════════════════════════════════════════════
     TAB CLICKS (category)
     ══════════════════════════════════════════════════════════════════════ */

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');
      activeCat = tab.dataset.cat;
      render();
    });
  });

  /* ══════════════════════════════════════════════════════════════════════
     STATUS FILTER PILLS
     ══════════════════════════════════════════════════════════════════════ */

  statusPills.forEach(pill => {
    pill.addEventListener('click', () => {
      statusPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      activeStatus = pill.dataset.status;
      render();
    });
  });

  /* ══════════════════════════════════════════════════════════════════════
     SEARCH
     ══════════════════════════════════════════════════════════════════════ */

  if (search) {
    let debounce;
    search.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(render, 120);
    });
  }

  /* ══════════════════════════════════════════════════════════════════════
     SLIDE-OUT PANEL
     ══════════════════════════════════════════════════════════════════════ */

  function openSlideout(slug) {
    const m = modules.find(x => x.slug === slug);
    if (!m || !slideout) return;

    const catLabel = (CAT_META[m.category] || CAT_META.uncategorized).label;
    const colorVar = catColors[m.category] === 'crimson' ? 'accent-secondary' : catColors[m.category] === 'rose' ? 'accent-tertiary' : 'accent';
    const types = Array.isArray(m.supported_types) ? m.supported_types : [];
    const hasKey = !!m.has_key;
    const isEnabled = !!m.is_enabled;
    const status = getModuleStatus(m);

    let healthBadge = '';
    if (m.health_status && m.health_status !== 'unknown') {
      const hClass = m.health_status === 'healthy' ? 'badge-low' : m.health_status === 'degraded' ? 'badge-medium' : 'badge-critical';
      healthBadge = `<span class="badge ${hClass}">${esc(m.health_status)}</span>`;
    }

    // Big status banner
    const statusBannerMap = {
      enabled:  { cls: 'slideout-status-enabled',  icon: checkSvg, label: 'Enabled & Active', desc: 'This module is configured and actively running during scans.' },
      disabled: { cls: 'slideout-status-disabled', icon: xSvg,     label: 'Disabled',         desc: 'This module has an API key but is currently turned off.' },
      missing:  { cls: 'slideout-status-missing',  icon: warnSvg,  label: 'Key Required',     desc: 'This module needs an API key to function. Add one below.' },
      free:     { cls: 'slideout-status-free',     icon: checkSvg, label: 'Free Module',      desc: 'This module works without an API key. No setup needed.' },
    };
    const sb = statusBannerMap[status];

    slideout.innerHTML = `
      <!-- Close button -->
      <button class="slideout-close" id="slideoutClose" aria-label="Close panel">&times;</button>

      <!-- Header -->
      <div class="slideout-header">
        <h3 class="slideout-title" style="color:var(--${colorVar})">${esc(m.name)}</h3>
        <div class="flex items-center gap-2 mt-2" style="flex-wrap:wrap">
          <span class="badge badge-info">${esc(catLabel)}</span>
          ${m.requires_key ? '<span class="badge badge-medium">Key Required</span>' : '<span class="badge badge-low">Free</span>'}
          ${healthBadge}
        </div>
      </div>

      <!-- Status Banner -->
      <div class="slideout-status-banner ${sb.cls}">
        <div class="slideout-status-icon">${sb.icon}</div>
        <div class="slideout-status-text">
          <strong>${sb.label}</strong>
          <span>${sb.desc}</span>
        </div>
        ${isAdmin && m.requires_key ? `
        <label class="toggle-switch-modern">
          <input type="checkbox" id="slideoutToggleCheck" ${isEnabled ? 'checked' : ''} data-slug="${esc(m.slug)}">
          <span class="toggle-slider"></span>
        </label>` : ''}
      </div>

      <!-- Description -->
      <div class="slideout-section">
        <p class="slideout-desc">${esc(m.description || 'No description available.')}</p>
        ${m.docs_url ? `<a href="${esc(m.docs_url)}" target="_blank" rel="noopener noreferrer" class="slideout-link">
          <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          View API Documentation
        </a>` : ''}
      </div>

      <!-- Metadata -->
      <div class="slideout-section">
        <span class="label">Module Details</span>
        <div class="slideout-meta-grid">
          <div>
            <span class="label">Base URL</span>
            <p class="slideout-meta-value" style="word-break:break-all;">${esc(m.base_url || '(internal)')}</p>
          </div>
          <div>
            <span class="label">Rate Limit</span>
            <p class="slideout-meta-value">${m.rate_limit ? esc(m.rate_limit) + ' req/min' : 'No limit'}</p>
          </div>
          <div>
            <span class="label">Auth Type</span>
            <p class="slideout-meta-value">${esc((m.auth_type || 'none').replace('_', ' '))}</p>
          </div>
          <div>
            <span class="label">Last Updated</span>
            <p class="slideout-meta-value">${m.updated_at ? esc(m.updated_at.slice(0, 10)) : 'Never'}</p>
          </div>
        </div>
      </div>

      <!-- Supported Query Types -->
      ${types.length > 0 ? `
      <div class="slideout-section">
        <span class="label">Works With</span>
        <div class="slideout-types mt-2">
          ${types.map(t => `<span class="badge badge-info">${esc(t)}</span>`).join('')}
        </div>
      </div>` : ''}

      <!-- API Key Management (Admin Only) -->
      ${isAdmin && m.requires_key ? `
      <div class="slideout-section slideout-key-section">
        <span class="label">API Key</span>
        <form class="slideout-key-form mt-2" id="slideoutKeyForm" onsubmit="return false">
          <div class="input-group mb-3">
            <span class="prefix">&#128274;</span>
            <input type="password" class="input slideout-key-input" id="slideoutKeyInput"
                   placeholder="${hasKey ? 'Enter new key to replace...' : 'Paste your API key here...'}"
                   maxlength="500" autocomplete="new-password" spellcheck="false" data-lpignore="true"
                   aria-label="API key for ${esc(m.name)}">
            <button class="btn btn-sm btn-ghost slideout-peek-btn" type="button" id="slideoutPeek" aria-label="Toggle key visibility">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>
          <div class="flex gap-2" style="flex-wrap:wrap;">
            <button class="btn btn-sm btn-glitch slideout-save-btn" type="submit" id="slideoutSave" data-slug="${esc(m.slug)}">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="20 6 9 17 4 12"/></svg>
              Save Key
            </button>
            ${hasKey ? `
            <button class="btn btn-sm btn-secondary slideout-clear-btn" type="button" id="slideoutClear" data-slug="${esc(m.slug)}">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/></svg>
              Remove Key
            </button>` : ''}
          </div>
        </form>
      </div>

      <!-- Health Check -->
      <div class="slideout-section">
        <span class="label">Connection Test</span>
        <p class="slideout-help-text">Test if the API is reachable and your key works.</p>
        <div class="flex items-center gap-2 mt-2">
          <button class="btn btn-sm btn-outline slideout-health-btn" id="slideoutHealth" data-slug="${esc(m.slug)}">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            Test Connection
          </button>
          <span class="label slideout-health-result" id="slideoutHealthResult"></span>
        </div>
      </div>
      ` : ''}

      ${!isAdmin && m.requires_key ? `
      <div class="slideout-section">
        <div class="slideout-notice">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <span>Contact your administrator to configure the API key for this module.</span>
        </div>
      </div>
      ` : ''}
    `;

    // Show slideout
    slideout.classList.add('open');
    if (overlay) overlay.classList.add('active');
    document.body.style.overflow = 'hidden';

    // Attach slideout event handlers
    attachSlideoutEvents(m.slug);
  }

  function closeSlideout() {
    if (slideout) slideout.classList.remove('open');
    if (overlay)  overlay.classList.remove('active');
    document.body.style.overflow = '';
  }

  // Close on overlay click
  if (overlay) overlay.addEventListener('click', closeSlideout);

  // Close on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && slideout?.classList.contains('open')) closeSlideout();
  });

  function attachSlideoutEvents(slug) {
    // Close button
    const closeBtn = document.getElementById('slideoutClose');
    if (closeBtn) closeBtn.addEventListener('click', closeSlideout);

    // Peek button
    const peekBtn = document.getElementById('slideoutPeek');
    const keyInput = document.getElementById('slideoutKeyInput');
    if (peekBtn && keyInput) {
      peekBtn.addEventListener('click', () => {
        keyInput.type = keyInput.type === 'password' ? 'text' : 'password';
      });
    }

    // Save key
    const saveBtn = document.getElementById('slideoutSave');
    const keyForm = document.getElementById('slideoutKeyForm');
    if (saveBtn) {
      const handler = async (e) => {
        e.preventDefault();
        await handleSaveKey(slug);
      };
      saveBtn.addEventListener('click', handler);
      if (keyForm) keyForm.addEventListener('submit', handler);
    }

    // Clear key
    const clearBtn = document.getElementById('slideoutClear');
    if (clearBtn) clearBtn.addEventListener('click', () => handleClearKey(slug));

    // Toggle checkbox
    const toggleCheck = document.getElementById('slideoutToggleCheck');
    if (toggleCheck) {
      toggleCheck.addEventListener('change', () => handleToggle(slug, !toggleCheck.checked));
    }

    // Health check
    const healthBtn = document.getElementById('slideoutHealth');
    if (healthBtn) healthBtn.addEventListener('click', () => handleHealthCheck(slug));
  }

  /* ══════════════════════════════════════════════════════════════════════
     API KEY CRUD
     ══════════════════════════════════════════════════════════════════════ */

  async function handleSaveKey(slug) {
    const input = document.getElementById('slideoutKeyInput');
    if (!input) return;

    const keyValue = input.value.trim();
    if (!keyValue) {
      showToast('error', 'Please enter an API key before saving.');
      input.focus();
      return;
    }

    const saveBtn = document.getElementById('slideoutSave');
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

      showToast('success', `API key saved for <strong>${esc(slugToName(slug))}</strong>.`);
      input.value = '';
      input.type = 'password';

      await refreshModules();
      openSlideout(slug);
    } catch (err) {
      showToast('error', err.message || 'Could not save API key.');
    } finally {
      setBtnLoading(saveBtn, false, 'Save Key');
    }
  }

  async function handleClearKey(slug) {
    if (!confirm(`Remove the API key for ${slugToName(slug)}? This will disable the integration until a new key is provided.`)) return;

    const clearBtn = document.getElementById('slideoutClear');
    setBtnLoading(clearBtn, true, 'Removing...');

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

      showToast('success', `API key removed for <strong>${esc(slugToName(slug))}</strong>.`);
      await refreshModules();
      openSlideout(slug);
    } catch (err) {
      showToast('error', err.message || 'Could not clear API key.');
    } finally {
      setBtnLoading(clearBtn, false, 'Remove Key');
    }
  }

  async function handleToggle(slug, currentlyEnabled) {
    const newState = !currentlyEnabled;
    const toggleCheck = document.getElementById('slideoutToggleCheck');
    if (toggleCheck) toggleCheck.disabled = true;

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

      showToast('success', `${slugToName(slug)} ${newState ? 'enabled' : 'disabled'}.`);
      await refreshModules();
      openSlideout(slug);
    } catch (err) {
      showToast('error', err.message || 'Could not update status.');
      if (toggleCheck) { toggleCheck.checked = currentlyEnabled; toggleCheck.disabled = false; }
    }
  }

  async function handleHealthCheck(slug) {
    const healthBtn = document.getElementById('slideoutHealth');
    const resultEl  = document.getElementById('slideoutHealthResult');
    setBtnLoading(healthBtn, true, 'Testing...');
    if (resultEl) resultEl.textContent = '';

    try {
      const csrf = await getCsrfToken();
      const res  = await fetch(`${API_BASE}?action=health_check`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slug, _csrf_token: csrf }),
      });
      const data = await res.json();

      if (resultEl) {
        if (data.status === 'healthy') {
          resultEl.innerHTML = `<span style="color:var(--accent)">&#10003; Healthy</span> (${data.latency_ms || 0}ms)`;
        } else if (data.status === 'degraded') {
          resultEl.innerHTML = `<span style="color:var(--accent-tertiary)">&#9888; Degraded</span> (${data.latency_ms || 0}ms)`;
        } else {
          resultEl.innerHTML = `<span style="color:var(--accent-secondary)">&#10007; ${esc(data.error || 'Down')}</span>`;
        }
      }

      const m = modules.find(x => x.slug === slug);
      if (m) m.health_status = data.status || 'unknown';
    } catch (err) {
      if (resultEl) resultEl.innerHTML = `<span style="color:var(--accent-secondary)">&#10007; ${esc(err.message)}</span>`;
    } finally {
      setBtnLoading(healthBtn, false, 'Test Connection');
    }
  }

  /* ══════════════════════════════════════════════════════════════════════
     HELPERS
     ══════════════════════════════════════════════════════════════════════ */

  async function refreshModules() {
    try {
      const res  = await fetch(`${API_BASE}?action=list`, { credentials: 'same-origin' });
      const data = await res.json();
      if (res.ok) {
        modules = data.apis || [];
        updateStats();
        updateTabCounts();
        render();
      }
    } catch { /* ignore refresh errors */ }
  }

  async function getCsrfToken() {
    const res  = await fetch(`${AUTH_BASE}?action=csrf`, { credentials: 'same-origin' });
    const data = await res.json();
    return data.csrf_token;
  }

  function slugToName(slug) {
    return modules.find(m => m.slug === slug)?.name || slug;
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
