/**
 * CTI Platform — Dashboard Statistics
 * Fetches live data from php/api/stats.php and populates the overview panel.
 * Runs only on pages that contain #panelOverview.
 */
document.addEventListener('DOMContentLoaded', async () => {
  if (!document.getElementById('panelOverview')) return;

  await Promise.allSettled([
    fetchOverview(),
    fetchSeverity(),
    fetchQueryTypes(),
    fetchApiStatus(),
    fetchRecent(),
  ]);
});

async function fetchStats(action) {
  const res = await fetch('php/api/stats.php?action=' + action, { credentials: 'same-origin' });
  if (!res.ok) throw new Error('stats/' + action + ' returned ' + res.status);
  return res.json();
}

async function fetchOverview() {
  try {
    const d = await fetchStats('overview');
    setText('statTotalQueries',     fmtNum(d.total_queries));
    setText('statQueriesLabel',     '+' + fmtNum(d.week_queries) + ' this week');
    setText('statThreatsFound',     fmtNum(d.threats_found));
    setText('statDetectionRate',    (d.detection_rate ?? 0) + '% detection rate');
    setText('statApisActive',       d.apis_active + '/' + d.apis_total);
    setText('statApisLabel',        d.apis_active === d.apis_total ? 'All operational' : d.apis_active + ' operational');
    setText('statAvgResponse',      d.avg_response ? parseFloat(d.avg_response).toFixed(1) + 's' : '—');
    setText('statAvgResponseLabel', d.avg_response ? 'aggregate avg' : 'No data yet');
  } catch { /* keep placeholder dashes */ }
}

async function fetchSeverity() {
  try {
    const d    = await fetchStats('severity');
    const rows = d.severity || [];
    const map  = {};
    rows.forEach(r => { map[r.severity] = Number(r.cnt); });
    const keys = ['critical', 'high', 'medium', 'low', 'info'];
    const max  = Math.max(...keys.map(k => map[k] || 0), 1);
    keys.forEach(key => {
      const cnt = map[key] || 0;
      setStyle('sevFill'  + cap(key), 'width', Math.round((cnt / max) * 100) + '%');
      setText( 'sevCount' + cap(key), fmtNum(cnt));
    });
  } catch { /* keep defaults */ }
}

async function fetchQueryTypes() {
  try {
    const d    = await fetchStats('query_types');
    const rows = d.query_types || [];
    const slotMap = {
      ip: 'Ip',
      ipv4: 'Ip',
      ipv6: 'Ip',
      domain: 'Domain',
      hostname: 'Domain',
      url: 'Url',
      hash: 'Hash',
      cve: 'Cve',
      email: 'Email',
    };
    const base = { Ip: 0, Domain: 0, Url: 0, Hash: 0, Cve: 0, Email: 0 };

    rows.forEach(r => {
      const rawType = String(r.type || '').trim().toLowerCase();
      const slot = slotMap[rawType];
      if (!slot) return;
      base[slot] += Number(r.cnt) || 0;
    });

    const max = Math.max(...Object.values(base), 1);
    Object.entries(base).forEach(([slot, count]) => {
      const pct = Math.round((count / max) * 100);
      setText('qtValue' + slot, fmtNum(count));
      setStyle('qtFill' + slot, 'width', pct + '%');
    });
  } catch { /* keep defaults */ }
}

/* ── API Status: module-level state ─────────────────────────── */
let _allApis        = [];
let _apiFilter      = 'all';   // 'all' | 'configured' | 'missing'
let _apiSearch      = '';
let _apiPage        = 1;
const _apiPerPage   = 12;

async function fetchApiStatus() {
  try {
    const d  = await fetchStats('api_status');
    _allApis = d.apis || [];

    /* pill counts */
    const configured = _allApis.filter(a => a.is_enabled && a.has_key).length;
    const missing    = _allApis.length - configured;
    setText('apiPillCountAll',        _allApis.length);
    setText('apiPillCountConfigured', configured);
    setText('apiPillCountMissing',    missing);

    renderApiGrid();
    wireApiControls();
  } catch { /* keep defaults */ }
}

function renderApiGrid() {
  const grid  = document.getElementById('apiStatusGrid');
  const pager = document.getElementById('apiStatusPager');
  if (!grid) return;

  /* 1. filter by status */
  let visible = _allApis.filter(a => {
    if (_apiFilter === 'configured') return a.is_enabled && a.has_key;
    if (_apiFilter === 'missing')    return !(a.is_enabled && a.has_key);
    return true;
  });

  /* 2. filter by search */
  const q = _apiSearch.toLowerCase().trim();
  if (q) visible = visible.filter(a => (a.name || '').toLowerCase().includes(q));

  /* 3. heading */
  const allOn = _allApis.length > 0 && _allApis.every(a => a.is_enabled && a.has_key);
  setText('apiStatusHeading',
    visible.length === 0 ? 'No results'
    : allOn ? 'All systems operational'
    : 'Some APIs not configured'
  );

  /* 4. paginate */
  const totalPages = Math.max(1, Math.ceil(visible.length / _apiPerPage));
  if (_apiPage > totalPages) _apiPage = totalPages;
  const slice = visible.slice((_apiPage - 1) * _apiPerPage, _apiPage * _apiPerPage);

  /* 5. render items */
  if (slice.length === 0) {
    grid.innerHTML = `<div style="grid-column:1/-1;padding:1.5rem;text-align:center;" class="label">No APIs match your filter.</div>`;
  } else {
    grid.innerHTML = slice.map(a => {
      const on   = a.is_enabled && a.has_key;
      const dot  = on ? '&#9679;' : '&#9651;';
      const cls  = on ? 'badge-low' : 'badge-high';
      const rate = (a.rate_limit && a.has_key) ? a.rate_limit + ' req/min' : 'No key set';
      return `<div class="api-status-item">
        <span class="badge ${cls}">${dot}</span>
        <span>${escHtml(a.name)}</span>
        <span class="label">${escHtml(rate)}</span>
      </div>`;
    }).join('');
  }

  /* 6. render pagination */
  if (!pager) return;
  if (totalPages <= 1) {
    pager.innerHTML = visible.length > 0
      ? `<span class="page-info">${visible.length} API${visible.length !== 1 ? 's' : ''}</span>`
      : '';
    return;
  }

  let html = `<button class="page-btn" ${_apiPage <= 1 ? 'disabled' : ''} data-api-page="${_apiPage - 1}">&laquo;</button>`;
  const maxV = 5;
  let sp = Math.max(1, _apiPage - Math.floor(maxV / 2));
  let ep = Math.min(totalPages, sp + maxV - 1);
  if (ep - sp < maxV - 1) sp = Math.max(1, ep - maxV + 1);
  if (sp > 1) html += `<button class="page-btn" data-api-page="1">1</button><span class="page-info">...</span>`;
  for (let i = sp; i <= ep; i++) {
    html += `<button class="page-btn${i === _apiPage ? ' active' : ''}" data-api-page="${i}">${i}</button>`;
  }
  if (ep < totalPages) html += `<span class="page-info">...</span><button class="page-btn" data-api-page="${totalPages}">${totalPages}</button>`;
  html += `<button class="page-btn" ${_apiPage >= totalPages ? 'disabled' : ''} data-api-page="${_apiPage + 1}">&raquo;</button>`;
  html += `<span class="page-info">${visible.length} total</span>`;
  pager.innerHTML = html;

  pager.querySelectorAll('.page-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const p = parseInt(btn.dataset.apiPage, 10);
      if (!isNaN(p)) { _apiPage = p; renderApiGrid(); }
    });
  });
}

function wireApiControls() {
  /* search */
  const search = document.getElementById('apiStatusSearch');
  let debounce;
  search?.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      _apiSearch = search.value;
      _apiPage   = 1;
      renderApiGrid();
    }, 220);
  });

  /* filter pills */
  document.querySelectorAll('#apiStatusPills .status-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('#apiStatusPills .status-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      _apiFilter = pill.dataset.apiFilter;
      _apiPage   = 1;
      renderApiGrid();
    });
  });
}

async function fetchRecent() {
  try {
    const d     = await fetchStats('recent');
    const tbody = document.getElementById('recentActivityBody');
    if (!tbody) return;
    const rows = d.recent || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="label" style="text-align:center;padding:1.5rem;">No query history yet.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => {
      const score   = Number(r.risk_score || 0);
      const sev     = score >= 75 ? 'critical' : score >= 55 ? 'high' : score >= 30 ? 'medium' : 'low';
      const ts      = (r.queried_at || '').replace('T', ' ').substring(0, 19) || '—';
      return `<tr>
        <td class="label">${escHtml(ts)}</td>
        <td><span class="badge badge-info">${escHtml((r.query_type || '—').toUpperCase())}</span></td>
        <td class="accent-text" style="word-break:break-all;max-width:200px;">${escHtml(r.query_value || '—')}</td>
        <td>${escHtml(r.api_source || '—')}</td>
        <td><span class="badge badge-${escHtml(sev)}">${cap(sev)}</span></td>
        <td><span class="badge badge-low">Completed</span></td>
      </tr>`;
    }).join('');
  } catch { /* keep defaults */ }
}

/* ── Utilities ───────────────────────────────────────────── */
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setStyle(id, prop, val) {
  const el = document.getElementById(id);
  if (el) el.style[prop] = val;
}

function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }
function fmtNum(n) { return Number(n || 0).toLocaleString(); }

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
