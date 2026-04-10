document.addEventListener('DOMContentLoaded', () => {
  const showToast = window.CtiStaticUi?.showToast || ((message) => window.alert(message));
  const clone = window.CtiStaticUi?.clone || ((value) => JSON.parse(JSON.stringify(value)));

  const API_QUERY = 'php/api/query.php';
  const API_AUTH = 'php/api/auth.php';
  const params = new URLSearchParams(window.location.search);
  const scanKey = params.get('id');

  let pollTimer = null;
  let pollInFlight = false;
  let isRealScan = false;
  let scanData = null;
  let resultsData = [];
  let browseData = [];
  let correlationsData = [];
  let logsData = [];
  let scanSettingsData = { meta_information: [], global_settings: [], module_settings: [] };
  const scanSettingsBaseline = {
    global_settings: Array.isArray(window.CTI_SCAN_SETTINGS_BASELINE?.global_settings)
      ? clone(window.CTI_SCAN_SETTINGS_BASELINE.global_settings)
      : [],
    module_settings: Array.isArray(window.CTI_SCAN_SETTINGS_BASELINE?.module_settings)
      ? clone(window.CTI_SCAN_SETTINGS_BASELINE.module_settings)
      : [],
  };
  let browseViewMode = 'types';
  let browseSelectedType = null;
  let browseSearchLabel = null;
  let logFilterMode = 'all';
  let graphSnapshot = { nodes: [], edges: [] };
  let eventGraphData = null;
  let eventStatsData = null;
  let dnsaIssueFilter = { severity: 'all', group: 'all', search: '' };
  let dnsaIssueGroups = [];
  const MAX_LOG_ROWS_RENDER = 500;
  const MAX_GRAPH_NODES_RENDER = 250;
  const MAX_GRAPH_EDGES_RENDER = 500;

  const tabs = document.querySelectorAll('.scaninfo-tab');
  const panels = document.querySelectorAll('.scaninfo-panel');

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function fmtDate(value) {
    if (!value) return '--';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toISOString().replace('T', ' ').slice(0, 19);
  }

  function capitalize(value) {
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  function shortLabel(value, max = 42) {
    const text = String(value ?? '').trim();
    if (!text) return '--';
    return text.length > max ? `${text.slice(0, max - 1)}…` : text;
  }

  async function getCsrfToken() {
    try {
      const res = await fetch(`${API_AUTH}?action=csrf`, { credentials: 'same-origin' });
      const data = await res.json();
      return data.csrf_token || null;
    } catch {
      return null;
    }
  }

  function switchToTab(tabName) {
    tabs.forEach((tab) => tab.classList.remove('active'));
    panels.forEach((panel) => panel.classList.remove('active'));
    const tab = [...tabs].find((item) => item.dataset.tab === tabName);
    tab?.classList.add('active');
    document.getElementById(`tab${capitalize(tabName)}`)?.classList.add('active');
    renderActivePanel();
  }

  tabs.forEach((tab) => {
    tab.addEventListener('click', () => switchToTab(tab.dataset.tab));
  });

  function loadDraftPayload() {
    try {
      const raw = sessionStorage.getItem('cti-static-draft-scan');
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function loadStaticPayload(key) {
    if (!key) return null;
    if (key === 'preview-draft') return loadDraftPayload();
    const details = window.CTI_STATIC_SCAN_DETAILS || {};
    return details[String(key)] ? clone(details[String(key)]) : null;
  }

  async function loadBackendPayload(scanId) {
    try {
      const res = await fetch(`${API_QUERY}?action=scan_detail&id=${encodeURIComponent(scanId)}`, {
        credentials: 'same-origin',
      });
      if (!res.ok) return null;
      const data = await res.json();
      return data.scan ? data : null;
    } catch {
      return null;
    }
  }

  function applyPayload(payload) {
    scanData = payload.scan || {};
    resultsData = Array.isArray(payload.results) ? payload.results : [];
    browseData = Array.isArray(payload.browse) ? payload.browse : [];
    correlationsData = Array.isArray(payload.correlations) ? payload.correlations : [];
    logsData = Array.isArray(payload.logs) ? payload.logs : [];
    scanSettingsData = payload.scan_settings || { meta_information: [], global_settings: [], module_settings: [] };
    eventGraphData = payload.event_graph || { enabled: false, events: [], relationships: [], handlers: [] };
    eventStatsData = payload.event_stats || null;
  }

  function syncDraftPayload() {
    if (scanKey !== 'preview-draft') return;
    sessionStorage.setItem('cti-static-draft-scan', JSON.stringify({
      scan: scanData,
      results: resultsData,
      browse: browseData,
      correlations: correlationsData,
      logs: logsData,
      scan_settings: scanSettingsData,
    }));
  }

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(async () => {
      if (!isRealScan || !scanData || !['starting', 'running'].includes(scanData.status)) {
        stopPolling();
        return;
      }

      if (pollInFlight) return;

      pollInFlight = true;
      try {
        const payload = await loadBackendPayload(scanKey);
        if (!payload) return;
        applyPayload(payload);
        renderAll();

        if (!['starting', 'running'].includes(scanData.status)) {
          stopPolling();
          showToast(`Scan ${scanData.status}.`);
        }
      } finally {
        pollInFlight = false;
      }
    }, 3000);
  }

  function stopPolling() {
    if (!pollTimer) return;
    clearInterval(pollTimer);
    pollTimer = null;
  }

  function renderHeader() {
    const title = document.getElementById('scanTitle');
    const badge = document.getElementById('scanStatusBadge');
    const backendBadge = document.getElementById('scanBackendBadge');
    if (title) title.textContent = scanData.name || 'Untitled Scan';

    if (badge) {
      const statusMap = {
        running: 'badge-info',
        starting: 'badge-info',
        preview: 'badge-medium',
        finished: 'badge-low',
        aborted: 'badge-critical',
        failed: 'badge-critical',
      };
      badge.className = `scan-status-badge badge ${statusMap[scanData.status] || 'badge-info'}`;
      badge.textContent = String(scanData.status || '').toUpperCase();
    }

    if (backendBadge) {
      const backendLabel = String(scanData.backend_used || '').trim();
      const backendKey = String(scanData.backend_key || '').trim().toLowerCase();
      if (backendLabel) {
        backendBadge.style.display = 'inline-flex';
        backendBadge.textContent = backendLabel;
        backendBadge.title = `Backend used for this scan: ${backendLabel}`;
        let backendClass = 'scan-status-badge badge badge-medium';
        if (backendKey === 'cti-python') {
          backendClass = 'scan-status-badge badge badge-low';
        } else if (backendKey === 'spiderfoot-bridge') {
          backendClass = 'scan-status-badge badge badge-info';
        }
        backendBadge.className = backendClass;
      } else {
        backendBadge.style.display = 'none';
      }
    }

    const stuckBanner = document.getElementById('stuckScanBanner');
    if (stuckBanner) {
      stuckBanner.style.display = (['running', 'starting'].includes(scanData.status) && scanData.stuck) ? 'flex' : 'none';
    }

    document.title = `${scanData.name || 'Scan Details'} - CTI`;
  }

  function renderSummary() {
    const byId = (id) => document.getElementById(id);
    byId('statTotal').textContent = scanData.total_elements || 0;
    byId('statUnique').textContent = scanData.unique_elements || 0;
    byId('statStatus').textContent = String(scanData.status || '').toUpperCase();
    byId('statErrors').textContent = scanData.error_count || 0;

    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    correlationsData.forEach((item) => {
      if (counts[item.severity] !== undefined) counts[item.severity] += 1;
    });

    const corrSummary = byId('corrSummary');
    if (corrSummary) {
      corrSummary.innerHTML = `
        <span class="corr-badge corr-high">High <strong>${counts.high}</strong></span>
        <span class="corr-badge corr-medium">Medium <strong>${counts.medium}</strong></span>
        <span class="corr-badge corr-low">Low <strong>${counts.low}</strong></span>
        <span class="corr-badge corr-info">Info <strong>${counts.info}</strong></span>
      `;
    }

    renderBarChart();
    renderTimeline();
    renderDnsAuditIssues();
  }

  function renderBarChart() {
    const container = document.getElementById('chartContainer');
    if (!container) return;

    if (!browseData.length) {
      container.innerHTML = '<p class="label" style="opacity:0.5;padding:1rem;">No data types to display.</p>';
      return;
    }

    const totalUnique = browseData.reduce((sum, item) => sum + (item.unique_elements || 0), 0) || 1;
    const maxPct = Math.max(...browseData.map((item) => Math.round((item.unique_elements / totalUnique) * 100)), 1);
    const yTicks = [0, 25, 50, 75, 100].filter((tick) => tick <= Math.min(100, maxPct + 20));

    let html = `
      <div class="vbar-chart-wrap">
        <div class="vbar-y-label">Percentage of Unique Elements</div>
        <div class="vbar-inner">
          <div class="vbar-y-axis">`;

    [...yTicks].reverse().forEach((tick) => {
      html += `<span class="vbar-ytick">${tick}</span>`;
    });

    html += '</div><div class="vbar-plot"><div class="vbar-gridlines">';
    yTicks.forEach((tick) => {
      html += `<div class="vbar-gridline" style="bottom:${tick}%"></div>`;
    });
    html += '</div>';

    browseData.forEach((item) => {
      const pct = Math.round((item.unique_elements / totalUnique) * 100);
      html += `
        <div class="vbar-col vbar-col-clickable" data-browse-type="${esc(item.type)}" title="Open ${esc(item.type)}">
          <div class="vbar-bar-wrap">
            <span class="vbar-value">${pct}%</span>
            <div class="vbar-bar" style="height:${pct}%;" title="${esc(item.type)}: ${item.unique_elements} unique (${item.total_elements} total)"></div>
          </div>
          <span class="vbar-label">${esc(item.type)}</span>
        </div>`;
    });

    html += '</div></div></div>';
    container.innerHTML = html;

    container.querySelectorAll('.vbar-col-clickable').forEach((col) => {
      col.addEventListener('click', () => {
        browseSelectedType = col.dataset.browseType;
        browseViewMode = 'elements';
        browseSearchLabel = null;
        switchToTab('browse');
        renderBrowseElements(browseSelectedType);
      });
    });
  }

  function renderTimeline() {
    const container = document.getElementById('timelineContent');
    if (!container) return;

    const liveRows = resultsData.filter((item) => !['failed', 'aborted'].includes(item.status));
    if (!liveRows.length) {
      container.innerHTML = '<p class="label" style="opacity:0.5;">No temporal data available.</p>';
      return;
    }

    const buckets = new Map();
    liveRows.forEach((item) => {
      const stamp = fmtDate(item.queried_at).slice(0, 16);
      const bucket = buckets.get(stamp) || { count: 0, passes: new Set(), types: new Set() };
      bucket.count += 1;
      bucket.passes.add(item.enrichment_pass ?? 0);
      bucket.types.add(item.data_type || item.query_type || 'unknown');
      buckets.set(stamp, bucket);
    });

    container.innerHTML = [...buckets.entries()].map(([stamp, bucket]) => `
      <div class="log-entry log-info">
        <span class="log-time">${esc(stamp)}</span>
        <span class="log-level">EVENTS</span>
        <span class="log-msg">${bucket.count} result(s), ${bucket.types.size} type(s), enrichment passes: ${[...bucket.passes].sort((a, b) => a - b).join(', ')}</span>
      </div>
    `).join('');
  }

  function normalizeDnsSeverity(value) {
    const raw = String(value || '').trim().toLowerCase();
    if (['critical', 'high', 'danger', 'error', 'failed'].includes(raw)) return 'critical';
    if (['warning', 'warn', 'medium'].includes(raw)) return 'warning';
    return 'info';
  }

  function safeParseJson(value) {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }

  function extractDnsAuditIssue(row) {
    if (String(row.api_source || '').toLowerCase() !== 'dnsaudit') return null;

    const parsed = safeParseJson(row.result_summary || '');
    if (!parsed || parsed.kind !== 'dnsaudit_issue') return null;

    const severity = normalizeDnsSeverity(parsed.severity || row.severity || parsed.type || '');
    const group = String(parsed.category_group || parsed.group || parsed.category || 'DNS Security Issues').trim();
    const title = String(parsed.issue_title || parsed.title || parsed.issue_slug || 'DNSAudit Issue').trim();
    const description = String(parsed.description || parsed.details || '').trim();
    const recommendation = String(parsed.recommendation || parsed.fix || parsed.solution || '').trim();
    const docsUrl = String(parsed.docs_url || '').trim();
    const issueSlug = String(parsed.issue_slug || '').trim();

    return {
      id: row.id,
      severity,
      group: group || 'DNS Security Issues',
      title: title || 'DNSAudit Issue',
      description,
      recommendation,
      docsUrl,
      issueSlug,
      queriedAt: row.queried_at,
    };
  }

  function collectDnsAuditIssues() {
    return resultsData
      .map((row) => extractDnsAuditIssue(row))
      .filter((item) => item !== null);
  }

  function syncDnsIssueGroupOptions(issues) {
    const groups = [...new Set(issues.map((item) => item.group).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const changed = groups.length !== dnsaIssueGroups.length || groups.some((group, idx) => dnsaIssueGroups[idx] !== group);
    if (!changed) return;
    dnsaIssueGroups = groups;

    const select = document.getElementById('dnsaIssueGroup');
    if (!select) return;

    const prev = select.value || 'all';
    select.innerHTML = `<option value="all">All Categories</option>${groups.map((group) => `<option value="${esc(group)}">${esc(group)}</option>`).join('')}`;
    if (groups.includes(prev)) {
      select.value = prev;
    } else {
      select.value = 'all';
      dnsaIssueFilter.group = 'all';
    }
  }

  function renderDnsAuditIssues() {
    const card = document.getElementById('dnsaIssueCard');
    const summary = document.getElementById('dnsaIssueSummary');
    const list = document.getElementById('dnsaIssueList');
    if (!card || !summary || !list) return;

    const issues = collectDnsAuditIssues();
    if (!issues.length) {
      card.style.display = 'none';
      return;
    }
    card.style.display = 'block';

    syncDnsIssueGroupOptions(issues);

    const totals = { critical: 0, warning: 0, info: 0 };
    issues.forEach((item) => { totals[item.severity] += 1; });
    summary.innerHTML = `
      <span class="corr-badge corr-high">Critical <strong>${totals.critical}</strong></span>
      <span class="corr-badge corr-medium">Warning <strong>${totals.warning}</strong></span>
      <span class="corr-badge corr-info">Info <strong>${totals.info}</strong></span>
      <span class="corr-badge corr-low">Total <strong>${issues.length}</strong></span>
    `;

    const filtered = issues.filter((item) => {
      if (dnsaIssueFilter.severity !== 'all' && item.severity !== dnsaIssueFilter.severity) return false;
      if (dnsaIssueFilter.group !== 'all' && item.group !== dnsaIssueFilter.group) return false;
      if (dnsaIssueFilter.search) {
        const hay = `${item.title} ${item.description} ${item.recommendation} ${item.group}`.toLowerCase();
        if (!hay.includes(dnsaIssueFilter.search)) return false;
      }
      return true;
    });

    if (!filtered.length) {
      list.innerHTML = '<div class="scaninfo-empty-notice"><p>No DNSAudit issues match the current filter.</p></div>';
      return;
    }

    list.innerHTML = filtered.map((item) => {
      const badgeClass = item.severity === 'critical'
        ? 'corr-high'
        : (item.severity === 'warning' ? 'corr-medium' : 'corr-info');
      const docsLink = item.docsUrl
        ? `<a href="${esc(item.docsUrl)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-ghost" style="margin-top:8px;">Open Fix Guide</a>`
        : '';
      return `
        <div class="corr-item ${item.severity === 'critical' ? 'corr-item-high' : (item.severity === 'warning' ? 'corr-item-medium' : 'corr-item-info')}">
          <div class="corr-item-header" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
            <span class="corr-badge ${badgeClass}">${esc(item.severity.toUpperCase())}</span>
            <strong>${esc(item.title)}</strong>
            <span class="label" style="opacity:0.7;">${esc(item.group)}</span>
          </div>
          ${item.description ? `<p class="corr-item-detail">${esc(item.description)}</p>` : ''}
          ${item.recommendation ? `<p class="corr-item-detail"><strong>Recommendation:</strong> ${esc(item.recommendation)}</p>` : ''}
          <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;flex-wrap:wrap;">
            <span class="label" style="font-size:0.7rem;opacity:0.6;">${item.issueSlug ? `${esc(item.issueSlug)} · ` : ''}${fmtDate(item.queriedAt)}</span>
            ${docsLink}
          </div>
        </div>
      `;
    }).join('');
  }

  function renderCorrelations() {
    const list = document.getElementById('corrList');
    if (!list) return;

    if (!correlationsData.length) {
      list.innerHTML = `
        <div class="scaninfo-empty-notice">
          <strong>No correlations.</strong>
          <p>No correlation entries found for this scan.</p>
        </div>`;
      return;
    }

    list.innerHTML = correlationsData.map((item) => {
      const sevClass = {
        high: 'corr-item-high',
        medium: 'corr-item-medium',
        low: 'corr-item-low',
        info: 'corr-item-info',
      }[item.severity] || 'corr-item-info';

      return `
        <div class="corr-item ${sevClass}">
          <div class="corr-item-header">
            <span class="corr-badge corr-${esc(item.severity)}">${esc(String(item.severity || '').toUpperCase())}</span>
            <strong>${esc(item.title)}</strong>
          </div>
          ${item.detail ? `<p class="corr-item-detail">${esc(item.detail)}</p>` : ''}
          <div style="display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap;">
            <span class="label" style="font-size:0.7rem;opacity:0.6;">${esc(item.rule_name)} - ${fmtDate(item.created_at)}</span>
            ${(Number(item.linked_result_count || 0) > 0 || (Array.isArray(item.linked_result_ids) && item.linked_result_ids.length))
              ? `<span class="label" style="font-size:0.7rem;opacity:0.7;">Linked events: ${Number(item.linked_result_count || item.linked_result_ids.length || 0)}</span>`
              : ''}
          </div>
        </div>`;
    }).join('');
  }

  function renderBrowse(rows = browseData) {
    const body = document.getElementById('browseBody');
    if (!body) return;

    browseViewMode = 'types';
    browseSelectedType = null;
    browseSearchLabel = null;

    document.getElementById('browseTypeHeaders').style.display = 'table-header-group';
    document.getElementById('browseDrilldownHeaders').style.display = 'none';
    document.getElementById('browseBreadcrumb').style.display = 'none';
    document.getElementById('browseToolbar').style.display = 'none';

    if (!rows.length) {
      body.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:2rem;" class="label">No data elements found.</td></tr>';
      return;
    }

    body.innerHTML = rows.map((item) => `
      <tr class="browse-type-row" data-type="${esc(item.type)}" style="cursor:pointer;">
        <td data-label="Type"><a class="accent-text">${esc(item.type)}</a></td>
        <td data-label="Unique Data Elements" style="text-align:center;">${item.unique_elements}</td>
        <td data-label="Total Data Elements" style="text-align:center;">${item.total_elements}</td>
        <td data-label="Last Data Element">${fmtDate(item.last_element_at)}</td>
      </tr>
    `).join('');

    body.querySelectorAll('.browse-type-row').forEach((row) => {
      row.addEventListener('click', () => {
        browseSelectedType = row.dataset.type;
        browseViewMode = 'elements';
        renderBrowseElements(browseSelectedType);
      });
    });
  }

  function getElementsForType(typeName) {
    const lowerType = String(typeName || '').toLowerCase();
    return resultsData.filter((row) => {
      if (row.status === 'failed') return false;
      if ((row.data_type || '').toLowerCase() === lowerType) return true;
      if ((row.api_category || '').replace(/[_-]/g, ' ').toLowerCase() === lowerType) return true;
      if ((row.query_type || '').replace(/[_-]/g, ' ').toLowerCase() === lowerType) return true;
      return false;
    });
  }

  function normalizeSourceValue(value) {
    const text = String(value || '').trim();
    if (!text || text === 'ROOT') return scanData?.target || 'ROOT';
    if (/^[a-z0-9_-]+:(?!\/\/)/i.test(text)) {
      return text.replace(/^[a-z0-9_-]+:/i, '');
    }
    return text;
  }

  function findAllMatches(pattern, text) {
    const matches = String(text || '').match(pattern);
    return matches ? matches.filter(Boolean) : [];
  }

  function deriveElementValue(item, breadcrumbLabel) {
    const breadcrumbText = String(breadcrumbLabel || '').trim();
    const effectiveType = /^search:/i.test(breadcrumbText)
      ? (item.data_type || item.query_type || '')
      : (breadcrumbLabel || item.data_type || item.query_type || '');
    const typeText = String(effectiveType).toLowerCase();
    const summary = String(item.result_summary || '').trim();
    const fallback = String(item.query_value || '').trim() || summary || '--';

    const ipMatches = findAllMatches(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, summary);
    const domainMatches = findAllMatches(/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})+\b/ig, summary);
    const emailMatches = findAllMatches(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig, summary);
    const urlMatches = findAllMatches(/https?:\/\/[^\s"'<>]+/ig, summary);
    const hashMatches = findAllMatches(/\b[a-f0-9]{32,64}\b/ig, summary);
    const phoneMatches = findAllMatches(/\+?\d[\d\s\-()]{7,}/g, summary);
    const bitcoinMatches = findAllMatches(/\b(?:bc1[a-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, summary);

    if (typeText.includes('ip address') || typeText === 'ip') {
      return ipMatches.at(-1) || fallback;
    }
    if (typeText.includes('email')) {
      return emailMatches[0] || fallback;
    }
    if (typeText.includes('url') || typeText.includes('web content')) {
      return urlMatches[0] || fallback;
    }
    if (typeText.includes('hash')) {
      return hashMatches[0] || fallback;
    }
    if (typeText.includes('phone')) {
      return phoneMatches[0] || fallback;
    }
    if (typeText.includes('bitcoin')) {
      return bitcoinMatches[0] || fallback;
    }
    if (typeText.includes('internet name') || typeText.includes('domain')) {
      return domainMatches[0] || fallback;
    }

    return fallback;
  }

  function deriveSourceElement(item, elementValue) {
    const candidates = [
      normalizeSourceValue(item.source_data),
      normalizeSourceValue(item.source_ref),
      normalizeSourceValue(item.enriched_from),
      String(item.query_value || '').trim(),
      scanData?.target || '',
    ].filter(Boolean);

    const normalizedElement = String(elementValue || '').trim().toLowerCase();
    const source = candidates.find((candidate) => String(candidate).trim().toLowerCase() !== normalizedElement);
    return source || scanData?.target || 'ROOT';
  }

  function renderElementRows(elements, breadcrumbLabel) {
    const body = document.getElementById('browseBody');
    if (!body) return;

    document.getElementById('browseTypeHeaders').style.display = 'none';
    document.getElementById('browseDrilldownHeaders').style.display = 'table-header-group';
    document.getElementById('browseBreadcrumb').style.display = 'block';
    document.getElementById('browseToolbar').style.display = 'block';
    document.getElementById('breadcrumbSeparator').style.display = 'inline';
    document.getElementById('breadcrumbTypeText').textContent = breadcrumbLabel;

    if (!elements.length) {
      body.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:2rem;" class="label">No elements found.</td></tr>';
      return;
    }

    body.innerHTML = elements.map((item) => {
      const elementValue = deriveElementValue(item, breadcrumbLabel);
      const sourceElement = deriveSourceElement(item, elementValue);
      return `
      <tr class="browse-element-row ${item.false_positive ? 'log-warning' : ''}" data-result-id="${item.id}">
        <td style="text-align:center;"><input type="checkbox" class="browse-element-checkbox" value="${item.id}"></td>
        <td data-label="Data Element"><span style="font-family:monospace;font-size:0.9rem;">${esc(elementValue)}</span></td>
        <td data-label="Source Data Element"><span style="font-family:monospace;font-size:0.9rem;">${esc(sourceElement)}</span></td>
        <td data-label="Source Module"><span class="badge badge-info">${esc(item.api_source || item.api_name || 'Unknown')}</span></td>
        <td data-label="Identified">${fmtDate(item.queried_at)}</td>
      </tr>
    `;
    }).join('');

    body.querySelectorAll('.browse-element-row').forEach((row) => {
      row.addEventListener('click', (event) => {
        if (event.target.closest('.browse-element-checkbox')) return;
        const result = resultsData.find((item) => String(item.id) === row.dataset.resultId);
        if (result) toggleElementDetail(row, result);
      });
    });

    const selectAll = document.getElementById('browseSelectAll');
    if (selectAll) {
      selectAll.checked = false;
      selectAll.onchange = () => {
        body.querySelectorAll('.browse-element-checkbox').forEach((checkbox) => {
          checkbox.checked = selectAll.checked;
        });
      };
    }
  }

  function renderBrowseElements(typeName) {
    browseViewMode = 'elements';
    browseSearchLabel = null;
    renderElementRows(getElementsForType(typeName), typeName);
  }

  function renderSearchResults(matches, label) {
    browseViewMode = 'elements';
    browseSelectedType = null;
    browseSearchLabel = label;
    switchToTab('browse');
    renderElementRows(matches, label);
  }

  function toggleElementDetail(row, item) {
    const existing = row.nextElementSibling;
    if (existing?.classList.contains('browse-element-detail')) {
      existing.remove();
      return;
    }

    document.querySelectorAll('.browse-element-detail').forEach((detail) => detail.remove());

    let detailHtml = '';
    const raw = item.result_summary || '';
    try {
      const parsed = JSON.parse(raw);
      detailHtml = renderJsonDetail(parsed);
    } catch {
      detailHtml = raw
        ? `<pre style="margin:0;white-space:pre-wrap;word-break:break-all;font-size:0.78rem;color:var(--fg);max-height:300px;overflow:auto;">${esc(raw)}</pre>`
        : '<span class="label" style="opacity:0.5;">No detailed data available.</span>';
    }

    const detailRow = document.createElement('tr');
    detailRow.className = 'browse-element-detail';
    const currentType = browseSearchLabel || browseSelectedType || item.data_type || item.query_type;
    const elementValue = deriveElementValue(item, currentType);
    const sourceElement = deriveSourceElement(item, elementValue);
    detailRow.innerHTML = `
      <td colspan="5" style="padding:12px 16px;background:var(--card-bg, rgba(0,200,255,0.03));border-left:3px solid var(--accent);">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
          <div>
            <strong class="accent-text">${esc(item.api_source || item.api_name || 'Unknown')}</strong>
            <span class="label" style="margin-left:8px;opacity:0.6;">${esc(item.query_type)} -> ${esc(item.query_value)}</span>
          </div>
          <span class="label" style="font-size:0.7rem;opacity:0.5;">${esc(item.response_time || '')} · ${fmtDate(item.queried_at)}</span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px 14px;margin-bottom:10px;">
          <div><span class="label" style="opacity:0.6;">Data Element</span><div style="font-family:monospace;">${esc(elementValue)}</div></div>
          <div><span class="label" style="opacity:0.6;">Source Data Element</span><div style="font-family:monospace;">${esc(sourceElement)}</div></div>
          <div><span class="label" style="opacity:0.6;">False Positive</span><div>${item.false_positive ? 'Yes' : 'No'}</div></div>
        </div>
        <div style="margin-bottom:10px;">
          <button class="btn btn-sm btn-ghost fp-detail-toggle" data-result-id="${item.id}" data-next="${item.false_positive ? 0 : 1}">
            ${item.false_positive ? 'Clear False Positive' : 'Mark as False Positive'}
          </button>
        </div>
        ${detailHtml}
      </td>`;

    row.after(detailRow);
    detailRow.querySelector('.fp-detail-toggle')?.addEventListener('click', async (event) => {
      event.stopPropagation();
      const resultId = Number(event.currentTarget.dataset.resultId);
      const nextValue = event.currentTarget.dataset.next === '1';
      await toggleFalsePositive(resultId, nextValue);
    });
  }

  function renderJsonDetail(value, depth = 0) {
    if (depth > 3) return '<span class="label">[nested object]</span>';
    if (Array.isArray(value)) {
      if (!value.length) return '<span class="label" style="opacity:0.5;">[]</span>';
      return `<div style="margin-left:${depth * 12}px;">${value.map((item, index) => `
        <div style="margin-bottom:6px;">
          <span class="label" style="opacity:0.5;">[${index}]</span>
          ${typeof item === 'object' && item !== null ? renderJsonDetail(item, depth + 1) : `<span style="color:var(--fg);">${esc(String(item))}</span>`}
        </div>`).join('')}</div>`;
    }

    const entries = Object.entries(value || {});
    if (!entries.length) return '<span class="label" style="opacity:0.5;">{}</span>';
    return `<div class="browse-detail-grid" style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:0.78rem;margin-left:${depth * 12}px;">${entries.map(([key, item]) => `
      <span class="label" style="opacity:0.7;">${esc(key)}</span>
      <div>${typeof item === 'object' && item !== null ? renderJsonDetail(item, depth + 1) : `<span style="color:var(--fg);">${esc(String(item))}</span>`}</div>`).join('')}</div>`;
  }

  function buildGraphModel() {
    if (eventGraphData?.enabled && Array.isArray(eventGraphData.events) && eventGraphData.events.length) {
      const nodes = new Map();
      const edges = [];
      const edgeKeys = new Set();
      const addEdge = (source, target) => {
        const key = `${source}->${target}`;
        if (edgeKeys.has(key)) return;
        edgeKeys.add(key);
        edges.push({ source, target });
      };

      nodes.set('target', { id: 'target', label: scanData.target, kind: 'target' });

      eventGraphData.events.forEach((event) => {
        if (event.event_type === 'ROOT') return;
        const eventId = `event:${event.event_hash}`;
        nodes.set(eventId, {
          id: eventId,
          label: shortLabel(event.event_data || event.event_type || 'Event'),
          kind: 'result',
          rawLabel: event.event_data || event.event_type || 'Event',
        });
      });

      (eventGraphData.handlers || []).forEach((handler) => {
        const eventId = `event:${handler.event_hash}`;
        if (!nodes.has(eventId)) return;
        const moduleId = `module:${handler.module_slug || 'unknown'}`;
        if (!nodes.has(moduleId)) {
          nodes.set(moduleId, {
            id: moduleId,
            label: handler.module_slug || 'Unknown',
            kind: 'module',
            rawLabel: handler.module_slug || 'Unknown',
          });
        }
        addEdge(eventId, moduleId);
      });

      (eventGraphData.relationships || []).forEach((relationship) => {
        const childId = `event:${relationship.child_event_hash}`;
        const parentId = `event:${relationship.parent_event_hash}`;
        const moduleId = `module:${relationship.module_slug || 'unknown'}`;

        if (relationship.relationship_type === 'seed') {
          if (nodes.has(childId)) addEdge('target', childId);
          return;
        }

        if (!nodes.has(childId)) return;

        if (nodes.has(moduleId)) {
          addEdge(moduleId, childId);
        } else if (nodes.has(parentId)) {
          addEdge(parentId, childId);
        } else {
          addEdge('target', childId);
        }
      });

      if (!edges.length) {
        [...nodes.values()].forEach((node) => {
          if (node.id !== 'target') addEdge('target', node.id);
        });
      }

      graphSnapshot = { nodes: [...nodes.values()], edges };
      return graphSnapshot;
    }

    const liveRows = resultsData.filter((item) => !['failed', 'aborted'].includes(item.status));
    const nodes = new Map();
    const edges = [];

    nodes.set('target', { id: 'target', label: scanData.target, kind: 'target' });

    liveRows.forEach((item) => {
      const moduleId = `module:${item.api_source || item.api_name || 'unknown'}`;
      const entityId = `result:${item.id}`;
      const parentRef = item.source_ref && item.source_ref !== 'ROOT' ? item.source_ref : null;

      if (!nodes.has(moduleId)) {
        nodes.set(moduleId, { id: moduleId, label: item.api_source || item.api_name || 'Unknown', kind: 'module' });
        edges.push({ source: 'target', target: moduleId });
      }

      nodes.set(entityId, {
        id: entityId,
        label: shortLabel(item.result_summary || item.query_value || item.data_type || 'Result'),
        kind: 'result',
        rawLabel: item.result_summary || item.query_value || item.data_type || 'Result',
      });
      edges.push({ source: moduleId, target: entityId });

      if (parentRef) {
        const parentId = `ref:${parentRef}`;
        if (!nodes.has(parentId)) {
          nodes.set(parentId, { id: parentId, label: shortLabel(parentRef), kind: 'reference', rawLabel: parentRef });
        }
        edges.push({ source: parentId, target: entityId });
      }
    });

    graphSnapshot = { nodes: [...nodes.values()], edges };
    return graphSnapshot;
  }

  function renderGraph() {
    const canvas = document.getElementById('graphCanvas');
    if (!canvas) return;

    const model = buildGraphModel();
    if (model.nodes.length < 2) {
      canvas.innerHTML = '<div class="scaninfo-empty-notice"><p>Insufficient data to produce a graph.</p></div>';
      return;
    }

    if (model.nodes.length > MAX_GRAPH_NODES_RENDER || model.edges.length > MAX_GRAPH_EDGES_RENDER) {
      canvas.innerHTML = `
        <div class="scaninfo-empty-notice">
          <p>Live graph rendering is paused for large scans.</p>
          <p>${model.nodes.length} node(s), ${model.edges.length} edge(s).</p>
          <p>Use Browse or export the graph instead of drawing the full SVG live.</p>
        </div>`;
      return;
    }

    const cs = getComputedStyle(document.documentElement);
    const cAccent = cs.getPropertyValue('--accent').trim() || '#00c8ff';
    const cTertiary = cs.getPropertyValue('--accent-tertiary').trim() || '#a855f7';
    const cFg = cs.getPropertyValue('--fg').trim() || '#eee';
    const cBg = cs.getPropertyValue('--bg').trim() || '#0d0a0b';

    const width = canvas.clientWidth || 960;
    const height = 540;
    const centerX = width / 2;
    const centerY = height / 2;

    const positioned = model.nodes.map((node, index) => {
      if (node.id === 'target') {
        return { ...node, x: centerX, y: centerY, color: cAccent, radius: 18 };
      }

      const radiusBase = node.kind === 'module' ? 160 : 255;
      const angle = (2 * Math.PI * index) / Math.max(model.nodes.length - 1, 1);
      return {
        ...node,
        x: centerX + Math.cos(angle) * radiusBase,
        y: centerY + Math.sin(angle) * radiusBase * 0.62,
        color: node.kind === 'module' ? cTertiary : '#22c55e',
        radius: node.kind === 'module' ? 12 : 8,
      };
    });

    const nodeMap = new Map(positioned.map((node) => [node.id, node]));
    let svg = `<svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" style="background:${cBg};border-radius:4px;">`;

    model.edges.forEach((edge) => {
      const source = nodeMap.get(edge.source);
      const target = nodeMap.get(edge.target);
      if (!source || !target) return;
      svg += `<line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" stroke="${cAccent}" stroke-width="1" opacity="0.22"/>`;
    });

    positioned.forEach((node) => {
      svg += `<circle cx="${node.x}" cy="${node.y}" r="${node.radius}" fill="${node.color}" opacity="0.88"/>`;
      svg += `<text x="${node.x}" y="${node.y + node.radius + 12}" text-anchor="middle" fill="${cFg}" font-size="10" font-family="JetBrains Mono, monospace">${esc(shortLabel(node.label, 22))}</text>`;
    });

    svg += '</svg>';
    canvas.innerHTML = svg;
  }

  function buildGexf() {
    const model = buildGraphModel();
    const nodes = model.nodes.map((node) => `<node id="${esc(node.id)}" label="${esc(node.rawLabel || node.label)}"/>`).join('');
    const edges = model.edges.map((edge, index) => `<edge id="e${index}" source="${esc(edge.source)}" target="${esc(edge.target)}"/>`).join('');
    return `<?xml version="1.0" encoding="UTF-8"?>
<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">
  <graph mode="static" defaultedgetype="directed">
    <nodes>${nodes}</nodes>
    <edges>${edges}</edges>
  </graph>
</gexf>`;
  }

  function findParentRow(item) {
    const ref = item.source_ref;
    if (!ref || ref === 'ROOT') return null;
    return resultsData.find((row) => row.id !== item.id && (
      row.query_value === ref ||
      row.result_summary === ref ||
      row.enriched_from === ref
    )) || null;
  }

  function collectChildren(item) {
    return resultsData.filter((row) => row.id !== item.id && (
      row.source_ref === item.query_value ||
      row.source_ref === item.result_summary ||
      row.enriched_from === item.query_value
    ));
  }

  function renderGenealogy() {
    const select = document.getElementById('genealogySelect');
    const content = document.getElementById('genealogyContent');
    if (!select || !content) return;

    const rows = resultsData.filter((item) => !['failed', 'aborted'].includes(item.status));
    if (!rows.length) {
      select.innerHTML = '<option>No findings available</option>';
      content.innerHTML = '<p class="label" style="opacity:0.5;">No genealogy data available.</p>';
      return;
    }

    const currentValue = select.value || String(rows[0].id);
    select.innerHTML = rows.map((item) => `<option value="${item.id}">${esc(shortLabel(item.data_type || item.query_type, 24))} · ${esc(shortLabel(item.result_summary || item.query_value, 52))}</option>`).join('');
    select.value = rows.some((item) => String(item.id) === currentValue) ? currentValue : String(rows[0].id);

    const selected = rows.find((item) => String(item.id) === select.value) || rows[0];
    const ancestry = [];
    let cursor = selected;
    while (cursor) {
      ancestry.unshift(cursor);
      cursor = findParentRow(cursor);
    }

    const children = collectChildren(selected);
    content.innerHTML = `
      <div class="log-entry log-info"><span class="log-level">UPSTREAM</span><span class="log-msg">${ancestry.map((item) => esc(shortLabel(item.result_summary || item.query_value, 48))).join(' → ') || esc(scanData.target)}</span></div>
      <div class="log-entry ${selected.false_positive ? 'log-warning' : 'log-info'}"><span class="log-level">SELECTED</span><span class="log-msg">${esc(selected.data_type || selected.query_type)} · ${esc(selected.result_summary || selected.query_value || '--')}</span></div>
      <div class="log-entry log-info"><span class="log-level">DOWNSTREAM</span><span class="log-msg">${children.length ? children.map((item) => esc(shortLabel(item.result_summary || item.query_value, 48))).join(' | ') : 'No child findings linked to this event.'}</span></div>
    `;
  }

  function settingsRowKey(row, keyFields) {
    return keyFields.map((field) => String(row?.[field] ?? '').trim().toLowerCase()).join('||');
  }

  function mergeSettingsRows(runtimeRows, baselineRows, keyFields) {
    if (!Array.isArray(runtimeRows) || !runtimeRows.length) {
      return Array.isArray(baselineRows) ? clone(baselineRows) : [];
    }
    if (!Array.isArray(baselineRows) || !baselineRows.length) {
      return runtimeRows;
    }

    const runtimeByKey = new Map();
    runtimeRows.forEach((row) => runtimeByKey.set(settingsRowKey(row, keyFields), row));

    const merged = baselineRows.map((baseRow) => {
      const key = settingsRowKey(baseRow, keyFields);
      const runtimeRow = runtimeByKey.get(key);
      if (!runtimeRow) return { ...baseRow };

      return {
        ...baseRow,
        ...runtimeRow,
        module: runtimeRow.module ?? baseRow.module,
        option: runtimeRow.option ?? baseRow.option,
      };
    });

    const baselineKeys = new Set(baselineRows.map((row) => settingsRowKey(row, keyFields)));
    runtimeRows.forEach((row) => {
      const key = settingsRowKey(row, keyFields);
      if (!baselineKeys.has(key)) merged.push(row);
    });

    return merged;
  }

  function isSensitiveSettingOption(option) {
    const normalized = String(option || '').trim().toLowerCase();
    return normalized.includes('api key') || normalized.includes('apikey');
  }

  function maskSecretValue(value) {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    if (/^\*{4,}[a-z0-9]{0,4}$/i.test(raw)) return raw;
    if (raw.length <= 4) return '*'.repeat(raw.length);
    const suffix = raw.slice(-4);
    const stars = '*'.repeat(Math.min(8, Math.max(4, raw.length - 4)));
    return `${stars}${suffix}`;
  }

  function renderSettingsRows(rows, columns, emptyMessage) {
    if (!rows.length) {
      return `<tr><td colspan="${columns.length}" style="text-align:center;padding:1rem;" class="label">${esc(emptyMessage)}</td></tr>`;
    }

    return rows.map((row) => `
      <tr>
        ${columns.map((col, index) => {
          let cellClass = 'scan-settings-cell';
          if (columns.length === 2) {
            cellClass += index === 0 ? ' settings-option-label scan-settings-option' : ' settings-option-value scan-settings-value';
          } else if (columns.length === 3) {
            if (index === 0) {
              cellClass += ' scan-settings-module';
            } else if (index === 1) {
              cellClass += ' settings-option-label scan-settings-option';
            } else {
              cellClass += ' settings-option-value scan-settings-value';
            }
          }
          let cellValue = row[col] ?? '';
          if (col === 'value' && isSensitiveSettingOption(row.option)) {
            cellValue = maskSecretValue(cellValue);
          }
          return `<td class="${cellClass}">${esc(cellValue)}</td>`;
        }).join('')}
      </tr>
    `).join('');
  }

  function renderSettings() {
    const metaBody = document.getElementById('settingsMetaBody');
    const globalBody = document.getElementById('settingsGlobalBody');
    const moduleBody = document.getElementById('settingsModuleBody');
    if (!metaBody || !globalBody || !moduleBody) return;

    let metaRows = Array.isArray(scanSettingsData?.meta_information)
      ? scanSettingsData.meta_information
      : [];
    let globalRows = Array.isArray(scanSettingsData?.global_settings)
      ? scanSettingsData.global_settings
      : [];
    let moduleRows = Array.isArray(scanSettingsData?.module_settings)
      ? scanSettingsData.module_settings
      : [];

    if (!metaRows.length) {
      metaRows = [
        { option: 'Name', value: scanData?.name || '' },
        { option: 'Internal ID', value: scanData?.id || '' },
        { option: 'Target', value: scanData?.target || '' },
        { option: 'Started', value: fmtDate(scanData?.started_at) },
        { option: 'Completed', value: fmtDate(scanData?.finished_at) },
        { option: 'Status', value: String(scanData?.status || '').toUpperCase() },
      ];
      if (scanData?.backend_used) {
        metaRows.push({ option: 'Backend Used', value: scanData.backend_used });
      }
    }

    globalRows = mergeSettingsRows(globalRows, scanSettingsBaseline.global_settings, ['option']);
    moduleRows = mergeSettingsRows(moduleRows, scanSettingsBaseline.module_settings, ['module', 'option']);

    metaBody.innerHTML = renderSettingsRows(metaRows, ['option', 'value'], 'No meta information found.');
    globalBody.innerHTML = renderSettingsRows(globalRows, ['option', 'value'], 'No global settings found.');
    moduleBody.innerHTML = renderSettingsRows(moduleRows, ['module', 'option', 'value'], 'No module settings found.');

    // Show snapshot vs live indicator badge
    const badge = document.getElementById('settingsSourceBadge');
    if (badge) {
      const hasSnapshot = scanSettingsData?.has_snapshot === true;
      badge.style.display = 'inline-block';
      if (hasSnapshot) {
        badge.textContent = 'SNAPSHOT';
        badge.title = 'Settings captured at scan start time';
        badge.className = 'badge badge-small badge-low';
      } else {
        badge.textContent = 'LIVE';
        badge.title = 'Showing current settings (no snapshot captured for this scan)';
        badge.className = 'badge badge-small badge-medium';
      }
    }
  }

  function renderLog() {
    const content = document.getElementById('logContent');
    if (!content) return;

    const filtered = logFilterMode === 'errors'
      ? logsData.filter((item) => item.level === 'error')
      : logsData;

    if (!filtered.length) {
      content.innerHTML = '<p class="label" style="opacity:0.5;">No log entries.</p>';
      return;
    }

    const visibleLogs = filtered.length > MAX_LOG_ROWS_RENDER
      ? filtered.slice(-MAX_LOG_ROWS_RENDER)
      : filtered;

    const notice = filtered.length > MAX_LOG_ROWS_RENDER
      ? `<div class="log-entry log-info"><span class="log-level">INFO</span><span class="log-msg">Showing the most recent ${MAX_LOG_ROWS_RENDER} of ${filtered.length} log entries.</span></div>`
      : '';

    content.innerHTML = notice + visibleLogs.map((log) => {
      const levelClass = {
        error: 'log-error',
        warning: 'log-warning',
        debug: 'log-debug',
        info: 'log-info',
      }[log.level] || 'log-info';

      return `<div class="log-entry ${levelClass}"><span class="log-time">${fmtDate(log.logged_at)}</span><span class="log-level">${esc(String(log.level || '').toUpperCase())}</span>${log.module ? `<span class="log-module">[${esc(log.module)}]</span>` : ''}<span class="log-msg">${esc(log.message)}</span></div>`;
    }).join('');
  }

  async function toggleFalsePositive(resultId, falsePositive) {
    const row = resultsData.find((item) => Number(item.id) === Number(resultId));
    if (!row) return;

    if (isRealScan) {
      const csrf = await getCsrfToken();
      if (!csrf) {
        showToast('Auth required.', 'error');
        return;
      }

      const res = await fetch(`${API_QUERY}?action=set_false_positive`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ result_id: resultId, false_positive: falsePositive, _csrf_token: csrf }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Could not update false-positive state.', 'error');
        return;
      }
    }

    row.false_positive = falsePositive;
    if (browseViewMode === 'elements') {
      if (browseSearchLabel) {
        renderSearchResults(searchAcrossResults(document.getElementById('siSearch')?.value || ''), browseSearchLabel);
      } else if (browseSelectedType) {
        renderBrowseElements(browseSelectedType);
      }
    }
    renderGenealogy();
    syncDraftPayload();
    showToast(falsePositive ? 'Result marked as false positive.' : 'False positive cleared.');
  }

  function searchAcrossResults(query) {
    const input = String(query || '').trim();
    if (!input) return [];

    let matcher;
    if (/^\/.+\/[a-z]*$/i.test(input)) {
      const match = input.match(/^\/(.+)\/([a-z]*)$/i);
      matcher = new RegExp(match[1], match[2]);
      return resultsData.filter((row) => matcher.test(JSON.stringify(row)));
    }

    if (input.includes('*') || input.includes('?')) {
      const regex = new RegExp(`^${input.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');
      return resultsData.filter((row) => regex.test(row.result_summary || '') || regex.test(row.query_value || '') || regex.test(row.api_source || '') || regex.test(row.data_type || ''));
    }

    const needle = input.toLowerCase();
    return resultsData.filter((row) => JSON.stringify(row).toLowerCase().includes(needle));
  }

  function getActiveTabName() {
    return document.querySelector('.scaninfo-tab.active')?.dataset.tab || 'summary';
  }

  function renderActivePanel() {
    if (!scanData) return;

    const activeTab = getActiveTabName();
    switch (activeTab) {
      case 'summary':
        renderSummary();
        break;
      case 'correlations':
        renderCorrelations();
        break;
      case 'browse':
        if (browseViewMode === 'elements' && browseSelectedType) {
          renderBrowseElements(browseSelectedType);
        } else if (browseViewMode === 'elements' && browseSearchLabel) {
          renderSearchResults(searchAcrossResults(document.getElementById('siSearch')?.value || ''), browseSearchLabel);
        } else {
          renderBrowse();
        }
        break;
      case 'graph':
        renderGraph();
        renderGenealogy();
        break;
      case 'settings':
        renderSettings();
        break;
      case 'log':
        renderLog();
        break;
      default:
        renderSummary();
        break;
    }
  }

  function renderAll() {
    if (!scanData) return;
    renderHeader();
    renderActivePanel();
  }

  function exportBlob(content, mime, filename) {
    const blob = new Blob([content], { type: mime });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
  }

  function csvCell(value) {
    return `"${String(value ?? '').replace(/"/g, '""')}"`;
  }

  function csvRow(values) {
    return values.map((value) => csvCell(value)).join(',');
  }

  function doSearch() {
    const query = document.getElementById('siSearch')?.value || '';
    if (!query.trim()) {
      renderBrowse();
      return;
    }

    try {
      const matches = searchAcrossResults(query);
      renderSearchResults(matches, `Search: ${query}`);
      showToast(`Matched ${matches.length} result(s).`);
    } catch {
      showToast('Invalid regex pattern.', 'error');
    }
  }

  document.getElementById('browseBackLink')?.addEventListener('click', (event) => {
    event.preventDefault();
    renderBrowse();
  });

  document.getElementById('genealogySelect')?.addEventListener('change', renderGenealogy);
  document.getElementById('graphSaveImg')?.addEventListener('click', () => {
    const svg = document.querySelector('#graphCanvas svg');
    if (!svg) return showToast('There is no graph to export.', 'error');
    exportBlob(new XMLSerializer().serializeToString(svg), 'image/svg+xml', `scan_${scanData.id || scanKey}_graph.svg`);
  });
  document.getElementById('graphExport')?.addEventListener('click', () => {
    const svg = document.querySelector('#graphCanvas svg');
    if (!svg) return showToast('There is no graph to export.', 'error');
    exportBlob(new XMLSerializer().serializeToString(svg), 'image/svg+xml', `scan_${scanData.id || scanKey}_graph.svg`);
  });
  document.getElementById('graphExportGexf')?.addEventListener('click', () => {
    exportBlob(buildGexf(), 'application/gexf+xml', `scan_${scanData.id || scanKey}_graph.gexf`);
    showToast('Exported graph as GEXF.');
  });
  document.getElementById('graphRefresh')?.addEventListener('click', () => {
    renderGraph();
    renderGenealogy();
    showToast('Refreshed graph and genealogy views.');
  });
  document.getElementById('downloadLogs')?.addEventListener('click', () => {
    const text = logsData.map((log) => `[${log.logged_at}] [${String(log.level || '').toUpperCase()}]${log.module ? ` [${log.module}]` : ''} ${log.message}`).join('\n');
    exportBlob(text, 'text/plain', `scan_${scanData.id || scanKey}_log.txt`);
  });
  document.getElementById('siSearchBtn')?.addEventListener('click', doSearch);
  document.getElementById('siSearch')?.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') doSearch();
  });
  document.getElementById('dnsaIssueSeverity')?.addEventListener('change', (event) => {
    dnsaIssueFilter.severity = String(event.target.value || 'all');
    renderDnsAuditIssues();
  });
  document.getElementById('dnsaIssueGroup')?.addEventListener('change', (event) => {
    dnsaIssueFilter.group = String(event.target.value || 'all');
    renderDnsAuditIssues();
  });
  document.getElementById('dnsaIssueSearch')?.addEventListener('input', (event) => {
    dnsaIssueFilter.search = String(event.target.value || '').trim().toLowerCase();
    renderDnsAuditIssues();
  });
  document.getElementById('logFilterAll')?.addEventListener('click', () => {
    logFilterMode = 'all';
    document.getElementById('logFilterAll')?.classList.add('active');
    document.getElementById('logFilterErrors')?.classList.remove('active');
    renderLog();
  });
  document.getElementById('logFilterErrors')?.addEventListener('click', () => {
    logFilterMode = 'errors';
    document.getElementById('logFilterErrors')?.classList.add('active');
    document.getElementById('logFilterAll')?.classList.remove('active');
    renderLog();
  });

  document.getElementById('siClone')?.addEventListener('click', () => {
    if (!scanData?.id || !isRealScan) {
      showToast('Clone is only available for backend scans.', 'error');
      return;
    }
    window.location.href = `newscan.php?clone_scan_id=${encodeURIComponent(scanData.id)}`;
  });

  document.getElementById('siRerun')?.addEventListener('click', async () => {
    if (!isRealScan) {
      showToast('Preview mode. Re-run is not available.', 'error');
      return;
    }

    const csrf = await getCsrfToken();
    if (!csrf) return showToast('Auth required.', 'error');

    const res = await fetch(`${API_QUERY}?action=rerun_scan`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanData.id, _csrf_token: csrf }),
    });
    const data = await res.json();
    if (!res.ok || !data.scan_id) return showToast(data.error || 'Failed to re-run scan.', 'error');
    showToast('Scan re-run started.');
    setTimeout(() => { window.location.href = `scaninfo.php?id=${data.scan_id}`; }, 300);
  });

  document.getElementById('siRerunCorrelations')?.addEventListener('click', async () => {
    if (!isRealScan) {
      showToast('Preview mode. Correlation re-run is not available.', 'error');
      return;
    }

    const button = document.getElementById('siRerunCorrelations');
    if (button) button.disabled = true;

    try {
      const csrf = await getCsrfToken();
      if (!csrf) {
        showToast('Auth required.', 'error');
        return;
      }

      const res = await fetch(`${API_QUERY}?action=rerun_correlations`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanData.id, _csrf_token: csrf }),
      });
      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Could not re-run correlations.', 'error');
        return;
      }

      const payload = await loadBackendPayload(scanData.id);
      if (payload?.scan) {
        applyPayload(payload);
        renderAll();
      }

      showToast(`Correlations refreshed (${data.correlation_count || 0} finding(s)).`);
    } catch {
      showToast('Could not re-run correlations.', 'error');
    } finally {
      if (button) button.disabled = false;
    }
  });

  document.getElementById('siExport')?.addEventListener('click', () => {
    const headers = [
      'ID',
      'API Source',
      'Query Type',
      'Query Value',
      'Data Type',
      'Risk Score',
      'Status',
      'False Positive',
      'Queried At',
      'DNSAudit Category Group',
      'DNSAudit Issue Title',
      'DNSAudit Severity',
      'DNSAudit Recommendation',
      'DNSAudit Docs URL',
    ];

    const rows = resultsData.map((item) => {
      const issue = extractDnsAuditIssue(item);
      return [
        item.id || '',
        item.api_source || item.api_name || '',
        item.query_type || '',
        item.query_value || '',
        item.data_type || '',
        item.risk_score || '',
        item.status || '',
        item.false_positive ? 'yes' : 'no',
        item.queried_at || '',
        issue?.group || '',
        issue?.title || '',
        issue?.severity || '',
        issue?.recommendation || '',
        issue?.docsUrl || '',
      ];
    });

    const csv = [csvRow(headers), ...rows.map((row) => csvRow(row))].join('\n');
    exportBlob(csv, 'text/csv', `scan_${scanData.id || scanKey}_results.csv`);
  });

  document.addEventListener('abortScan', async () => {
    if (!scanData || !['running', 'starting'].includes(scanData.status)) {
      showToast('This scan is not currently running.', 'error');
      return;
    }

    if (isRealScan) {
      const csrf = await getCsrfToken();
      if (!csrf) return showToast('Auth required.', 'error');

      const res = await fetch(`${API_QUERY}?action=abort_scan`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanData.id, _csrf_token: csrf }),
      });
      const data = await res.json();
      if (!data.aborted) return showToast('Could not abort scan.', 'error');
    }

    scanData.status = 'aborted';
    scanData.finished_at = new Date().toISOString().replace('T', ' ').slice(0, 19);
    scanData.stuck = false;
    stopPolling();
    syncDraftPayload();
    renderAll();
    showToast('Scan aborted.');
  });

  async function init() {
    if (scanKey && /^\d+$/.test(scanKey)) {
      const payload = await loadBackendPayload(scanKey);
      if (payload) {
        isRealScan = true;
        applyPayload(payload);
        renderAll();
        if (['starting', 'running'].includes(scanData.status)) startPolling();
        return;
      }
    }

    const payload = loadStaticPayload(scanKey);
    if (!payload?.scan) {
      document.getElementById('scanTitle').textContent = 'Scan Not Found';
      showToast('No scan data found for this ID.', 'error');
      return;
    }

    applyPayload(payload);
    renderAll();
  }

  init();
});
