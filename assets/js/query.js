/**
 * CTI Platform - Scans List Page
 * Loads real scans from backend API.
 * Static preview scans are only enabled when the page explicitly opts in.
 */
document.addEventListener('DOMContentLoaded', () => {
  const showToast = window.CtiStaticUi?.showToast || ((message) => window.alert(message));
  const clone = window.CtiStaticUi?.clone || ((value) => JSON.parse(JSON.stringify(value)));

  const API_QUERY = 'php/api/query.php';
  const API_AUTH  = 'php/api/auth.php';
  const staticPreviewEnabled = Boolean(window.CTI_ENABLE_STATIC_SCAN_PREVIEW);
  let useBackend = false;
  let backendLoadFailed = false;

  // Prevent stale preview rows from leaking into normal backend mode.
  if (!staticPreviewEnabled) {
    sessionStorage.removeItem('cti-static-draft-scan');
  }

  async function getCsrfToken() {
    try {
      const res = await fetch(`${API_AUTH}?action=csrf`, { credentials: 'same-origin' });
      const data = await res.json();
      return data.csrf_token || null;
    } catch { return null; }
  }

  function esc(str) {
    return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function fmtDate(value) {
    if (!value) return '--';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toISOString().replace('T', ' ').slice(0, 19);
  }

  const scanTableBody = document.getElementById('scanTableBody');
  const scanEmpty = document.getElementById('scanEmpty');
  const tableWrap = document.querySelector('.resp-table-wrap');
  const scanPager = document.getElementById('scanPager');
  const selectAllCb = document.getElementById('selectAllScans');
  const filterBtn = document.getElementById('filterBtn');
  const filterMenu = document.getElementById('filterMenu');
  const filterLabel = document.getElementById('filterLabel');
  const refreshBtn = document.getElementById('refreshScans');
  const deleteBtn = document.getElementById('deleteSelected');
  const rerunBtn = document.getElementById('rerunSelected');
  const stopBtn = document.getElementById('stopSelected');
  const exportBtn = document.getElementById('exportSelected');
  const exportJsonBtn = document.getElementById('exportJsonSelected');
  const pagerFirst = document.getElementById('pagerFirst');
  const pagerPrev = document.getElementById('pagerPrev');
  const pagerNext = document.getElementById('pagerNext');
  const pagerLast = document.getElementById('pagerLast');
  const pagerSize = document.getElementById('pagerSize');
  const pagerPage = document.getElementById('pagerPage');
  const pagerInfo = document.getElementById('pagerInfo');

  let currentPage = 1;
  let pageSize = 10;
  let totalScans = 0;
  let totalPages = 1;
  let statusFilter = '';
  let scansData = [];
  let allScans = loadBaseScans();

  function loadDraftSummary() {
    try {
      const raw = sessionStorage.getItem('cti-static-draft-scan');
      if (!raw) return null;
      const draft = JSON.parse(raw);
      if (!draft?.scan) return null;

      const counts = { high: 0, medium: 0, low: 0, info: 0 };
      (draft.correlations || []).forEach(item => {
        if (counts[item.severity] !== undefined) counts[item.severity] += 1;
      });

      return {
        id: 'preview-draft',
        detail_id: 'preview-draft',
        name: draft.scan.name || 'Preview Scan',
        target: draft.scan.target || '',
        target_type: draft.scan.target_type || 'unknown',
        use_case: draft.scan.use_case || 'custom',
        started_at: draft.scan.started_at || '',
        finished_at: draft.scan.finished_at || '',
        status: draft.scan.status || 'preview',
        total_elements: draft.scan.total_elements || 0,
        unique_elements: draft.scan.unique_elements || 0,
        error_count: draft.scan.error_count || 0,
        user_name: draft.scan.user_name || 'Analyst Preview',
        selected_modules: draft.scan.selected_modules || [],
        corr_high: counts.high,
        corr_medium: counts.medium,
        corr_low: counts.low,
        corr_info: counts.info,
        stuck: Boolean(draft.scan.stuck),
      };
    } catch {
      return null;
    }
  }

  function loadBaseScans() {
    if (!staticPreviewEnabled) {
      return [];
    }

    const base = clone(Array.isArray(window.CTI_STATIC_SCANS) ? window.CTI_STATIC_SCANS : []).map(scan => ({
      ...scan,
      id: String(scan.id),
      detail_id: String(scan.id),
    }));

    const draft = loadDraftSummary();
    if (draft) {
      base.unshift(draft);
    }

    return base.sort((a, b) => String(b.started_at || '').localeCompare(String(a.started_at || '')));
  }

  function statusBadge(status) {
    const map = {
      running: 'badge-info',
      starting: 'badge-info',
      preview: 'badge-medium',
      finished: 'badge-low',
      aborted: 'badge-critical',
      failed: 'badge-critical',
    };
    return `<span class="badge ${map[status] || 'badge-info'}">${esc(String(status || '').toUpperCase())}</span>`;
  }

  function corrBadges(scan) {
    return `<span class="corr-badge corr-high">${scan.corr_high || 0}</span> <span class="corr-badge corr-medium">${scan.corr_medium || 0}</span> <span class="corr-badge corr-low">${scan.corr_low || 0}</span> <span class="corr-badge corr-info">${scan.corr_info || 0}</span>`;
  }

  function isTerminableStatus(status) {
    return ['running', 'starting'].includes(String(status || '').toLowerCase());
  }

  async function refreshVisibleScans() {
    // Try backend first
    try {
      const url = `${API_QUERY}?action=list_scans&page=${currentPage}&limit=${pageSize}` +
        (statusFilter ? `&status=${encodeURIComponent(statusFilter)}` : '');
      const res = await fetch(url, { credentials: 'same-origin' });
      if (res.ok) {
        const data = await res.json();
        if (data.scans) {
          useBackend = true;
          backendLoadFailed = false;
          scansData = data.scans.map(s => ({
            ...s,
            id: String(s.id),
            detail_id: String(s.id),
          }));
          totalScans = data.total || 0;
          totalPages = data.total_pages || 1;
          currentPage = data.page || 1;

          // Prepend draft scan only in explicit preview mode.
          const draft = loadDraftSummary();
          if (staticPreviewEnabled && draft && currentPage === 1 && !statusFilter) {
            scansData.unshift(draft);
            totalScans += 1;
            totalPages = Math.max(1, Math.ceil(totalScans / pageSize));
          }

          renderScanTable();
          return;
        }
      }
    } catch { /* fall through */ }

    if (!staticPreviewEnabled) {
      useBackend = false;
      scansData = [];
      totalScans = 0;
      totalPages = 1;
      currentPage = 1;
      renderScanTable();

      if (!backendLoadFailed) {
        backendLoadFailed = true;
        showToast('Unable to load real scans from the backend.', 'error');
      }
      return;
    }

    // Explicit static preview fallback
    const filtered = allScans.filter(scan => !statusFilter || scan.status === statusFilter);
    totalScans = filtered.length;
    totalPages = Math.max(1, Math.ceil(totalScans / pageSize));
    currentPage = Math.min(currentPage, totalPages);

    const startIndex = (currentPage - 1) * pageSize;
    scansData = filtered.slice(startIndex, startIndex + pageSize);
    renderScanTable();
  }

  function renderScanTable() {
    if (!scanTableBody) return;

    if (!scansData.length) {
      scanTableBody.innerHTML = '';
      tableWrap?.classList.add('hidden');
      scanPager?.classList.add('hidden');
      scanEmpty?.classList.remove('hidden');
      if (pagerInfo) pagerInfo.textContent = 'Scans 0 - 0 / 0 (0)';
      updateBulkBtns();
      return;
    }

    tableWrap?.classList.remove('hidden');
    scanPager?.classList.remove('hidden');
    scanEmpty?.classList.add('hidden');

    scanTableBody.innerHTML = scansData.map(scan => `
      <tr data-id="${esc(scan.id)}">
        <td style="text-align:center;"><input type="checkbox" class="scan-cb" value="${esc(scan.id)}"></td>
        <td style="white-space:nowrap;"><a href="scaninfo.php?id=${encodeURIComponent(scan.detail_id || scan.id)}" class="accent-text">${esc(scan.name)}</a></td>
        <td style="white-space:nowrap;">${esc(scan.target)}</td>
        <td style="white-space:nowrap;">${fmtDate(scan.started_at)}</td>
        <td style="white-space:nowrap;">${fmtDate(scan.finished_at)}</td>
        <td style="text-align:center;white-space:nowrap;">${statusBadge(scan.status)}</td>
        <td style="text-align:center;">${scan.total_elements || 0}</td>
        <td style="text-align:center;white-space:nowrap;">${corrBadges(scan)}</td>
        <td style="text-align:center;white-space:nowrap;">
          <div class="scan-actions">
            ${isTerminableStatus(scan.status) ? `
            <button class="scan-act-btn destructive-text" title="Terminate" data-stop="${esc(scan.id)}">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12"/></svg>
            </button>` : ''}
            <button class="scan-act-btn destructive-text" title="Delete" data-delete="${esc(scan.id)}">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            </button>
            <button class="scan-act-btn" title="Re-run" data-rerun="${esc(scan.id)}">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            </button>
            <button class="scan-act-btn" title="Clone" data-clone="${esc(scan.id)}">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            </button>
            <a href="scaninfo.php?id=${encodeURIComponent(scan.detail_id || scan.id)}" class="scan-act-btn" title="View">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            </a>
          </div>
        </td>
      </tr>
    `).join('');

    const start = totalScans ? ((currentPage - 1) * pageSize) + 1 : 0;
    const end = Math.min(currentPage * pageSize, totalScans);
    if (pagerInfo) {
      pagerInfo.textContent = `Scans ${start} - ${end} / ${totalScans} (${totalScans})`;
    }

    // Update page selector dropdown
    if (pagerPage) {
      pagerPage.innerHTML = '';
      for (let i = 1; i <= totalPages; i++) {
        const opt = document.createElement('option');
        opt.value = i;
        opt.textContent = i;
        if (i === currentPage) opt.selected = true;
        pagerPage.appendChild(opt);
      }
    }

    selectAllCb.checked = false;
    updateBulkBtns();
  }

  pagerFirst?.addEventListener('click', () => {
    currentPage = 1;
    refreshVisibleScans();
  });

  pagerPrev?.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage -= 1;
      refreshVisibleScans();
    }
  });

  pagerNext?.addEventListener('click', () => {
    if (currentPage < totalPages) {
      currentPage += 1;
      refreshVisibleScans();
    }
  });

  pagerLast?.addEventListener('click', () => {
    currentPage = totalPages;
    refreshVisibleScans();
  });

  pagerSize?.addEventListener('change', () => {
    pageSize = parseInt(pagerSize.value, 10) || 10;
    currentPage = 1;
    refreshVisibleScans();
  });

  pagerPage?.addEventListener('change', () => {
    currentPage = parseInt(pagerPage.value, 10) || 1;
    refreshVisibleScans();
  });

  filterBtn?.addEventListener('click', (event) => {
    event.stopPropagation();
    filterMenu?.classList.toggle('hidden');
  });

  document.addEventListener('click', () => filterMenu?.classList.add('hidden'));

  filterMenu?.addEventListener('click', event => {
    const option = event.target.closest('.scan-filter-opt');
    if (!option) return;
    filterMenu.querySelectorAll('.scan-filter-opt').forEach(item => item.classList.remove('active'));
    option.classList.add('active');
    statusFilter = option.dataset.filter || '';
    if (filterLabel) filterLabel.textContent = option.textContent;
    filterMenu.classList.add('hidden');
    currentPage = 1;
    refreshVisibleScans();
  });

  selectAllCb?.addEventListener('change', () => {
    document.querySelectorAll('.scan-cb').forEach(cb => {
      cb.checked = selectAllCb.checked;
    });
    updateBulkBtns();
  });

  document.addEventListener('change', event => {
    if (event.target.classList.contains('scan-cb')) {
      updateBulkBtns();
    }
  });

  function getSelectedIds() {
    return [...document.querySelectorAll('.scan-cb:checked')].map(cb => cb.value);
  }

  function getSelectedScans() {
    const selected = new Set(getSelectedIds().map(String));
    return scansData.filter(scan => selected.has(String(scan.id)));
  }

  function updateBulkBtns() {
    const selectedIds = getSelectedIds();
    const selectedScans = getSelectedScans();
    const hasSelection = selectedIds.length > 0;

    [deleteBtn, rerunBtn, exportBtn, exportJsonBtn].forEach(button => {
      if (button) button.disabled = !hasSelection;
    });

    if (stopBtn) {
      stopBtn.disabled = !selectedScans.some(scan => isTerminableStatus(scan.status));
    }
  }

  function downloadBlob(blob, filename) {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  }

  refreshBtn?.addEventListener('click', () => {
    allScans = loadBaseScans();
    currentPage = 1;
    refreshVisibleScans();
    showToast('Refreshed scan list.');
  });

  function removeDraftIfNeeded(id) {
    if (id === 'preview-draft') {
      sessionStorage.removeItem('cti-static-draft-scan');
    }
  }

  async function deleteScanIds(ids) {
    ids.forEach(removeDraftIfNeeded);

    // Try backend delete for numeric IDs
    const numericIds = ids.filter(id => /^\d+$/.test(id)).map(Number);
    if (numericIds.length) {
      try {
        const csrf = await getCsrfToken();
        if (csrf) {
          await fetch(`${API_QUERY}?action=delete_scan`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_ids: numericIds, _csrf_token: csrf }),
          });
        }
      } catch { /* ignore */ }
    }

    allScans = allScans.filter(scan => !ids.includes(String(scan.id)));
    currentPage = 1;
    refreshVisibleScans();
    showToast(ids.length === 1 ? 'Scan deleted.' : `${ids.length} scans deleted.`);
  }

  async function rerunScan(id) {
    if (!/^\d+$/.test(id)) {
      showToast('Re-run is only available for backend scans.', 'error');
      return;
    }

    try {
      const csrf = await getCsrfToken();
      if (!csrf) { showToast('Auth required.', 'error'); return; }

      const res = await fetch(`${API_QUERY}?action=rerun_scan`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: Number(id), _csrf_token: csrf }),
      });
      const data = await res.json();

      if (res.ok && data.scan_id) {
        showToast('Scan re-run started!');
        setTimeout(() => {
          window.location.href = `scaninfo.php?id=${data.scan_id}`;
        }, 300);
      } else {
        showToast(data.error || 'Failed to re-run scan.', 'error');
      }
    } catch {
      showToast('Failed to re-run scan.', 'error');
    }
  }

  function cloneScan(id) {
    if (!/^\d+$/.test(id)) {
      showToast('Clone is only available for backend scans.', 'error');
      return;
    }
    window.location.href = `newscan.php?clone_scan_id=${encodeURIComponent(id)}`;
  }

  async function abortScan(id) {
    if (/^\d+$/.test(id) && useBackend) {
      try {
        const csrf = await getCsrfToken();
        if (csrf) {
          const res = await fetch(`${API_QUERY}?action=abort_scan`, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: Number(id), _csrf_token: csrf }),
          });
          const data = await res.json();
          if (data.aborted) {
            showToast('Scan terminated.');
            refreshVisibleScans();
            return;
          }
          showToast(data.error || 'Failed to terminate the scan.', 'error');
          return;
        }
        showToast('Auth required.', 'error');
        return;
      } catch {
        showToast('Failed to terminate the scan.', 'error');
        return;
      }
    }

    // Static fallback
    const scan = allScans.find(item => String(item.id) === String(id));
    if (!scan || !['running', 'starting'].includes(scan.status)) {
      showToast('Scan is not running.', 'error');
      return;
    }

    scan.status = 'aborted';
    scan.finished_at = new Date().toISOString().replace('T', ' ').slice(0, 19);
    scan.stuck = false;
    refreshVisibleScans();
    showToast('Scan terminated.');
  }

  scanTableBody?.addEventListener('click', event => {
    const del = event.target.closest('[data-delete]');
    if (del) {
      deleteScanIds([del.dataset.delete]);
      return;
    }

    const rerun = event.target.closest('[data-rerun]');
    if (rerun) {
      rerunScan(rerun.dataset.rerun);
      return;
    }

    const clone = event.target.closest('[data-clone]');
    if (clone) {
      cloneScan(clone.dataset.clone);
      return;
    }

    const stop = event.target.closest('[data-stop]');
    if (stop) {
      abortScan(stop.dataset.stop);
    }
  });

  deleteBtn?.addEventListener('click', () => {
    const ids = getSelectedIds();
    if (ids.length) {
      deleteScanIds(ids);
    }
  });

  rerunBtn?.addEventListener('click', () => {
    const ids = getSelectedIds();
    const numericIds = ids.filter(id => /^\d+$/.test(id)).map(Number);
    if (!numericIds.length) {
      showToast('Bulk re-run is only available for backend scans.', 'error');
      return;
    }

    (async () => {
      try {
        const csrf = await getCsrfToken();
        if (!csrf) { showToast('Auth required.', 'error'); return; }

        const res = await fetch(`${API_QUERY}?action=multi_rerun`, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scan_ids: numericIds, _csrf_token: csrf }),
        });
        const data = await res.json();

        if (!res.ok || !data.scan_ids?.length) {
          showToast(data.error || 'Failed to queue the selected scans.', 'error');
          return;
        }

        showToast(`Queued ${data.scan_ids.length} scan(s).`);
        setTimeout(() => {
          window.location.href = `scaninfo.php?id=${data.scan_ids[0]}`;
        }, 300);
      } catch {
        showToast('Failed to queue the selected scans.', 'error');
      }
    })();
  });

  stopBtn?.addEventListener('click', () => {
    getSelectedScans()
      .filter(scan => isTerminableStatus(scan.status))
      .forEach(scan => abortScan(scan.id));
  });

  async function exportSelectedAs(format = 'csv') {
    const ids = getSelectedIds();
    if (!ids.length) return;

    const numericIds = ids.filter(id => /^\d+$/.test(id));
    if (numericIds.length) {
      try {
        const res = await fetch(
          `${API_QUERY}?action=multi_export&scan_ids=${encodeURIComponent(numericIds.join(','))}&format=${encodeURIComponent(format)}`,
          { credentials: 'same-origin' }
        );
        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Failed to export the selected scans.', 'error');
          return;
        }

        if (format === 'json') {
          downloadBlob(
            new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
            'scans_export.json'
          );
          showToast('Exported the selected scans as JSON.');
          return;
        }

        const csv = 'Scan ID,Scan Name,Target,API Source,Query Type,Query Value,Data Type,Risk Score,Status,False Positive,Queried At\n' +
          (data.results || []).map(row => {
            const scan = (data.scans || []).find(item => Number(item.id) === Number(row.scan_id));
            return `"${row.scan_id}","${scan?.name || ''}","${scan?.target || ''}","${row.api_source || ''}","${row.query_type || ''}","${row.query_value || ''}","${row.data_type || ''}","${row.risk_score || ''}","${row.status || ''}","${row.false_positive ? 'yes' : 'no'}","${row.queried_at || ''}"`;
          }).join('\n');

        downloadBlob(new Blob([csv], { type: 'text/csv' }), 'scans_export.csv');
        showToast('Exported the selected scans as CSV.');
      } catch {
        showToast('Failed to export the selected scans.', 'error');
      }
      return;
    }

    if (format === 'json') {
      const rows = allScans.filter(scan => ids.includes(String(scan.id)));
      downloadBlob(
        new Blob([JSON.stringify({ scans: rows }, null, 2)], { type: 'application/json' }),
        'scans_export.json'
      );
      showToast('Exported the selected preview scans as JSON.');
      return;
    }

    const rows = allScans.filter(scan => ids.includes(String(scan.id)));
    const csv = 'Name,Target,Started,Finished,Status,Elements\n' +
      rows.map(scan => `"${scan.name}","${scan.target}","${scan.started_at || ''}","${scan.finished_at || ''}","${scan.status}","${scan.total_elements || 0}"`).join('\n');

    downloadBlob(new Blob([csv], { type: 'text/csv' }), 'scans_export.csv');
    showToast('Exported the selected preview scans as CSV.');
  }

  exportBtn?.addEventListener('click', () => {
    exportSelectedAs('csv');
  });

  exportJsonBtn?.addEventListener('click', () => {
    exportSelectedAs('json');
  });

  refreshVisibleScans();
});
