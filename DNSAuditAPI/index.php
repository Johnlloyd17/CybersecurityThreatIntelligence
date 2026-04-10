<?php
/**
 * DNSAudit API Integration - Dashboard
 *
 * Based on https://dnsaudit.io/docs/api
 */

require_once __DIR__ . '/src/Database.php';
require_once __DIR__ . '/src/DnsAuditClient.php';

$config = require __DIR__ . '/config.php';
$endpoints = $config['endpoints'] ?? [];

$dbOk = false;
$stats = [];
$assets = [];
$categories = [];
$dbError = null;
$dailyUsage = 0;
$dailyLimit = $config['rate_limits']['daily_scans'] ?? 20;

try {
    $db = Database::connect($config['db']);
    $dbOk = true;
    $stats = Database::getDashboardStats($db);
    $assets = Database::listAssets($db);
    $categories = Database::getCategories($db);
    $dailyUsage = Database::getDailyApiUsage($db);
} catch (Throwable $e) {
    $dbError = $e->getMessage();
}

$client = new DnsAuditClient($config);
$apiConfigured = $client->isConfigured();
$severityStats = array_merge(
    ['critical' => 0, 'warning' => 0, 'info' => 0],
    $stats['by_severity'] ?? []
);
$statusStats = array_merge(
    ['open' => 0, 'triaged' => 0, 'resolved' => 0, 'ignored' => 0],
    $stats['by_status'] ?? []
);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNSAudit API - Dashboard</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<div class="container">
    <div class="header">
        <h1><span>DNSAudit</span> API Dashboard</h1>
        <div>
            <span class="api-status <?= $apiConfigured ? 'connected' : 'error' ?>">
                API: <?= $apiConfigured ? 'Configured' : 'Not configured' ?>
            </span>
            <span class="api-status <?= $dbOk ? 'connected' : 'error' ?>">
                DB: <?= $dbOk ? 'Connected' : 'Error' ?>
            </span>
            <?php if ($dbOk): ?>
                <span class="api-status <?= $dailyUsage < $dailyLimit ? 'connected' : 'error' ?>">
                    Scans today: <?= $dailyUsage ?>/<?= $dailyLimit ?>
                </span>
            <?php endif; ?>
        </div>
    </div>

    <?php if (!$dbOk): ?>
        <div class="alert alert-error">
            Database connection failed: <?= htmlspecialchars($dbError ?? 'Unknown error') ?><br>
            Run <code>database.sql</code> in phpMyAdmin to create/update the schema.
        </div>
    <?php endif; ?>

    <?php if (!$apiConfigured): ?>
        <div class="alert alert-info">
            Set your DNSAudit API key in <code>config.php</code>. API is in early access -
            <a href="https://dnsaudit.io/api" target="_blank" style="color:var(--accent);">request access here</a>.
        </div>
    <?php endif; ?>

    <div class="tabs">
        <button class="tab active" data-tab="dashboard">Dashboard</button>
        <button class="tab" data-tab="scan">Scan</button>
        <button class="tab" data-tab="export">Export</button>
        <button class="tab" data-tab="findings">Findings</button>
        <button class="tab" data-tab="scans">Scan History</button>
        <button class="tab" data-tab="assets">Assets</button>
        <button class="tab" data-tab="logs">API Logs</button>
    </div>

    <!-- ============================================================= -->
    <!-- Dashboard Tab -->
    <!-- ============================================================= -->
    <div class="tab-panel active" id="tab-dashboard">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Avg Score</div>
                <div class="value"><?= $stats['avg_score'] ?? 0 ?>/100</div>
            </div>
            <div class="stat-card">
                <div class="label">Total Scans</div>
                <div class="value"><?= $stats['total_scans'] ?? 0 ?></div>
            </div>
            <div class="stat-card">
                <div class="label">Total Findings</div>
                <div class="value"><?= $stats['total_findings'] ?? 0 ?></div>
            </div>
            <div class="stat-card">
                <div class="label">Assets</div>
                <div class="value"><?= $stats['total_assets'] ?? 0 ?></div>
            </div>
            <div class="stat-card">
                <div class="label">Critical</div>
                <div class="value critical"><?= (int) $severityStats['critical'] ?></div>
            </div>
            <div class="stat-card">
                <div class="label">Warning</div>
                <div class="value high"><?= (int) $severityStats['warning'] ?></div>
            </div>
            <div class="stat-card">
                <div class="label">Info</div>
                <div class="value info"><?= (int) $severityStats['info'] ?></div>
            </div>
            <div class="stat-card">
                <div class="label">Open</div>
                <div class="value info"><?= (int) $statusStats['open'] ?></div>
            </div>
            <div class="stat-card">
                <div class="label">Resolved</div>
                <div class="value low"><?= (int) $statusStats['resolved'] ?></div>
            </div>
        </div>

        <?php if (!empty($endpoints)): ?>
            <div class="search-box">
                <h3>Configured API Endpoints</h3>
                <div class="table-wrap" style="margin-top: 12px;">
                    <table>
                        <thead>
                        <tr>
                            <th>Name</th>
                            <th>Method</th>
                            <th>Path</th>
                            <th>Description</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($endpoints as $name => $endpoint): ?>
                            <tr>
                                <td><?= htmlspecialchars($endpoint['label'] ?? strtoupper((string) $name)) ?></td>
                                <td><?= htmlspecialchars(strtoupper((string) ($endpoint['method'] ?? 'GET'))) ?></td>
                                <td><code><?= htmlspecialchars((string) ($endpoint['path'] ?? '-')) ?></code></td>
                                <td><?= htmlspecialchars((string) ($endpoint['description'] ?? '-')) ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>

        <?php if (!empty($stats['recent_scans'])): ?>
            <div class="search-box">
                <h3>Recent Scans</h3>
                <div class="table-wrap" style="margin-top: 12px;">
                    <table>
                        <thead>
                        <tr>
                            <th>Grade</th>
                            <th>Score</th>
                            <th>Domain</th>
                            <th>Findings</th>
                            <th>Critical</th>
                            <th>Warnings</th>
                            <th>Scanned</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($stats['recent_scans'] as $scan): ?>
                            <tr>
                                <td><span class="badge badge-<?= gradeClass($scan['grade'] ?? '') ?>"><?= htmlspecialchars($scan['grade'] ?? '-') ?></span></td>
                                <td><?= (int) ($scan['score'] ?? 0) ?>/100</td>
                                <td><?= htmlspecialchars($scan['domain']) ?></td>
                                <td><?= (int) $scan['total_findings'] ?></td>
                                <td><?= (int) $scan['critical_count'] ?></td>
                                <td><?= (int) $scan['warning_count'] ?></td>
                                <td><?= htmlspecialchars($scan['scanned_at'] ?? '-') ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php elseif ($dbOk): ?>
            <div class="empty-state">
                <h3>No scans yet</h3>
                <p>Use the Scan tab to run your first DNS security scan.</p>
            </div>
        <?php endif; ?>

        <?php if (!empty($stats['recent_findings'])): ?>
            <div class="search-box">
                <h3>Recent Findings</h3>
                <div class="table-wrap" style="margin-top: 12px;">
                    <table>
                        <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Domain</th>
                            <th>Category</th>
                            <th>Finding</th>
                            <th>Status</th>
                            <th>Scanned</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($stats['recent_findings'] as $f): ?>
                            <tr>
                                <?php
                                $severity = strtolower((string) ($f['severity'] ?? 'info'));
                                $severityClass = $severity === 'critical' ? 'critical' : ($severity === 'warning' ? 'high' : 'info');
                                ?>
                                <td><span class="badge badge-<?= htmlspecialchars($severityClass) ?>"><?= htmlspecialchars($severity) ?></span></td>
                                <td><?= htmlspecialchars($f['domain']) ?></td>
                                <td><?= htmlspecialchars($f['category'] ?? '-') ?></td>
                                <td title="<?= htmlspecialchars($f['title'] ?? '') ?>"><?= htmlspecialchars(truncateText((string) ($f['title'] ?? '-'), 70)) ?></td>
                                <td><span class="badge badge-<?= htmlspecialchars($f['status']) ?>"><?= htmlspecialchars($f['status']) ?></span></td>
                                <td><?= htmlspecialchars($f['scanned_at'] ?? '-') ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- ============================================================= -->
    <!-- Scan Tab -->
    <!-- ============================================================= -->
    <div class="tab-panel" id="tab-scan">
        <div class="search-box">
            <h3>Run DNS Security Scan</h3>
            <p class="hint" style="margin-bottom:16px;">
                Calls <code>GET /v1/scan?domain=</code> — runs 26+ checks including DNSSEC, SPF, DKIM, DMARC, zone transfer, and vulnerability detection.
            </p>
            <div class="form-row">
                <div class="form-group">
                    <label>Domain</label>
                    <input type="text" id="scan-domain" placeholder="example.com">
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn btn-primary" id="btn-scan" onclick="runScan()">Scan</button>
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <label class="checkbox-label">
                        <input type="checkbox" id="scan-save" checked> Save to DB
                    </label>
                </div>
            </div>
        </div>

        <div id="scan-status" style="display:none;" class="alert alert-info">
            <span class="spinner"></span> <span id="scan-status-text">Running DNS security scan (26+ checks)...</span>
        </div>
        <div id="scan-error" style="display:none;" class="alert alert-error"></div>
        <div id="scan-results"></div>
    </div>

    <!-- ============================================================= -->
    <!-- Export Tab -->
    <!-- ============================================================= -->
    <div class="tab-panel" id="tab-export">
        <div class="search-box">
            <h3>Export Scan Results</h3>
            <p class="hint" style="margin-bottom:16px;">
                Calls <code>GET /export/json/:domain</code> and <code>GET /export/pdf/:domain</code>.
            </p>
            <div class="form-row">
                <div class="form-group">
                    <label>Domain</label>
                    <input type="text" id="export-domain" placeholder="example.com">
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn btn-primary" id="btn-export" onclick="runExport()">Export JSON</button>
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn btn-outline" id="btn-export-pdf" onclick="downloadPdfReport()">Download PDF</button>
                </div>
            </div>
        </div>

        <div id="export-status" style="display:none;" class="alert alert-info">
            <span class="spinner"></span> Fetching export payload...
        </div>
        <div id="export-error" style="display:none;" class="alert alert-error"></div>
        <div id="export-results"></div>
    </div>

    <!-- ============================================================= -->
    <!-- Findings Tab -->
    <!-- ============================================================= -->
    <div class="tab-panel" id="tab-findings">
        <div class="search-box">
            <h3>Browse Findings</h3>
            <div class="form-row">
                <div class="form-group">
                    <label>Search</label>
                    <input type="text" id="filter-search" placeholder="Domain, title, category...">
                </div>
                <div class="form-group">
                    <label>Severity</label>
                    <select id="filter-severity">
                        <option value="">All</option>
                        <option value="critical">Critical</option>
                        <option value="warning">Warning</option>
                        <option value="info">Info</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Status</label>
                    <select id="filter-status">
                        <option value="">All</option>
                        <option value="open">Open</option>
                        <option value="triaged">Triaged</option>
                        <option value="resolved">Resolved</option>
                        <option value="ignored">Ignored</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Category</label>
                    <select id="filter-category">
                        <option value="">All</option>
                        <?php foreach ($categories as $category): ?>
                            <option value="<?= htmlspecialchars($category) ?>"><?= htmlspecialchars($category) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group">
                    <label>Limit</label>
                    <select id="filter-limit">
                        <option value="25">25</option>
                        <option value="50" selected>50</option>
                        <option value="100">100</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn btn-primary" onclick="loadFindings()">Filter</button>
                </div>
            </div>
        </div>
        <div id="findings-list">
            <?php if ($dbOk): ?>
                <div class="empty-state"><p>Use filters above to browse stored findings.</p></div>
            <?php endif; ?>
        </div>
    </div>

    <!-- ============================================================= -->
    <!-- Scan History Tab -->
    <!-- ============================================================= -->
    <div class="tab-panel" id="tab-scans">
        <div class="search-box">
            <h3>Local Scan History (Database)</h3>
            <div class="form-row">
                <div class="form-group">
                    <label>Domain</label>
                    <input type="text" id="local-domain-filter" placeholder="example.com">
                </div>
                <div class="form-group">
                    <label>Grade</label>
                    <select id="local-grade-filter">
                        <option value="">All</option>
                        <option value="A+">A+</option>
                        <option value="A">A</option>
                        <option value="B">B</option>
                        <option value="C">C</option>
                        <option value="D">D</option>
                        <option value="F">F</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Limit</label>
                    <input type="number" id="local-limit" min="1" max="100" value="20">
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn btn-outline" onclick="loadLocalScans()">Refresh Local</button>
                </div>
            </div>
        </div>
        <div id="local-scans-list">
            <div class="empty-state"><p>Click Refresh Local to load stored scan summaries.</p></div>
        </div>

        <div class="search-box">
            <h3>API Scan History</h3>
            <p class="hint" style="margin-bottom:16px;">
                Calls <code>GET /v1/scan-history?limit=</code> and renders whatever structure the API returns.
            </p>
            <div class="form-row">
                <div class="form-group">
                    <label>Limit</label>
                    <input type="number" id="api-history-limit" min="1" max="100" value="20">
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn btn-primary" onclick="fetchApiHistory()">Fetch from API</button>
                </div>
            </div>
        </div>
        <div id="api-scans-list">
            <div class="empty-state"><p>Click Fetch from API to load remote scan history.</p></div>
        </div>
    </div>

    <!-- ============================================================= -->
    <!-- Assets Tab -->
    <!-- ============================================================= -->
    <div class="tab-panel" id="tab-assets">
        <div class="search-box">
            <h3>Monitored Assets</h3>
            <div class="form-row">
                <div class="form-group">
                    <label>Domain / Host</label>
                    <input type="text" id="asset-value" placeholder="example.com">
                </div>
                <div class="form-group">
                    <label>Type</label>
                    <select id="asset-type">
                        <option value="domain">Domain</option>
                        <option value="host">Host</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>&nbsp;</label>
                    <button class="btn btn-primary" onclick="addAsset()">Add Asset</button>
                </div>
            </div>
        </div>

        <div id="asset-message" style="display:none;" class="alert"></div>

        <div class="table-wrap">
            <table>
                <thead>
                <tr><th>Asset</th><th>Type</th><th>Active</th><th>Added</th></tr>
                </thead>
                <tbody id="asset-list">
                <?php if (!empty($assets)): ?>
                    <?php foreach ($assets as $a): ?>
                        <tr>
                            <td><?= htmlspecialchars($a['asset']) ?></td>
                            <td><?= htmlspecialchars($a['type']) ?></td>
                            <td><?= (int) $a['is_active'] === 1 ? 'Yes' : 'No' ?></td>
                            <td><?= htmlspecialchars($a['created_at']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr><td colspan="4" style="text-align:center; color:var(--text-muted);">No assets added yet</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- ============================================================= -->
    <!-- API Logs Tab -->
    <!-- ============================================================= -->
    <div class="tab-panel" id="tab-logs">
        <div class="search-box">
            <h3>API Request Logs</h3>
            <button class="btn btn-outline" onclick="loadLogs()">Refresh</button>
        </div>
        <div id="logs-results">
            <div class="empty-state"><p>Click Refresh to load recent API logs.</p></div>
        </div>
    </div>
</div>

<script>
const API_CONFIGURED = <?= $apiConfigured ? 'true' : 'false' ?>;
const DB_CONNECTED = <?= $dbOk ? 'true' : 'false' ?>;

// -- Tab navigation ---------------------------------------------------
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        const panelId = 'tab-' + tab.dataset.tab;
        const panel = document.getElementById(panelId);
        if (panel) {
            panel.classList.add('active');
        }

        if (tab.dataset.tab === 'scans') {
            loadLocalScans();
        }
        if (tab.dataset.tab === 'logs') {
            loadLogs();
        }
    });
});

// -- Scan -------------------------------------------------------------
async function runScan() {
    const domain = document.getElementById('scan-domain').value.trim();
    if (!domain) return alert('Enter a domain');
    if (!API_CONFIGURED) return alert('API key not configured. Edit config.php first.');

    const save = document.getElementById('scan-save').checked;
    const btn = document.getElementById('btn-scan');

    btn.disabled = true;
    show('scan-status');
    hide('scan-error');
    document.getElementById('scan-results').innerHTML = '';

    try {
        const params = new URLSearchParams({ action: 'scan', domain, save: save ? '1' : '0' });
        const data = await requestJson('search.php?' + params.toString());

        hide('scan-status');

        if (data.error) {
            document.getElementById('scan-error').textContent = data.error;
            show('scan-error');
            return;
        }

        renderScanResponse(data);
        if (save && DB_CONNECTED) {
            loadLocalScans();
            loadFindings();
        }
    } catch (e) {
        hide('scan-status');
        document.getElementById('scan-error').textContent = 'Request failed: ' + e.message;
        show('scan-error');
    } finally {
        btn.disabled = false;
    }
}

function renderScanResponse(data) {
    const container = document.getElementById('scan-results');
    const scan = data.scan || {};
    const findings = extractFindings(scan);
    const severitySummary = summarizeFindings(findings);
    let html = '';

    // Score/Grade summary
    const grade = getGradeValue(scan) || '-';
    const score = getScoreValue(scan);
    const scoreLabel = score === null ? '-' : `${escHtml(String(score))}/100`;
    html += `<div class="stats-grid" style="margin-bottom:16px;">
        <div class="stat-card"><div class="label">Grade</div><div class="value">${escHtml(String(grade))}</div></div>
        <div class="stat-card"><div class="label">Score</div><div class="value">${scoreLabel}</div></div>
        <div class="stat-card"><div class="label">Findings</div><div class="value">${findings.length}</div></div>
        <div class="stat-card"><div class="label">Critical</div><div class="value critical">${severitySummary.critical}</div></div>
        <div class="stat-card"><div class="label">Warning</div><div class="value high">${severitySummary.warning}</div></div>
        <div class="stat-card"><div class="label">Info</div><div class="value info">${severitySummary.info}</div></div>
        <div class="stat-card"><div class="label">Daily Usage</div><div class="value">${data.daily_usage || '?'}/${data.daily_limit || 20}</div></div>
    </div>`;

    // Findings table
    if (findings.length > 0) {
        html += '<div class="search-box"><h3>Findings (' + findings.length + ')</h3>';
        html += '<div class="table-wrap" style="margin-top:12px;"><table><thead><tr>' +
            '<th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Recommendation</th>' +
            '</tr></thead><tbody>';

        findings.forEach(f => {
            const sev = normalizeSeverity(f.severity || f.type || 'info');
            const sevClass = severityClass(sev);
            html += `<tr>
                <td><span class="badge badge-${escHtml(sevClass)}">${escHtml(sev)}</span></td>
                <td>${escHtml(f.category || f.group || '-')}</td>
                <td>${escHtml(f.title || f.name || f.issue || '-')}</td>
                <td title="${escHtml(f.description || f.details || f.message || '')}">${escHtml(truncate(f.description || f.details || f.message || '-', 100))}</td>
                <td>${escHtml(f.recommendation || f.fix || f.solution || '-')}</td>
            </tr>`;
        });

        html += '</tbody></table></div></div>';
    } else {
        html += '<div class="empty-state"><p>No individual findings in the response. Raw response is shown below.</p></div>';
    }

    // Saved info
    if (data.saved > 0) {
        html += `<div class="alert alert-success">Saved ${data.saved} finding(s) to database.</div>`;
    }

    // Raw JSON (collapsed)
    html += `<details style="margin-top:16px;"><summary style="cursor:pointer;color:var(--text-muted);font-size:13px;">Raw API Response</summary>
        <div class="json-view" style="margin-top:8px;">${escHtml(JSON.stringify(scan, null, 2))}</div></details>`;

    container.innerHTML = html;
}

// -- Export -----------------------------------------------------------
async function runExport() {
    const domain = document.getElementById('export-domain').value.trim();
    if (!domain) return alert('Enter a domain');
    if (!API_CONFIGURED) return alert('API key not configured. Edit config.php first.');

    const btn = document.getElementById('btn-export');
    btn.disabled = true;
    show('export-status');
    hide('export-error');
    document.getElementById('export-results').innerHTML = '';

    try {
        const params = new URLSearchParams({ action: 'export', domain });
        const data = await requestJson('search.php?' + params.toString());
        hide('export-status');

        if (data.error) {
            document.getElementById('export-error').textContent = data.error;
            show('export-error');
            return;
        }

        renderExportResponse(data.export || {});
    } catch (e) {
        hide('export-status');
        document.getElementById('export-error').textContent = 'Request failed: ' + e.message;
        show('export-error');
    } finally {
        btn.disabled = false;
    }
}

async function downloadPdfReport() {
    const domain = document.getElementById('export-domain').value.trim();
    if (!domain) return alert('Enter a domain');
    if (!API_CONFIGURED) return alert('API key not configured. Edit config.php first.');

    const btn = document.getElementById('btn-export-pdf');
    btn.disabled = true;
    show('export-status');
    hide('export-error');

    try {
        const params = new URLSearchParams({ action: 'export_pdf', domain, pdf_format: 'detailed' });
        const response = await fetch('search.php?' + params.toString(), {
            headers: { 'Accept': 'application/pdf' },
        });

        if (!response.ok) {
            const raw = await response.text();
            const parsed = tryParseJson(raw) ?? extractEmbeddedJson(raw);
            const message = parsed?.error || compactText(raw).slice(0, 220) || `HTTP ${response.status}`;
            throw new Error(message);
        }

        const blob = await response.blob();
        const contentDisposition = response.headers.get('Content-Disposition') || '';
        const suggested = getFilenameFromContentDisposition(contentDisposition);
        const filename = suggested || `${domain}-dns-report.pdf`;

        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = objectUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(objectUrl);
    } catch (e) {
        document.getElementById('export-error').textContent = 'PDF export failed: ' + e.message;
        show('export-error');
    } finally {
        hide('export-status');
        btn.disabled = false;
    }
}

function renderExportResponse(payload) {
    const findings = extractFindings(payload);
    const grade = getGradeValue(payload) || '-';
    const score = getScoreValue(payload);
    const scoreLabel = score === null ? '-' : `${escHtml(String(score))}/100`;

    const html = `<div class="stats-grid" style="margin-bottom:16px;">
        <div class="stat-card"><div class="label">Grade</div><div class="value">${escHtml(String(grade))}</div></div>
        <div class="stat-card"><div class="label">Score</div><div class="value">${scoreLabel}</div></div>
        <div class="stat-card"><div class="label">Findings</div><div class="value">${findings.length}</div></div>
    </div>
    <details open><summary style="cursor:pointer;color:var(--text-muted);font-size:13px;">Export JSON Payload</summary>
        <div class="json-view" style="margin-top:8px;">${escHtml(JSON.stringify(payload, null, 2))}</div>
    </details>`;

    document.getElementById('export-results').innerHTML = html;
}

function extractFindings(scan) {
    for (const key of ['findings', 'issues']) {
        if (Array.isArray(scan[key])) return scan[key];
        if (scan.data && Array.isArray(scan.data[key])) return scan.data[key];
    }

    for (const key of ['results']) {
        if (Array.isArray(scan[key])) return scan[key];
        if (scan.data && Array.isArray(scan.data[key])) return scan.data[key];

        const topLevel = scan[key];
        if (topLevel && typeof topLevel === 'object') {
            const mapped = mapResultsObjectToFindings(topLevel);
            if (mapped.length > 0) return mapped;
        }

        const nested = scan.data?.[key];
        if (nested && typeof nested === 'object') {
            const mapped = mapResultsObjectToFindings(nested);
            if (mapped.length > 0) return mapped;
        }
    }

    if (scan.data && Array.isArray(scan.data)) return scan.data;
    return [];
}

// -- Findings ---------------------------------------------------------
async function loadFindings() {
    const params = new URLSearchParams({
        action: 'findings',
        search: document.getElementById('filter-search').value,
        severity: document.getElementById('filter-severity').value,
        status: document.getElementById('filter-status').value,
        category: document.getElementById('filter-category').value,
        limit: document.getElementById('filter-limit').value || '50',
    });

    try {
        const data = await requestJson('search.php?' + params.toString());

        if (data.error) {
            document.getElementById('findings-list').innerHTML = `<div class="alert alert-error">${escHtml(data.error)}</div>`;
            return;
        }

        const rows = data.findings || [];
        if (rows.length === 0) {
            document.getElementById('findings-list').innerHTML = '<div class="empty-state"><p>No findings match the filters.</p></div>';
            return;
        }

        let html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Severity</th><th>Domain</th><th>Category</th><th>Finding</th><th>Description</th><th>Status</th><th>Scanned</th>' +
            '</tr></thead><tbody>';

        rows.forEach(r => {
            const sev = normalizeSeverity(r.severity || 'info');
            const sevClass = severityClass(sev);
            html += `<tr>
                <td><span class="badge badge-${escHtml(sevClass)}">${escHtml(sev)}</span></td>
                <td>${escHtml(r.domain || '-')}</td>
                <td>${escHtml(r.category || '-')}</td>
                <td title="${escHtml(r.title || '')}">${escHtml(truncate(r.title || '-', 60))}</td>
                <td title="${escHtml(r.description || '')}">${escHtml(truncate(r.description || '-', 80))}</td>
                <td>
                    <select onchange="updateStatus(${r.id}, this.value)" style="font-size:11px;padding:2px 4px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;">
                        <option value="open" ${r.status === 'open' ? 'selected' : ''}>Open</option>
                        <option value="triaged" ${r.status === 'triaged' ? 'selected' : ''}>Triaged</option>
                        <option value="resolved" ${r.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                        <option value="ignored" ${r.status === 'ignored' ? 'selected' : ''}>Ignored</option>
                    </select>
                </td>
                <td>${escHtml(r.scanned_at || '-')}</td>
            </tr>`;
        });

        html += '</tbody></table></div>';
        document.getElementById('findings-list').innerHTML = html;
    } catch (e) {
        document.getElementById('findings-list').innerHTML = `<div class="alert alert-error">Failed: ${escHtml(e.message)}</div>`;
    }
}

async function updateStatus(id, status) {
    try {
        const data = await requestJson('search.php?' + new URLSearchParams({ action: 'update_status', id, status }));
        if (data.error) alert(data.error);
    } catch (e) {
        alert('Failed: ' + e.message);
    }
}

// -- Scan History -----------------------------------------------------
async function loadLocalScans() {
    const target = document.getElementById('local-scans-list');
    if (!DB_CONNECTED) {
        target.innerHTML = '<div class="alert alert-error">Database is not connected.</div>';
        return;
    }

    const params = new URLSearchParams({
        action: 'summaries',
        domain: document.getElementById('local-domain-filter').value.trim(),
        grade: document.getElementById('local-grade-filter').value,
        limit: String(clampInt(document.getElementById('local-limit').value, 20, 1, 100)),
    });

    try {
        const data = await requestJson('search.php?' + params.toString());

        if (data.error) {
            target.innerHTML = `<div class="alert alert-error">${escHtml(data.error)}</div>`;
            return;
        }

        const rows = data.summaries || [];
        if (rows.length === 0) {
            target.innerHTML = '<div class="empty-state"><p>No local scans found for the selected filters.</p></div>';
            return;
        }

        let html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Grade</th><th>Score</th><th>Domain</th><th>Findings</th><th>Critical</th><th>Warning</th><th>Info</th><th>Scanned</th>' +
            '</tr></thead><tbody>';

        rows.forEach(row => {
            html += `<tr>
                <td><span class="badge badge-${escHtml(gradeClassJs(row.grade || '-'))}">${escHtml(row.grade || '-')}</span></td>
                <td>${escHtml(String(row.score ?? '-'))}</td>
                <td>${escHtml(row.domain || '-')}</td>
                <td>${escHtml(String(row.total_findings ?? 0))}</td>
                <td>${escHtml(String(row.critical_count ?? 0))}</td>
                <td>${escHtml(String(row.warning_count ?? 0))}</td>
                <td>${escHtml(String(row.info_count ?? 0))}</td>
                <td>${escHtml(row.scanned_at || '-')}</td>
            </tr>`;
        });

        html += '</tbody></table></div>';
        target.innerHTML = html;
    } catch (e) {
        target.innerHTML = `<div class="alert alert-error">${escHtml(e.message)}</div>`;
    }
}

async function fetchApiHistory() {
    const target = document.getElementById('api-scans-list');
    if (!API_CONFIGURED) {
        target.innerHTML = '<div class="alert alert-error">API key not configured.</div>';
        return;
    }

    const params = new URLSearchParams({
        action: 'history',
        limit: String(clampInt(document.getElementById('api-history-limit').value, 20, 1, 100)),
    });

    try {
        const data = await requestJson('search.php?' + params.toString());

        if (data.error) {
            target.innerHTML = `<div class="alert alert-error">${escHtml(data.error)}</div>`;
            return;
        }

        const history = data.history;
        const items = normalizeHistoryItems(history);
        if (items.length === 0) {
            target.innerHTML = '<div class="empty-state"><p>No scan history returned from API.</p></div>';
            return;
        }

        let html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Domain</th><th>Grade</th><th>Score</th><th>Findings</th><th>Timestamp</th>' +
            '</tr></thead><tbody>';

        items.forEach(item => {
            const domain = item.domain || item.asset || item.host || item.hostname || '-';
            const grade = getGradeValue(item) || '-';
            const score = getScoreValue(item);
            const scoreLabel = score === null ? '-' : String(score);
            const findingsCount = getHistoryFindingCount(item);
            const scannedAt = item.scanned_at || item.created_at || item.timestamp || item.date || '-';

            html += `<tr>
                <td>${escHtml(String(domain))}</td>
                <td><span class="badge badge-${escHtml(gradeClassJs(String(grade)))}">${escHtml(String(grade))}</span></td>
                <td>${escHtml(scoreLabel)}</td>
                <td>${escHtml(String(findingsCount))}</td>
                <td>${escHtml(String(scannedAt))}</td>
            </tr>`;
        });

        html += '</tbody></table></div>';
        html += `<details style="margin-top:12px;"><summary style="cursor:pointer;color:var(--text-muted);font-size:13px;">Raw API History Payload</summary>
            <div class="json-view" style="margin-top:8px;">${escHtml(JSON.stringify(history, null, 2))}</div></details>`;
        target.innerHTML = html;
    } catch (e) {
        target.innerHTML = `<div class="alert alert-error">Failed: ${escHtml(e.message)}</div>`;
    }
}

function normalizeHistoryItems(history) {
    if (Array.isArray(history)) return history;
    if (!history || typeof history !== 'object') return [];

    const keys = ['scans', 'history', 'items', 'results', 'data'];
    for (const key of keys) {
        if (Array.isArray(history[key])) return history[key];
    }
    if (history.data && typeof history.data === 'object') {
        for (const key of keys) {
            if (Array.isArray(history.data[key])) return history.data[key];
        }
    }
    return [history];
}

function getHistoryFindingCount(item) {
    if (Number.isFinite(Number(item.total_findings))) return Number(item.total_findings);
    if (Number.isFinite(Number(item.finding_count))) return Number(item.finding_count);
    const fromMain = extractFindings(item);
    if (fromMain.length > 0) return fromMain.length;
    return 0;
}

// -- Assets -----------------------------------------------------------
async function addAsset() {
    const asset = document.getElementById('asset-value').value.trim();
    const type = document.getElementById('asset-type').value;
    if (!asset) return alert('Enter an asset');

    try {
        const params = new URLSearchParams({ action: 'add_asset', asset, type });
        const data = await requestJson('search.php?' + params.toString());
        const msg = document.getElementById('asset-message');

        if (data.error) {
            msg.className = 'alert alert-error';
            msg.textContent = data.error;
        } else {
            msg.className = 'alert alert-success';
            msg.textContent = `Asset "${asset}" added.`;
            prependAssetRow(asset, type);
            document.getElementById('asset-value').value = '';
        }
        msg.style.display = 'block';
    } catch (e) {
        alert('Failed: ' + e.message);
    }
}

function prependAssetRow(asset, type) {
    const tbody = document.getElementById('asset-list');
    const firstCell = tbody.querySelector('tr td');
    if (firstCell && firstCell.textContent.includes('No assets')) tbody.innerHTML = '';

    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escHtml(asset)}</td><td>${escHtml(type)}</td><td>Yes</td><td>${new Date().toLocaleString()}</td>`;
    tbody.prepend(tr);
}

// -- API Logs ---------------------------------------------------------
async function loadLogs() {
    try {
        const data = await requestJson('search.php?action=logs');
        const logs = data.logs || [];

        if (logs.length === 0) {
            document.getElementById('logs-results').innerHTML = '<div class="empty-state"><p>No API logs yet.</p></div>';
            return;
        }

        let html = '<div class="table-wrap"><table><thead><tr>' +
            '<th>Time</th><th>Endpoint</th><th>Domain</th><th>HTTP Status</th><th>Findings</th><th>Response (ms)</th>' +
            '</tr></thead><tbody>';

        logs.forEach(l => {
            html += `<tr>
                <td>${escHtml(l.created_at || '-')}</td>
                <td>${escHtml(l.endpoint || '-')}</td>
                <td>${escHtml(l.domain || '-')}</td>
                <td>${escHtml(String(l.http_status ?? '-'))}</td>
                <td>${escHtml(String(l.finding_count ?? '-'))}</td>
                <td>${escHtml(String(l.response_time_ms ?? '-'))}</td>
            </tr>`;
        });
        html += '</tbody></table></div>';
        document.getElementById('logs-results').innerHTML = html;
    } catch (e) {
        document.getElementById('logs-results').innerHTML = `<div class="alert alert-error">Failed: ${escHtml(e.message)}</div>`;
    }
}

// -- Helpers ----------------------------------------------------------
async function requestJson(url) {
    const response = await fetch(url, {
        headers: { 'Accept': 'application/json' },
    });
    const raw = await response.text();

    const parsed = tryParseJson(raw) ?? extractEmbeddedJson(raw);
    if (parsed !== null) {
        return parsed;
    }

    const snippet = compactText(raw).slice(0, 220);
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${snippet || 'Invalid JSON response'}`);
    }
    throw new Error(`Invalid JSON response: ${snippet || 'Empty response'}`);
}

function tryParseJson(raw) {
    if (typeof raw !== 'string') return null;
    const text = raw.trim();
    if (text === '') return null;
    try {
        return JSON.parse(text);
    } catch {
        return null;
    }
}

function extractEmbeddedJson(raw) {
    if (typeof raw !== 'string') return null;

    const firstObj = raw.indexOf('{');
    const lastObj = raw.lastIndexOf('}');
    if (firstObj !== -1 && lastObj > firstObj) {
        const objCandidate = raw.slice(firstObj, lastObj + 1);
        const parsedObj = tryParseJson(objCandidate);
        if (parsedObj !== null) {
            return parsedObj;
        }
    }

    const firstArr = raw.indexOf('[');
    const lastArr = raw.lastIndexOf(']');
    if (firstArr !== -1 && lastArr > firstArr) {
        const arrCandidate = raw.slice(firstArr, lastArr + 1);
        const parsedArr = tryParseJson(arrCandidate);
        if (parsedArr !== null) {
            return parsedArr;
        }
    }

    return null;
}

function compactText(value) {
    return String(value || '').replace(/\s+/g, ' ').trim();
}

function summarizeFindings(findings) {
    const summary = { critical: 0, warning: 0, info: 0 };
    findings.forEach(item => {
        const sev = normalizeSeverity(item.severity || item.type || 'info');
        if (sev === 'critical') summary.critical += 1;
        else if (sev === 'warning') summary.warning += 1;
        else summary.info += 1;
    });
    return summary;
}

function normalizeSeverity(raw) {
    const value = String(raw || '').toLowerCase().trim();
    if (['critical', 'high', 'danger', 'error', 'fail', 'failed'].includes(value)) return 'critical';
    if (['warning', 'warn', 'medium'].includes(value)) return 'warning';
    return 'info';
}

function getGradeValue(payload) {
    const candidates = [
        payload?.grade,
        payload?.data?.grade,
        payload?.summary?.grade,
        payload?.summary?.overallGrade,
    ];

    for (const candidate of candidates) {
        const grade = toGradeIfPossible(candidate);
        if (grade !== null) {
            return grade;
        }
    }

    return null;
}

function toGradeIfPossible(value) {
    if (value === null || value === undefined) {
        return null;
    }

    if (Array.isArray(value)) {
        for (const entry of value) {
            const nested = toGradeIfPossible(entry);
            if (nested !== null) return nested;
        }
        return null;
    }

    if (typeof value === 'object') {
        for (const key of ['grade', 'letter', 'value', 'current', 'overall', 'overallGrade']) {
            if (!Object.prototype.hasOwnProperty.call(value, key)) {
                continue;
            }

            const nested = toGradeIfPossible(value[key]);
            if (nested !== null) return nested;
        }
        return null;
    }

    const text = String(value).trim();
    if (text === '') return null;

    const match = text.toUpperCase().match(/\b([A-F][+-]?)\b/);
    return match ? match[1] : null;
}

function getScoreValue(payload) {
    const candidates = [
        payload?.score,
        payload?.securityScore,
        payload?.data?.score,
        payload?.data?.securityScore,
    ];

    for (const candidate of candidates) {
        const value = toNumberIfPossible(candidate);
        if (value !== null) {
            return value;
        }
    }
    return null;
}

function toNumberIfPossible(value) {
    if (value === null || value === undefined) {
        return null;
    }

    if (typeof value === 'string' && value.trim() === '') {
        return null;
    }

    if (Number.isFinite(Number(value))) {
        return Number(value);
    }

    if (value && typeof value === 'object') {
        for (const key of ['total', 'count', 'value', 'score', 'securityScore']) {
            if (Object.prototype.hasOwnProperty.call(value, key)) {
                const nested = toNumberIfPossible(value[key]);
                if (nested !== null) return nested;
            }
        }
    }

    return null;
}

function mapResultsObjectToFindings(results) {
    if (!results || typeof results !== 'object' || Array.isArray(results)) return [];

    const findings = [];
    Object.entries(results).forEach(([checkName, payload]) => {
        const category = humanizeKey(checkName);
        const title = category || 'Result';

        if (Array.isArray(payload)) {
            payload.forEach((item) => {
                if (item && typeof item === 'object') {
                    findings.push({
                        severity: item.severity || item.status || 'info',
                        category: item.category || category,
                        title: item.title || item.check || title,
                        description: item.description || item.details || item.message || item.record || null,
                        recommendation: item.recommendation || item.fix || item.solution || null,
                    });
                    return;
                }

                if (item !== null && item !== undefined && String(item).trim() !== '') {
                    findings.push({
                        severity: 'info',
                        category,
                        title,
                        description: String(item),
                    });
                }
            });
            return;
        }

        if (payload && typeof payload === 'object') {
            findings.push({
                severity: payload.severity || payload.status || 'info',
                category: payload.category || category,
                title: payload.title || payload.check || title,
                description: payload.description || payload.details || payload.message || payload.record || null,
                recommendation: payload.recommendation || payload.fix || payload.solution || null,
            });
            return;
        }

        if (payload !== null && payload !== undefined && String(payload).trim() !== '') {
            findings.push({
                severity: 'info',
                category,
                title,
                description: String(payload),
            });
        }
    });

    return findings;
}

function humanizeKey(key) {
    const text = String(key || '');
    return text
        .replace(/([a-z])([A-Z])/g, '$1 $2')
        .replace(/[_.-]+/g, ' ')
        .replace(/\s+/g, ' ')
        .trim()
        .replace(/\b\w/g, (match) => match.toUpperCase());
}

function getFilenameFromContentDisposition(headerValue) {
    const header = String(headerValue || '');
    if (header === '') return null;

    const utf8Match = header.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match && utf8Match[1]) {
        try {
            return decodeURIComponent(utf8Match[1]);
        } catch {
            return utf8Match[1];
        }
    }

    const basicMatch = header.match(/filename=\"?([^\";]+)\"?/i);
    if (basicMatch && basicMatch[1]) {
        return basicMatch[1];
    }

    return null;
}

function severityClass(severity) {
    if (severity === 'critical') return 'critical';
    if (severity === 'warning') return 'high';
    return 'info';
}

function gradeClassJs(grade) {
    const g = String(grade || '').toUpperCase().trim();
    if (g.startsWith('A')) return 'info';
    if (g.startsWith('B')) return 'low';
    if (g.startsWith('C')) return 'medium';
    if (g.startsWith('D')) return 'high';
    return 'critical';
}

function truncate(value, maxLength) {
    const str = String(value || '');
    if (str.length <= maxLength) return str;
    return str.slice(0, maxLength - 3) + '...';
}

function clampInt(value, fallback, min, max) {
    const n = parseInt(String(value), 10);
    if (Number.isNaN(n)) return fallback;
    return Math.min(max, Math.max(min, n));
}

function show(id) { document.getElementById(id).style.display = 'block'; }
function hide(id) { document.getElementById(id).style.display = 'none'; }
function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
}

if (DB_CONNECTED) {
    loadLocalScans();
}
</script>
</body>
</html>

<?php
function gradeClass(string $grade): string
{
    $g = strtoupper(trim($grade));
    if (str_starts_with($g, 'A')) return 'info';
    if (str_starts_with($g, 'B')) return 'low';
    if (str_starts_with($g, 'C')) return 'medium';
    if (str_starts_with($g, 'D')) return 'high';
    return 'critical'; // F or unknown
}

function truncateText(string $text, int $maxLength): string
{
    if ($maxLength <= 3 || strlen($text) <= $maxLength) {
        return $text;
    }
    return substr($text, 0, $maxLength - 3) . '...';
}
?>

