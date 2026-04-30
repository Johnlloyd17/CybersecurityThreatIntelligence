<?php
$scanId = $_GET['id'] ?? '';
$previewMode = (isset($_GET['preview']) && $_GET['preview'] === '1') || $scanId === 'preview-draft';

$scanSettingsBaseline = [
    'global_settings' => [],
    'module_settings' => [],
];

function isSensitiveSettingOptionName(string $option): bool
{
    $normalized = strtolower(trim($option));
    return str_contains($normalized, 'api key') || str_contains($normalized, 'apikey');
}

function maskBaselineSettingValue(string $value): string
{
    $raw = trim($value);
    if ($raw === '') {
        return '';
    }

    if (preg_match('/^\*{4,}[a-z0-9]{0,4}$/i', $raw)) {
        return $raw;
    }

    $len = strlen($raw);
    if ($len <= 4) {
        return str_repeat('*', $len);
    }

    $suffix = substr($raw, -4);
    $stars = str_repeat('*', min(8, max(4, $len - 4)));
    return $stars . $suffix;
}

$baselinePath = __DIR__ . DIRECTORY_SEPARATOR . '.github' . DIRECTORY_SEPARATOR . 'SPIDERFOOT_SCAN_SETTINGS_BASELINE_TABLE.md';
if (is_readable($baselinePath)) {
    $baselineLines = file($baselinePath, FILE_IGNORE_NEW_LINES);
    if ($baselineLines !== false) {
        $inBaselineTable = false;
        foreach ($baselineLines as $line) {
            // Keep trailing tabs for tab-delimited rows so empty Value cells are preserved.
            $rawLine = rtrim((string)$line, "\r\n");
            if (trim($rawLine) === '') {
                continue;
            }

            // Support both tab-separated and pipe-delimited formats
            if (strpos($rawLine, "\t") !== false) {
                $cells = explode("\t", $rawLine);
                $cells = array_map('trim', $cells);
            } elseif (ltrim($rawLine)[0] === '|') {
                $cells = preg_split('/(?<!\\\\)\|/', trim($rawLine, '|'));
                if (!is_array($cells) || count($cells) < 3) {
                    continue;
                }
                $cells = array_map(
                    static fn(string $cell): string => trim(str_replace('\\|', '|', $cell)),
                    $cells
                );
            } else {
                continue;
            }

            if (count($cells) < 3) {
                continue;
            }

            if (!$inBaselineTable) {
                $header = array_map('strtolower', array_slice($cells, 0, 3));
                if ($header === ['module', 'option', 'value']) {
                    $inBaselineTable = true;
                }
                continue;
            }

            $isSeparatorRow = true;
            foreach (array_slice($cells, 0, 3) as $cell) {
                if (!preg_match('/^:?-{2,}:?$/', $cell)) {
                    $isSeparatorRow = false;
                    break;
                }
            }
            if ($isSeparatorRow) {
                continue;
            }

            $module = (string)($cells[0] ?? '');
            $option = (string)($cells[1] ?? '');
            $value = (string)implode('|', array_slice($cells, 2));
            if ($module === '' || $option === '') {
                continue;
            }

            if (isSensitiveSettingOptionName($option)) {
                $value = maskBaselineSettingValue($value);
            }

            if (strtolower($module) === 'sfp__global') {
                $scanSettingsBaseline['global_settings'][] = [
                    'option' => $option,
                    'value' => $value,
                ];
                continue;
            }

            $scanSettingsBaseline['module_settings'][] = [
                'module' => $module,
                'option' => $option,
                'value' => $value,
            ];
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Details &mdash; CTI Platform</title>
    <link rel="stylesheet" href="assets/css/styles.css?v=<?php echo filemtime('assets/css/styles.css'); ?>">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?php echo filemtime('assets/css/dashboard.css'); ?>">
    <script>document.documentElement.setAttribute('data-theme',localStorage.getItem('cti-theme')||'dark');</script>
</head>
<body>

    <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
         SIDEBAR
         â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
    <aside class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <a href="dashboard.php" class="nav-logo">
                <span class="accent-text">&lt;</span>CTI<span class="accent-text">/&gt;</span>
            </a>
            <button class="sidebar-close" id="sidebarClose" aria-label="Close sidebar">&#10005;</button>
        </div>
        <nav class="sidebar-nav">
            <a href="dashboard.php" class="sidebar-link">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
                <span>Dashboard</span>
            </a>
            <a href="newscan.php" class="sidebar-link">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                <span>New Scan</span>
            </a>
            <a href="query.php" class="sidebar-link active">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <span>Scans</span>
            </a>
            <a href="settings.php" class="sidebar-link">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                <span>Settings</span>
            </a>
        </nav>
        <div class="sidebar-footer">
            <div class="sidebar-user">
                <div class="user-avatar" id="userAvatarInitial">A</div>
                <div class="user-info">
                    <span class="user-name" id="userName">Loading...</span>
                    <span class="user-role label" id="userRole">&mdash;</span>
                </div>
            </div>
            <button class="btn btn-ghost btn-sm w-full" id="logoutBtn">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Logout
            </button>
        </div>
    </aside>

    <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
         MAIN CONTENT
         â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
    <div class="main-wrapper" id="mainWrapper">
        <header class="topbar">
            <div class="topbar-left">
                <button class="sidebar-toggle" id="sidebarToggle" aria-label="Toggle sidebar">
                    <span></span><span></span><span></span>
                </button>
                <h2 class="topbar-title">
                    <a href="query.php" class="label" style="color:var(--muted-fg);text-decoration:none;margin-right:8px;">&larr; Scans</a>
                    <span id="scanTitle">Loading...</span>
                    <span class="scan-status-badge" id="scanStatusBadge"></span>
                    <span class="scan-status-badge badge badge-medium" id="scanBackendBadge" style="display:none;"></span>
                </h2>
            </div>
            <div class="topbar-right">
                <span class="label" id="currentTime"></span>
                <button class="theme-toggle cti-refresh-btn" data-cti-refresh aria-label="Refresh data" title="Refresh data">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                </button>
                <button class="theme-toggle" id="themeToggle" data-theme-toggle aria-label="Toggle theme">
                    <svg class="theme-icon-sun" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                    <svg class="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
                </button>
                <span class="badge badge-low">&#9679; <span class="badge-label">Connected</span></span>
            </div>
        </header>


        <!-- Stuck scan warning â€” shown by JS when scan has been running >10 min without finishing -->
        <div id="stuckScanBanner" style="display:none;align-items:center;gap:12px;padding:10px 20px;background:var(--badge-critical-bg,#3d1a1a);color:var(--badge-critical-fg,#ff6b6b);border-bottom:1px solid var(--badge-critical-fg,#ff6b6b);font-size:13px;">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <span>This scan has been running for more than 10 minutes. The background worker may have crashed.</span>
            <button class="btn btn-small btn-danger" onclick="document.dispatchEvent(new CustomEvent('abortScan'))" style="margin-left:auto;">Abort Scan</button>
        </div>

        <div class="panel active" id="panelScanInfo">
            <div class="scaninfo-wrap">

                <!-- Tab Navigation -->
                <div class="scaninfo-tabs-row">
                    <div class="scaninfo-tabs" id="scanInfoTabs">
                        <button class="scaninfo-tab active" data-tab="summary">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                            Summary
                        </button>
                        <button class="scaninfo-tab" data-tab="correlations">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                            Correlations
                        </button>
                        <button class="scaninfo-tab" data-tab="browse">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="16" rx="2"/><line x1="7" y1="8" x2="17" y2="8"/><line x1="7" y1="12" x2="17" y2="12"/><line x1="7" y1="16" x2="13" y2="16"/></svg>
                            Browse
                        </button>
                        <button class="scaninfo-tab" data-tab="graph">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                            Graph
                        </button>
                        <button class="scaninfo-tab" data-tab="settings">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                            Scan Settings
                        </button>
                        <button class="scaninfo-tab" data-tab="log">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
                            Log
                        </button>
                    </div>
                    <div class="scaninfo-actions">
                        <button class="btn btn-sm btn-ghost" id="siClone" title="Clone Scan">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                        <button class="btn btn-sm btn-accent" id="siRerun" title="Re-run Scan">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                        </button>
                        <button class="btn btn-sm btn-ghost" id="siRerunCorrelations" title="Re-run Correlations">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20V10"/><path d="m18 20-6-6-6 6"/><path d="M12 4v6"/><path d="m6 4 6 6 6-6"/></svg>
                        </button>
                        <button class="btn btn-sm btn-ghost" id="siExport" title="Export">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        </button>
                        <input type="text" class="input input-sm" id="siSearch" placeholder="Search..." style="width:200px;">
                        <button class="btn btn-sm btn-accent" id="siSearchBtn" title="Search">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        </button>
                    </div>
                </div>

                <!-- â”€â”€ TAB: Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ -->
                <div class="scaninfo-panel active" id="tabSummary">
                    <div class="scaninfo-summary-grid">
                        <!-- Scan Status Card -->
                        <div class="card-holo scaninfo-card">
                            <div class="corner-tl"></div><div class="corner-tr"></div>
                            <div class="corner-bl"></div><div class="corner-br"></div>
                            <div class="scaninfo-card-header">
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                                Scan Status
                            </div>
                            <div class="scaninfo-stat-row">
                                <div class="scaninfo-stat"><span class="label">Total</span><strong id="statTotal">0</strong></div>
                                <div class="scaninfo-stat"><span class="label">Unique</span><strong id="statUnique">0</strong></div>
                                <div class="scaninfo-stat"><span class="label">Status</span><strong id="statStatus">&mdash;</strong></div>
                                <div class="scaninfo-stat"><span class="label">Errors</span><strong id="statErrors" style="color:var(--destructive)">0</strong></div>
                            </div>
                        </div>

                        <!-- Correlations Card -->
                        <div class="card-holo scaninfo-card">
                            <div class="corner-tl"></div><div class="corner-tr"></div>
                            <div class="corner-bl"></div><div class="corner-br"></div>
                            <div class="scaninfo-card-header">
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
                                Correlations
                            </div>
                            <div class="scaninfo-corr-row" id="corrSummary">
                                <span class="corr-badge corr-high">High <strong>0</strong></span>
                                <span class="corr-badge corr-medium">Medium <strong>0</strong></span>
                                <span class="corr-badge corr-low">Low <strong>0</strong></span>
                                <span class="corr-badge corr-info">Info <strong>0</strong></span>
                            </div>
                        </div>
                    </div>

                    <!-- Data Types Chart -->
                    <div class="card-holo mt-4 scaninfo-card" style="padding-bottom:1.5rem;">
                        <div class="corner-tl"></div><div class="corner-tr"></div>
                        <div class="corner-bl"></div><div class="corner-br"></div>
                        <div class="scaninfo-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                            Data Types
                        </div>
                        <div id="chartContainer" class="scaninfo-chart"></div>
                    </div>

                    <div class="card-holo mt-4 scaninfo-card" style="padding-bottom:1.25rem;">
                        <div class="corner-tl"></div><div class="corner-tr"></div>
                        <div class="corner-bl"></div><div class="corner-br"></div>
                        <div class="scaninfo-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3v18h18"/><path d="M7 16l3-3 3 2 4-6"/></svg>
                            Temporal View
                        </div>
                        <div id="timelineContent" class="scaninfo-log"></div>
                    </div>

                    <div class="card-holo mt-4 scaninfo-card" id="dnsaIssueCard" style="display:none;padding-bottom:1.25rem;">
                        <div class="corner-tl"></div><div class="corner-tr"></div>
                        <div class="corner-bl"></div><div class="corner-br"></div>
                        <div class="scaninfo-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 2 7l10 5 10-5-10-5z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/></svg>
                            DNSAudit Issues & Solutions
                        </div>
                        <div id="dnsaIssueSummary" class="scaninfo-corr-row" style="margin-bottom:10px;"></div>
                        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-bottom:10px;">
                            <select id="dnsaIssueSeverity" class="input input-sm">
                                <option value="all">All Severities</option>
                                <option value="critical">Critical</option>
                                <option value="warning">Warning</option>
                                <option value="info">Info</option>
                            </select>
                            <select id="dnsaIssueGroup" class="input input-sm">
                                <option value="all">All Categories</option>
                            </select>
                            <input id="dnsaIssueSearch" class="input input-sm" type="text" placeholder="Search issue title/details...">
                        </div>
                        <div id="dnsaIssueList" class="scaninfo-log"></div>
                    </div>
                </div>

                <!-- â”€â”€ TAB: Correlations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ -->
                <div class="scaninfo-panel" id="tabCorrelations">
                    <div id="corrList"></div>
                </div>


                <!-- â”€â”€ TAB: Graph â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ -->
                <div class="scaninfo-panel" id="tabBrowse">
                    <div id="browseBreadcrumb" class="label mb-3" style="display:none;">
                        <a href="#" id="browseBackLink" class="accent-text">&larr; All Data Types</a>
                        <span id="breadcrumbSeparator" style="display:none;"> / </span>
                        <span id="breadcrumbTypeText"></span>
                    </div>

                    <div id="browseToolbar" class="scaninfo-log-actions mb-3" style="display:none;">
                        <label class="label" style="display:flex;align-items:center;gap:8px;">
                            <input type="checkbox" id="browseSelectAll">
                            Select visible elements
                        </label>
                    </div>

                    <div class="resp-table-wrap">
                        <table class="resp-table scan-table">
                            <thead id="browseTypeHeaders">
                                <tr>
                                    <th>Type</th>
                                    <th style="text-align:center;">Unique Data Elements</th>
                                    <th style="text-align:center;">Total Data Elements</th>
                                    <th>Last Data Element</th>
                                </tr>
                            </thead>
                            <thead id="browseDrilldownHeaders" style="display:none;">
                                <tr>
                                    <th style="width:40px;text-align:center;"></th>
                                    <th>Data Element</th>
                                    <th>Source Data Element</th>
                                    <th>Source Module</th>
                                    <th>Identified</th>
                                </tr>
                            </thead>
                            <tbody id="browseBody"></tbody>
                        </table>
                    </div>
                </div>

                <div class="scaninfo-panel" id="tabGraph">
                    <div class="scaninfo-graph-toolbar">
                        <button class="btn btn-sm btn-ghost active" id="graphRandom">R</button>
                        <button class="btn btn-sm btn-ghost" id="graphForce">F</button>
                        <button class="btn btn-sm btn-ghost" id="graphSaveImg" title="Save Image">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                        </button>
                        <button class="btn btn-sm btn-accent" id="graphRefresh" title="Refresh">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                        </button>
                        <button class="btn btn-sm btn-ghost" id="graphExport" title="Export">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        </button>
                        <button class="btn btn-sm btn-ghost" id="graphExportGexf" title="Export GEXF">GEXF</button>
                    </div>
                    <div id="graphCanvas" class="scaninfo-graph-canvas"></div>
                    <div class="card-holo scaninfo-card mt-4">
                        <div class="corner-tl"></div><div class="corner-tr"></div>
                        <div class="corner-bl"></div><div class="corner-br"></div>
                        <div class="scaninfo-card-header">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="2"/><path d="M12 2v4"/><path d="M12 18v4"/><path d="M4.93 4.93l2.83 2.83"/><path d="M16.24 16.24l2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/></svg>
                            Event Genealogy
                        </div>
                        <div style="padding:0 1.25rem 1.25rem;">
                            <select id="genealogySelect" class="input input-sm" style="max-width:420px;margin-bottom:12px;"></select>
                            <div id="genealogyContent" class="scaninfo-log"></div>
                        </div>
                    </div>
                </div>

                <!-- â”€â”€ TAB: Scan Settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ -->
                <div class="scaninfo-panel" id="tabSettings">
                    <div class="card-holo scaninfo-card">
                        <div class="corner-tl"></div><div class="corner-tr"></div>
                        <div class="corner-bl"></div><div class="corner-br"></div>
                        <div class="scaninfo-card-header">Meta Information</div>
                        <table class="settings-form-table">
                            <tbody id="settingsMetaBody">
                                <tr><td colspan="2" style="text-align:center;padding:1rem;" class="label">Loading meta information...</td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="card-holo scaninfo-card mt-4">
                        <div class="corner-tl"></div><div class="corner-tr"></div>
                        <div class="corner-bl"></div><div class="corner-br"></div>
                        <div class="scaninfo-card-header">Global Settings</div>
                        <table class="settings-form-table">
                            <thead>
                                <tr><th>Option</th><th>Value</th></tr>
                            </thead>
                            <tbody id="settingsGlobalBody">
                                <?php if (empty($scanSettingsBaseline['global_settings'])): ?>
                                <tr><td colspan="2" style="text-align:center;padding:1rem;" class="label">No global settings found.</td></tr>
                                <?php else: ?>
                                <?php foreach ($scanSettingsBaseline['global_settings'] as $s): ?>
                                <tr>
                                    <td class="scan-settings-cell settings-option-label scan-settings-option"><?= htmlspecialchars($s['option'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td class="scan-settings-cell settings-option-value scan-settings-value"><?= htmlspecialchars($s['value'], ENT_QUOTES, 'UTF-8') ?></td>
                                </tr>
                                <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>

                    <div class="card-holo scaninfo-card mt-4">
                        <div class="corner-tl"></div><div class="corner-tr"></div>
                        <div class="corner-bl"></div><div class="corner-br"></div>
                        <div class="scaninfo-card-header">
                            Module Settings
                            <span id="settingsSourceBadge" class="badge badge-small" style="margin-left:8px;display:none;"></span>
                        </div>
                        <table class="settings-form-table">
                            <thead>
                                <tr><th>Module</th><th>Option</th><th>Value</th></tr>
                            </thead>
                            <tbody id="settingsModuleBody">
                                <?php if (empty($scanSettingsBaseline['module_settings'])): ?>
                                <tr><td colspan="3" style="text-align:center;padding:1rem;" class="label">No module settings found.</td></tr>
                                <?php else: ?>
                                <?php foreach ($scanSettingsBaseline['module_settings'] as $s): ?>
                                <tr>
                                    <td class="scan-settings-cell scan-settings-module"><?= htmlspecialchars($s['module'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td class="scan-settings-cell settings-option-label scan-settings-option"><?= htmlspecialchars($s['option'], ENT_QUOTES, 'UTF-8') ?></td>
                                    <td class="scan-settings-cell settings-option-value scan-settings-value"><?= htmlspecialchars($s['value'], ENT_QUOTES, 'UTF-8') ?></td>
                                </tr>
                                <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- â”€â”€ TAB: Log â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ -->
                <div class="scaninfo-panel" id="tabLog">
                    <div class="scaninfo-log-actions mb-3">
                        <button class="btn btn-sm btn-ghost active" id="logFilterAll">All Logs</button>
                        <button class="btn btn-sm btn-ghost" id="logFilterErrors">Errors Only</button>
                        <button class="btn btn-sm btn-ghost" id="downloadLogs">
                            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            Download Scan Logs
                        </button>
                    </div>
                    <div class="scaninfo-log" id="logContent"></div>
                </div>

            </div>
        </div>
    </div><!-- /main-wrapper -->

    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <div class="api-toast hidden" id="pageToast"></div>

    <script src="assets/js/theme.js?v=<?php echo filemtime('assets/js/theme.js'); ?>"></script>
    <script src="assets/js/cti-refresh.js?v=<?php echo filemtime('assets/js/cti-refresh.js'); ?>"></script>
    <?php if ($previewMode): ?>
    <script src="assets/js/static-shell.js?v=<?php echo filemtime('assets/js/static-shell.js'); ?>"></script>
    <script src="assets/js/scans.static-data.js?v=<?php echo filemtime('assets/js/scans.static-data.js'); ?>"></script>
    <?php else: ?>
    <script src="assets/js/auth.js?v=<?php echo filemtime('assets/js/auth.js'); ?>"></script>
    <script src="assets/js/dashboard.js?v=<?php echo filemtime('assets/js/dashboard.js'); ?>"></script>
    <?php endif; ?>
    <script>
        window.CTI_SCAN_SETTINGS_BASELINE = <?php echo json_encode($scanSettingsBaseline, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES); ?>;
    </script>
    <script src="assets/js/scaninfo.js?v=<?php echo filemtime('assets/js/scaninfo.js'); ?>"></script>
</body>
</html>
