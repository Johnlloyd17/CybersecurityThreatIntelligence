<!DOCTYPE html>
<?php
require_once __DIR__ . '/php/SpiderFootModuleMapper.php';
$ctiSpiderFootOrder = SpiderFootModuleMapper::getOrderedCtiSlugs();
$ctiSpiderFootDisplaySlugs = SpiderFootModuleMapper::getDisplaySlugMap();
?>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Settings &mdash; CTI Platform</title>
    <link rel="stylesheet" href="assets/css/styles.css?v=<?php echo filemtime('assets/css/styles.css'); ?>">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?php echo filemtime('assets/css/dashboard.css'); ?>">
    <script>document.documentElement.setAttribute('data-theme',localStorage.getItem('cti-theme')||'dark');</script>
    <script>
        window.CTI_SPIDERFOOT_MODULE_ORDER = <?php echo json_encode($ctiSpiderFootOrder, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_SPIDERFOOT_DISPLAY_SLUGS = <?php echo json_encode($ctiSpiderFootDisplaySlugs, JSON_UNESCAPED_SLASHES); ?>;
    </script>
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
            <a href="query.php" class="sidebar-link">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <span>Scans</span>
            </a>
            <a href="settings.php" class="sidebar-link active">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                <span>Settings</span>
            </a>
        </nav>
        <div class="sidebar-footer">
            <div class="sidebar-user">
                <div class="user-avatar" id="userAvatarInitial">A</div>
                <div class="user-info">
                    <span class="user-name" id="userName">Analyst Preview</span>
                    <span class="user-role label" id="userRole">Static Mode</span>
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
                <h2 class="topbar-title">Settings</h2>
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
                <span class="badge badge-medium">&#9679; <span class="badge-label">Static Mode</span></span>
            </div>
        </header>

        <div class="panel active" id="panelSettings">

            <!-- Action Bar -->
            <div class="settings-action-bar">
                <button class="btn btn-glitch" id="saveChanges">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                    Save Changes
                </button>
                <button class="btn btn-outline" id="importKeys">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    Import Snapshot
                </button>
                <button class="btn btn-outline" id="exportKeys">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    Export Snapshot
                </button>
                <button class="btn" id="resetFactory" style="background:var(--destructive);color:#fff;border-color:var(--destructive);">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                    Reset to Factory Default
                </button>
                <div class="settings-static-note">
                    Edit settings here, save them for future scans, or import/export a full admin configuration snapshot.
                </div>
            </div>

            <div class="card mb-4" style="padding:1rem 1.2rem;">
                <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem;">
                    <div>
                        <h3 style="margin:0;">Database Maintenance</h3>
                        <p class="label" style="margin:0.25rem 0 0;">Run safe maintenance tasks for CTI tables and review table statistics.</p>
                    </div>
                    <div style="display:flex;gap:8px;flex-wrap:wrap;">
                        <button class="btn btn-sm btn-outline" id="dbMaintStats">View Stats</button>
                        <button class="btn btn-sm btn-outline" id="dbMaintAnalyze">Analyze Tables</button>
                        <button class="btn btn-sm btn-outline" id="dbMaintOptimize">Optimize Tables</button>
                    </div>
                </div>
                <pre id="dbMaintOutput" class="label" style="margin:0;white-space:pre-wrap;background:rgba(0,0,0,0.08);padding:0.9rem;border-radius:12px;min-height:72px;">Maintenance output will appear here.</pre>
            </div>

            <!-- Two-Column Layout -->
            <div class="settings-layout">

                <!-- Left: Module Sidebar -->
                <div class="settings-mod-sidebar" id="settingsSidebar">
                    <div class="settings-mod-list" id="settingsModuleList">
                        <!-- Rendered by JS -->
                    </div>
                </div>

                <!-- Right: Settings Panel -->
                <div class="settings-panel" id="settingsPanel">
                    <div class="settings-panel-empty">
                        <p class="label" style="color:var(--muted-fg);">Select a module from the left to view its settings.</p>
                    </div>
                </div>

            </div>
        </div>
    </div><!-- /main-wrapper -->

    <!-- Sidebar overlay for mobile -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>

    <!-- Toast notification -->
    <div class="api-toast hidden" id="settingsToast"></div>

    <script src="assets/js/settings.static-data.js?v=<?php echo filemtime('assets/js/settings.static-data.js'); ?>"></script>
    <script src="assets/js/theme.js?v=<?php echo filemtime('assets/js/theme.js'); ?>"></script>
    <script src="assets/js/cti-refresh.js?v=<?php echo filemtime('assets/js/cti-refresh.js'); ?>"></script>
    <script src="assets/js/settings.js?v=<?php echo filemtime('assets/js/settings.js'); ?>"></script>
</body>
</html>
