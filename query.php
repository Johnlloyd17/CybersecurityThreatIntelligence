<?php
$previewMode = isset($_GET['preview']) && $_GET['preview'] === '1';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scans â€” CTI Platform</title>
    <link rel="stylesheet" href="assets/css/styles.css?v=<?php echo filemtime('assets/css/styles.css'); ?>">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?php echo filemtime('assets/css/dashboard.css'); ?>">
    <script>document.documentElement.setAttribute('data-theme',localStorage.getItem('cti-theme')||'dark');</script>
    <script>window.CTI_ENABLE_STATIC_SCAN_PREVIEW = <?php echo $previewMode ? 'true' : 'false'; ?>;</script>
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
                <h2 class="topbar-title">Scans</h2>
            </div>
            <div class="topbar-right">
                <span class="label" id="currentTime"></span>
                <button class="theme-toggle" id="themeToggle" data-theme-toggle aria-label="Toggle theme">
                    <svg class="theme-icon-sun" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                    <svg class="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
                </button>
            </div>
        </header>


        <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
             VIEW: NEW SCAN (collapsible)
             â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
        <div class="panel active" id="panelScans">
            <div class="scan-page-wrap">

                <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
                     SCANS LIST TABLE
                     â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
                <div id="scanListSection">
                    <!-- Toolbar -->
                    <div class="page-toolbar mb-4">
                        <div class="flex items-center gap-3" style="flex-wrap:wrap;">
                            <!-- Filter dropdown -->
                            <div class="scan-filter-wrap">
                                <button class="btn btn-sm btn-ghost" id="filterBtn">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/></svg>
                                    Filter: <span id="filterLabel">None</span>
                                </button>
                                <div class="scan-filter-menu hidden" id="filterMenu">
                                    <button class="scan-filter-opt active" data-filter="">None</button>
                                    <button class="scan-filter-opt" data-filter="running">Running</button>
                                    <button class="scan-filter-opt" data-filter="finished">Finished</button>
                                    <button class="scan-filter-opt" data-filter="failed">Failed / Aborted</button>
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center gap-2">
                            <button class="btn btn-sm btn-ghost" id="refreshScans" title="Refresh">
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                            </button>
                            <button class="btn btn-sm btn-ghost" id="stopSelected" title="Terminate Selected" disabled>
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12"/></svg>
                            </button>
                            <button class="btn btn-sm btn-accent" id="rerunSelected" title="Re-run Selected" disabled>
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                            </button>
                            <button class="btn btn-sm btn-accent" id="exportSelected" title="Export Selected" disabled>
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            </button>
                            <button class="btn btn-sm btn-outline" id="exportJsonSelected" title="Export Selected as JSON" disabled>
                                JSON
                            </button>
                            <button class="btn btn-sm" id="deleteSelected" title="Delete Selected" disabled style="background:var(--destructive);color:#fff;border-color:var(--destructive);">
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            </button>
                        </div>
                    </div>

                    <!-- Scans Table -->
                    <div class="resp-table-wrap">
                        <table class="resp-table scan-table" id="scanTable">
                            <thead>
                                <tr>
                                    <th style="width:30px;text-align:center;"><input type="checkbox" id="selectAllScans"></th>
                                    <th class="sortable" data-sort="name" style="white-space:nowrap;">Name</th>
                                    <th class="sortable" data-sort="target" style="white-space:nowrap;">Target</th>
                                    <th class="sortable" data-sort="started_at" style="white-space:nowrap;">Started</th>
                                    <th class="sortable" data-sort="finished_at" style="white-space:nowrap;">Finished</th>
                                    <th class="sortable" data-sort="status" style="text-align:center;white-space:nowrap;">Status</th>
                                    <th class="sortable" data-sort="total_elements" style="text-align:center;white-space:nowrap;">Elements</th>
                                    <th style="text-align:center;white-space:nowrap;">Correlations</th>
                                    <th style="text-align:center;white-space:nowrap;">Action</th>
                                </tr>
                            </thead>
                            <tbody id="scanTableBody">
                                <!-- Populated by JS -->
                            </tbody>
                        </table>
                    </div>

                    <!-- Pagination -->
                    <div class="scan-pager mt-3" id="scanPager">
                        <div class="flex items-center gap-2">
                            <button class="page-btn" id="pagerFirst" title="First page">&laquo;</button>
                            <button class="page-btn" id="pagerPrev" title="Previous">&lsaquo;</button>
                            <button class="page-btn" id="pagerNext" title="Next">&rsaquo;</button>
                            <button class="page-btn" id="pagerLast" title="Last page">&raquo;</button>
                            <select class="input input-sm" id="pagerSize" style="width:auto;">
                                <option value="10">10</option>
                                <option value="30">30</option>
                                <option value="100">All Rows</option>
                            </select>
                            <select class="input input-sm" id="pagerPage" style="width:auto;">
                                <option value="1">1</option>
                            </select>
                        </div>
                        <span class="label" id="pagerInfo">Scans 0 - 0 / 0 (0)</span>
                    </div>

                    <!-- Empty state -->
                    <div class="table-empty hidden" id="scanEmpty">
                        <div class="table-empty-icon">
                            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        </div>
                        <p>There is currently no history of previously run scans.</p>
                        <p class="label">Click <strong>New Scan</strong> to initiate a new scan.</p>
                    </div>
                </div>

            </div>
        </div>
    </div><!-- /main-wrapper -->

    <!-- Sidebar overlay for mobile -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <div class="api-toast hidden" id="pageToast"></div>

    <script src="assets/js/theme.js?v=<?php echo filemtime('assets/js/theme.js'); ?>"></script>
    <?php if ($previewMode): ?>
    <script src="assets/js/static-shell.js?v=<?php echo filemtime('assets/js/static-shell.js'); ?>"></script>
    <script src="assets/js/scans.static-data.js?v=<?php echo filemtime('assets/js/scans.static-data.js'); ?>"></script>
    <?php else: ?>
    <script src="assets/js/auth.js?v=<?php echo filemtime('assets/js/auth.js'); ?>"></script>
    <script src="assets/js/dashboard.js?v=<?php echo filemtime('assets/js/dashboard.js'); ?>"></script>
    <?php endif; ?>
    <script src="assets/js/query.js?v=<?php echo filemtime('assets/js/query.js'); ?>"></script>
</body>
</html>
