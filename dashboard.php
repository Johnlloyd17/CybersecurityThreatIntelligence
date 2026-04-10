<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard â€” CTI Platform</title>
    <link rel="stylesheet" href="assets/css/styles.css?v=<?php echo filemtime('assets/css/styles.css'); ?>">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?php echo filemtime('assets/css/dashboard.css'); ?>">
    <!-- Apply saved theme before CSS renders to prevent flash -->
    <script>document.documentElement.setAttribute('data-theme',localStorage.getItem('cti-theme')||'dark');</script>
</head>
<body>

    <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
         SIDEBAR NAVIGATION
         â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
    <aside class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <a href="index.php" class="nav-logo">
                <span class="accent-text">&lt;</span>CTI<span class="accent-text">/&gt;</span>
            </a>
            <button class="sidebar-close" id="sidebarClose" aria-label="Close sidebar">&#10005;</button>
        </div>

        <nav class="sidebar-nav">
            <a href="dashboard.php" class="sidebar-link active">
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
                    <span class="user-role label" id="userRole">â€”</span>
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
        <!-- Top bar -->
        <header class="topbar">
            <div class="topbar-left">
                <button class="sidebar-toggle" id="sidebarToggle" aria-label="Toggle sidebar">
                    <span></span><span></span><span></span>
                </button>
                <h2 class="topbar-title" id="panelTitle">Dashboard Overview</h2>
            </div>
            <div class="topbar-right">
                <span class="label" id="currentTime"></span>
                <button class="theme-toggle" id="themeToggle" data-theme-toggle aria-label="Toggle theme">
                    <svg class="theme-icon-sun" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                    <svg class="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
                </button>
                <span class="badge badge-low">&#9679; <span class="badge-label">Connected</span></span>
            </div>
        </header>

        <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
             PANEL: OVERVIEW (Dashboard)
             â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
        <div class="panel active" id="panelOverview">
            <!-- Stats Row -->
            <div class="dash-stats grid grid-4">
                <div class="card stat-card">
                    <span class="stat-label">Total Queries</span>
                    <span class="stat-value" id="statTotalQueries">â€”</span>
                    <span class="label accent-text mt-1" id="statQueriesLabel">Loading...</span>
                </div>
                <div class="card stat-card">
                    <span class="stat-label">Threats Found</span>
                    <span class="stat-value" id="statThreatsFound" style="color: var(--destructive)">â€”</span>
                    <span class="label destructive-text mt-1" id="statDetectionRate">Loading...</span>
                </div>
                <div class="card stat-card">
                    <span class="stat-label">APIs Active</span>
                    <span class="stat-value neon-text-tertiary" id="statApisActive">â€”</span>
                    <span class="label tertiary-text mt-1" id="statApisLabel">Loading...</span>
                </div>
                <div class="card stat-card">
                    <span class="stat-label">Avg Response</span>
                    <span class="stat-value neon-text-secondary" id="statAvgResponse">â€”</span>
                    <span class="label secondary-text mt-1" id="statAvgResponseLabel">Loading...</span>
                </div>
            </div>

            <!-- Charts Row -->
            <div class="grid grid-2 mt-6">
                <!-- Severity Distribution -->
                <div class="card">
                    <div class="card-header">
                        <h3>Threat Severity Distribution</h3>
                        <span class="label">Last 30 days</span>
                    </div>
                    <div class="severity-bars">
                        <div class="sev-row">
                            <span class="badge badge-critical">Critical</span>
                            <div class="sev-track"><div class="sev-fill sev-critical" id="sevFillCritical" style="width: 0%"></div></div>
                            <span class="label" id="sevCountCritical">â€”</span>
                        </div>
                        <div class="sev-row">
                            <span class="badge badge-high">High</span>
                            <div class="sev-track"><div class="sev-fill sev-high" id="sevFillHigh" style="width: 0%"></div></div>
                            <span class="label" id="sevCountHigh">â€”</span>
                        </div>
                        <div class="sev-row">
                            <span class="badge badge-medium">Medium</span>
                            <div class="sev-track"><div class="sev-fill sev-medium" id="sevFillMedium" style="width: 0%"></div></div>
                            <span class="label" id="sevCountMedium">â€”</span>
                        </div>
                        <div class="sev-row">
                            <span class="badge badge-low">Low</span>
                            <div class="sev-track"><div class="sev-fill sev-low" id="sevFillLow" style="width: 0%"></div></div>
                            <span class="label" id="sevCountLow">â€”</span>
                        </div>
                        <div class="sev-row">
                            <span class="badge badge-info">Info</span>
                            <div class="sev-track"><div class="sev-fill sev-info" id="sevFillInfo" style="width: 0%"></div></div>
                            <span class="label" id="sevCountInfo">â€”</span>
                        </div>
                    </div>
                </div>

                <!-- Query Types -->
                <div class="card">
                    <div class="card-header">
                        <h3>Queries by Type</h3>
                        <span class="label">Last 30 days</span>
                    </div>
                    <div class="query-type-grid">
                        <div class="qt-item">
                            <span class="qt-value accent-text" id="qtValueIp">0</span>
                            <span class="qt-label">IP Address</span>
                            <div class="qt-bar"><div class="qt-fill" id="qtFillIp" style="width:0%; background: var(--accent)"></div></div>
                        </div>
                        <div class="qt-item">
                            <span class="qt-value secondary-text" id="qtValueDomain">0</span>
                            <span class="qt-label">Domain</span>
                            <div class="qt-bar"><div class="qt-fill" id="qtFillDomain" style="width:0%; background: var(--accent-secondary)"></div></div>
                        </div>
                        <div class="qt-item">
                            <span class="qt-value tertiary-text" id="qtValueUrl">0</span>
                            <span class="qt-label">URL</span>
                            <div class="qt-bar"><div class="qt-fill" id="qtFillUrl" style="width:0%; background: var(--accent-tertiary)"></div></div>
                        </div>
                        <div class="qt-item">
                            <span class="qt-value" id="qtValueHash" style="color:#fbbf24">0</span>
                            <span class="qt-label">Hash</span>
                            <div class="qt-bar"><div class="qt-fill" id="qtFillHash" style="width:0%; background: #fbbf24"></div></div>
                        </div>
                        <div class="qt-item">
                            <span class="qt-value" id="qtValueCve" style="color:#ff6b35">0</span>
                            <span class="qt-label">CVE</span>
                            <div class="qt-bar"><div class="qt-fill" id="qtFillCve" style="width:0%; background: #ff6b35"></div></div>
                        </div>
                        <div class="qt-item">
                            <span class="qt-value" id="qtValueEmail" style="color:#a78bfa">0</span>
                            <span class="qt-label">Email</span>
                            <div class="qt-bar"><div class="qt-fill" id="qtFillEmail" style="width:0%; background: #a78bfa"></div></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Recent Activity Table -->
            <div class="card mt-6">
                <div class="card-header">
                    <h3>Recent Query Activity</h3>
                    <a href="query.php" class="btn btn-sm btn-ghost">View All</a>
                </div>
                <div class="table-wrap" style="clip-path:none; border:none;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Type</th>
                                <th>Query</th>
                                <th>Source</th>
                                <th>Severity</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="recentActivityBody">
                            <tr><td colspan="6" class="label" style="text-align:center;padding:1.5rem;">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- API Status Row -->
            <div class="card mt-6">
                <div class="card-header">
                    <h3>API Connection Status</h3>
                    <span class="label accent-text" id="apiStatusHeading">Loading...</span>
                </div>

                <!-- Toolbar: search + status pills -->
                <div class="api-status-toolbar">
                    <div class="input-group api-status-search">
                        <span class="prefix">
                            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        </span>
                        <input type="text" id="apiStatusSearch" class="input" placeholder="Search APIs..." autocomplete="off" aria-label="Search APIs">
                    </div>
                    <div class="status-filter-row" id="apiStatusPills" style="flex-wrap:nowrap;">
                        <button class="status-pill active" data-api-filter="all">
                            <span class="status-pill-dot all"></span> All
                            <span class="status-pill-count" id="apiPillCountAll">â€”</span>
                        </button>
                        <button class="status-pill" data-api-filter="configured">
                            <span class="status-pill-dot configured"></span> Configured
                            <span class="status-pill-count" id="apiPillCountConfigured">â€”</span>
                        </button>
                        <button class="status-pill" data-api-filter="missing">
                            <span class="status-pill-dot missing"></span> No Key
                            <span class="status-pill-count" id="apiPillCountMissing">â€”</span>
                        </button>
                    </div>
                </div>

                <div class="api-status-grid grid grid-3" id="apiStatusGrid">
                    <div class="api-status-item"><span class="badge badge-info">&#9651;</span><span>Loading...</span><span class="label">â€”</span></div>
                </div>

                <!-- Pagination -->
                <div class="pagination api-status-pager" id="apiStatusPager"></div>
            </div>
        </div>


    </div><!-- /main-wrapper -->

    <!-- Sidebar overlay for mobile -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>

    <script src="assets/js/theme.js?v=<?php echo filemtime('assets/js/theme.js'); ?>"></script>
    <script src="assets/js/auth.js?v=<?php echo filemtime('assets/js/auth.js'); ?>"></script>
    <script src="assets/js/dashboard.js?v=<?php echo filemtime('assets/js/dashboard.js'); ?>"></script>
    <script src="assets/js/dashboard-stats.js?v=<?php echo filemtime('assets/js/dashboard-stats.js'); ?>"></script>
</body>
</html>
