<!DOCTYPE html>
<?php
require_once __DIR__ . '/php/SpiderFootModuleMapper.php';
require_once __DIR__ . '/php/OsintEngine.php';
require_once __DIR__ . '/php/CtiPythonServiceRunner.php';
$ctiSpiderFootOrder = SpiderFootModuleMapper::getOrderedCtiSlugs();
$ctiSpiderFootDisplaySlugs = SpiderFootModuleMapper::getDisplaySlugMap();
$ctiNativeModuleSlugs = OsintEngine::getHandlerSlugs();
$ctiPythonModuleSlugs = CtiPythonServiceRunner::getSupportedModuleSlugs();
$ctiPythonParityVerifiedModuleSlugs = CtiPythonServiceRunner::getParityVerifiedModuleSlugs();
$ctiPythonParityVerifiedModuleTypes = CtiPythonServiceRunner::getParityVerifiedModuleTypes();
$ctiPythonModuleKeyRequirements = CtiPythonServiceRunner::getModuleKeyRequirements();
$ctiPythonModuleSupportedTypes = CtiPythonServiceRunner::getModuleSupportedQueryTypes();
?>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Scan - CTI Platform</title>
    <link rel="stylesheet" href="assets/css/styles.css?v=<?php echo filemtime('assets/css/styles.css'); ?>">
    <link rel="stylesheet" href="assets/css/dashboard.css?v=<?php echo filemtime('assets/css/dashboard.css'); ?>">
    <script>document.documentElement.setAttribute('data-theme',localStorage.getItem('cti-theme')||'dark');</script>
    <script>
        window.CTI_SPIDERFOOT_MODULE_ORDER = <?php echo json_encode($ctiSpiderFootOrder, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_SPIDERFOOT_DISPLAY_SLUGS = <?php echo json_encode($ctiSpiderFootDisplaySlugs, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_NATIVE_MODULE_SLUGS = <?php echo json_encode($ctiNativeModuleSlugs, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_PYTHON_ENGINE_MODULE_SLUGS = <?php echo json_encode($ctiPythonModuleSlugs, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_PYTHON_PARITY_VERIFIED_MODULE_SLUGS = <?php echo json_encode($ctiPythonParityVerifiedModuleSlugs, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_PYTHON_PARITY_VERIFIED_MODULE_TYPES = <?php echo json_encode($ctiPythonParityVerifiedModuleTypes, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_PYTHON_MODULE_KEY_REQUIREMENTS = <?php echo json_encode($ctiPythonModuleKeyRequirements, JSON_UNESCAPED_SLASHES); ?>;
        window.CTI_PYTHON_MODULE_SUPPORTED_TYPES = <?php echo json_encode($ctiPythonModuleSupportedTypes, JSON_UNESCAPED_SLASHES); ?>;
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
            <a href="newscan.php" class="sidebar-link active">
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
                <h2 class="topbar-title">New Scan</h2>
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


        <div class="panel active" id="panelNewScan">
            <div class="scan-page-wrap">

                <div class="card-holo query-box">
                    <div class="corner-tl"></div>
                    <div class="corner-tr"></div>
                    <div class="corner-bl"></div>
                    <div class="corner-br"></div>

                    <div class="query-header">
                        <span class="label accent-text">// NEW SCAN</span>
                        <h3>Intelligence Scan</h3>
                    </div>

                    <div class="scan-form mt-4">
                        <div class="scan-form-row">
                            <div class="scan-field">
                                <label class="label mb-1 block" for="scanName">Scan Name</label>
                                <div class="input-group">
                                    <input type="text" id="scanName" class="input" placeholder="The name of this scan." autocomplete="off" spellcheck="false">
                                </div>
                            </div>
                            <div class="scan-field">
                                <label class="label mb-1 block" for="scanTarget">Scan Target</label>
                                <div class="input-group">
                                    <span class="prefix">$</span>
                                    <input type="text" id="scanTarget" class="input" placeholder="The target of your scan." autocomplete="off" spellcheck="false">
                                </div>
                            </div>
                        </div>

                        <div class="scan-target-info mt-3">
                            <div class="scan-info-icon">
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                            </div>
                            <div class="scan-info-text">
                                Your scan target may be one of the following. The platform will automatically detect the target type:
                                <div class="scan-type-examples">
                                    <div class="scan-type-col">
                                        <span><strong>Domain Name:</strong> e.g. <em>example.com</em></span>
                                        <span><strong>IPv4 Address:</strong> e.g. <em>1.2.3.4</em></span>
                                        <span><strong>IPv6 Address:</strong> e.g. <em>2606:4700:4700::1111</em></span>
                                        <span><strong>Hostname:</strong> e.g. <em>abc.example.com</em></span>
                                        <span><strong>Subnet:</strong> e.g. <em>1.2.3.0/24</em></span>
                                        <span><strong>Bitcoin Address:</strong> e.g. <em>1HesYJSP1Qqcy...</em></span>
                                    </div>
                                    <div class="scan-type-col">
                                        <span><strong>E-mail address:</strong> e.g. <em>bob@example.com</em></span>
                                        <span><strong>Phone Number:</strong> e.g. <em>+12345678901</em></span>
                                        <span><strong>Human Name:</strong> e.g. <em>"John Smith"</em> (in quotes)</span>
                                        <span><strong>Username:</strong> e.g. <em>"jsmith2000"</em> (in quotes)</span>
                                        <span><strong>Network ASN:</strong> e.g. <em>1234</em></span>
                                        <span><strong>File Hash:</strong> e.g. <em>e99a18c428cb38d5...</em></span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Tabbed Module Selection -->
                <div class="card mt-4" id="scanModuleCard">
                    <div class="scan-tabs">
                        <button class="scan-tab active" data-tab="usecase">By Use Case</button>
                        <button class="scan-tab" data-tab="datatype">By Required Data</button>
                        <button class="scan-tab" data-tab="module">By Module</button>
                        <button class="scan-tab" data-tab="implemented">Implemented</button>
                    </div>

                    <div class="scan-tab-content active" id="tabUsecase">
                        <div class="usecase-list">
                            <label class="usecase-option">
                                <input type="radio" name="usecase" value="all" checked>
                                <div class="usecase-body">
                                    <strong>All</strong>
                                    <span class="usecase-title">Get anything and everything about the target.</span>
                                    <p>All enabled modules will be activated but every possible piece of information about the target will be obtained and analysed.</p>
                                </div>
                            </label>
                            <label class="usecase-option">
                                <input type="radio" name="usecase" value="footprint">
                                <div class="usecase-body">
                                    <strong>Footprint</strong>
                                    <span class="usecase-title">Understand what information this target exposes to the Internet.</span>
                                    <p>Gain an understanding about the target's network perimeter, associated identities and other information obtained through web crawling and search engine use.</p>
                                </div>
                            </label>
                            <label class="usecase-option">
                                <input type="radio" name="usecase" value="investigate">
                                <div class="usecase-body">
                                    <strong>Investigate</strong>
                                    <span class="usecase-title">Best for when you suspect the target is malicious but need more information.</span>
                                    <p>Some basic footprinting will be performed in addition to querying of blacklists and other sources that may have information about your target's maliciousness.</p>
                                </div>
                            </label>
                            <label class="usecase-option">
                                <input type="radio" name="usecase" value="passive">
                                <div class="usecase-body">
                                    <strong>Passive</strong>
                                    <span class="usecase-title">When you don't want the target to even suspect they are being investigated.</span>
                                    <p>As much information will be gathered without touching the target or their affiliates, therefore only modules that do not touch the target will be enabled.</p>
                                </div>
                            </label>
                        </div>
                    </div>

                    <div class="scan-tab-content" id="tabDatatype">
                        <div class="scan-bulk-actions mb-3">
                            <button class="btn btn-sm btn-ghost" id="dtSelectAll">Select All</button>
                            <button class="btn btn-sm btn-ghost" id="dtDeselectAll">Deselect All</button>
                            <span class="label ml-2" id="dtCount">0 selected</span>
                        </div>
                        <div class="scan-datatype-grid" id="datatypeGrid"></div>
                    </div>

                    <div class="scan-tab-content" id="tabModule">
                        <div class="scan-bulk-actions mb-3">
                            <button class="btn btn-sm btn-ghost" id="modSelectAll">Select All</button>
                            <button class="btn btn-sm btn-ghost" id="modDeselectAll">Deselect All</button>
                            <div class="scan-filter-group" id="modKeyFilter" aria-label="Module credential filter">
                                <span class="label scan-filter-group-label">Credentials</span>
                                <button type="button" class="scan-filter-pill active" data-key-filter="all">All</button>
                                <button type="button" class="scan-filter-pill" data-key-filter="no-key">No API Key</button>
                                <button type="button" class="scan-filter-pill" data-key-filter="requires-key">API Key</button>
                            </div>
                            <input type="text" class="input input-sm" id="modSearch" placeholder="Filter modules..." style="width:220px;margin-left:auto;">
                            <span class="label ml-2" id="modCount">0 selected</span>
                        </div>
                        <div class="scan-module-grid" id="moduleGrid"></div>
                    </div>

                    <div class="scan-tab-content" id="tabImplemented">
                        <div class="scan-impl-note mb-3">
                            This view shows only modules already migrated to the CTI Python engine. They are grouped by whether the current Python implementation needs credentials, and modules marked as parity verified are the ones CTI currently trusts to route through the Python engine by default.
                        </div>
                        <div class="scan-bulk-actions mb-3">
                            <button class="btn btn-sm btn-ghost" id="implSelectAll">Select All</button>
                            <button class="btn btn-sm btn-ghost" id="implDeselectAll">Deselect All</button>
                            <div class="scan-filter-group" id="implKeyFilter" aria-label="Implemented module credential filter">
                                <span class="label scan-filter-group-label">Credentials</span>
                                <button type="button" class="scan-filter-pill active" data-key-filter="all">All</button>
                                <button type="button" class="scan-filter-pill" data-key-filter="no-key">No API Key</button>
                                <button type="button" class="scan-filter-pill" data-key-filter="requires-key">API Key</button>
                            </div>
                            <input type="text" class="input input-sm" id="implSearch" placeholder="Filter implemented modules..." style="width:240px;margin-left:auto;">
                            <span class="label ml-2" id="implCount">0 selected</span>
                        </div>
                        <div class="scan-module-grid" id="implementedGrid"></div>
                    </div>
                </div>

                <div class="mt-4 flex gap-3">
                    <button class="btn btn-glitch btn-lg" id="runScan">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        Run Scan Now
                    </button>
                </div>

            </div>
        </div>
    </div><!-- /main-wrapper -->

    <!-- Sidebar overlay for mobile -->
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <div class="api-toast hidden" id="pageToast"></div>

    <script src="assets/js/theme.js?v=<?php echo filemtime('assets/js/theme.js'); ?>"></script>
    <script src="assets/js/cti-refresh.js?v=<?php echo filemtime('assets/js/cti-refresh.js'); ?>"></script>
    <script src="assets/js/static-shell.js?v=<?php echo filemtime('assets/js/static-shell.js'); ?>"></script>
    <script src="assets/js/settings.static-data.js?v=<?php echo filemtime('assets/js/settings.static-data.js'); ?>"></script>
    <script src="assets/js/newscan.js?v=<?php echo filemtime('assets/js/newscan.js'); ?>"></script>
</body>
</html>
