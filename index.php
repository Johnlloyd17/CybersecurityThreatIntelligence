<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTI Platform &mdash; Cybersecurity Threat Intelligence</title>
    <link rel="stylesheet" href="assets/css/styles.css?v=<?php echo filemtime('assets/css/styles.css'); ?>">
    <link rel="stylesheet" href="assets/css/landing.css?v=<?php echo filemtime('assets/css/landing.css'); ?>">
    <!-- Apply saved theme before CSS renders to prevent flash -->
    <script>
        document.documentElement.setAttribute('data-theme', localStorage.getItem('cti-theme') || 'dark');
    </script>
</head>

<body class="landing-page circuit-bg">

    <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
         NAVIGATION
         â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
    <nav class="nav" id="nav">
        <div class="nav-inner">
            <a href="#hero" class="nav-logo" aria-label="CTI Platform Home">
                <span class="accent-text">&lt;</span>CTI<span class="accent-text">/&gt;</span>
            </a>

            <button class="theme-toggle" id="themeToggle" data-theme-toggle aria-label="Toggle theme">
                <!-- Sun: shown in dark mode â€” click to switch to light -->
                <svg class="theme-icon-sun" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="5" />
                    <line x1="12" y1="1" x2="12" y2="3" />
                    <line x1="12" y1="21" x2="12" y2="23" />
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                    <line x1="1" y1="12" x2="3" y2="12" />
                    <line x1="21" y1="12" x2="23" y2="12" />
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                </svg>
                <!-- Moon: shown in light mode â€” click to switch to dark -->
                <svg class="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                </svg>
            </button>
        </div>
    </nav>

    <main>
        <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
             HERO SECTION
             â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
        <section class="hero section" id="hero">
            <div class="container">
                <div class="hero-grid">
                    <div class="hero-content">
                        <div class="hero-tag">
                            <span class="badge badge-low">&#9679; System Online</span>
                            <span class="label">// OSINT AUTOMATION PLATFORM v1.0</span>
                        </div>

                        <h1 class="hero-title">
                            <span class="hero-title-line hero-title-line-primary cyber-glitch neon-text" data-text="Cyber">Cyber</span>
                            <span class="hero-title-line hero-title-line-primary cyber-glitch neon-text" data-text="Threat">Threat</span>
                            <span class="hero-title-line neon-text-secondary">Intelligence</span>
                        </h1>

                        <p class="hero-sub">
                            Monitor indicators, investigate suspicious infrastructure, and centralize threat intelligence workflows in one streamlined platform for analysts and security teams.
                        </p>

                        <div class="hero-terminal">
                            <span class="label">$ cti-scan --target</span>
                            <span class="hero-typewriter accent-text blink-cursor" id="typewriter"></span>
                        </div>
                    </div>

                    <div class="hero-hud" id="hero-login-panel">
                        <div class="card-holo hero-login-card">
                            <div class="corner-tl"></div>
                            <div class="corner-tr"></div>
                            <div class="corner-bl"></div>
                            <div class="corner-br"></div>
                            <div class="hud-header">
                                <span class="label">// LOGIN PANEL - <b>Authenticate</b></span>
                            </div>

                            <div class="alert alert-error hidden" id="heroLoginError">
                                <span>&#9888;</span>
                                <span id="heroLoginErrorMsg">Invalid credentials.</span>
                            </div>

                            <form id="heroLoginForm" class="hero-login-form" autocomplete="off" novalidate>
                                <div class="input-group mb-4">
                                    <span class="prefix">&gt;</span>
                                    <input
                                        type="email"
                                        id="heroLoginEmail"
                                        class="input"
                                        placeholder="Enter email address"
                                        required
                                        autocomplete="email"
                                        aria-label="Hero login email address">
                                </div>

                                <div class="input-group has-action mb-4">
                                    <span class="prefix">&gt;</span>
                                    <input
                                        type="password"
                                        id="heroLoginPassword"
                                        class="input"
                                        placeholder="Enter password"
                                        required
                                        autocomplete="current-password"
                                        aria-label="Hero login password">
                                    <button
                                        type="button"
                                        class="input-action"
                                        id="toggleHeroLoginPassword"
                                        aria-label="Show password"
                                        aria-controls="heroLoginPassword"
                                        aria-pressed="false">
                                        <svg class="password-icon-show" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                            <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" />
                                            <circle cx="12" cy="12" r="3" />
                                        </svg>
                                        <svg class="password-icon-hide hidden" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                            <path d="M10.6 5.6A10.9 10.9 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-2 2.8" />
                                            <path d="M6.2 6.2C3.5 8.2 2 12 2 12s3.5 7 10 7a10 10 0 0 0 5.6-1.6" />
                                            <path d="m2 2 20 20" />
                                        </svg>
                                    </button>
                                </div>

                                <button type="submit" class="btn btn-glitch w-full btn-lg" id="heroLoginBtn">
                                    <span class="spinner hidden" id="heroLoginSpinner"></span>
                                    <span id="heroLoginBtnText">Login</span>
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </section>


    </main>

    <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
         FOOTER
         â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
    <!-- Back to Top Button -->
    <button class="back-to-top" id="backToTop" aria-label="Back to top">
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="18 15 12 9 6 15" />
        </svg>
    </button>

    <footer class="footer">
        <div class="container">
            <div class="footer-simple">
                <span class="nav-logo">
                    <span class="accent-text">&lt;</span>CTI<span class="accent-text">/&gt;</span>
                </span>
                <span class="label">&copy; 2026 CTI Platform. All rights reserved.</span>
            </div>
        </div>
    </footer>

    <script src="assets/js/theme.js?v=<?php echo filemtime('assets/js/theme.js'); ?>"></script>
    <script src="assets/js/auth.js?v=<?php echo filemtime('assets/js/auth.js'); ?>"></script>
    <script src="assets/js/landing.js?v=<?php echo filemtime('assets/js/landing.js'); ?>"></script>
</body>

</html>
