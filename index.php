<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CTI Platform â€” Cybersecurity Threat Intelligence</title>
    <link rel="stylesheet" href="assets/css/styles.css?v=<?php echo filemtime('assets/css/styles.css'); ?>">
    <link rel="stylesheet" href="assets/css/landing.css?v=<?php echo filemtime('assets/css/landing.css'); ?>">
    <!-- Apply saved theme before CSS renders to prevent flash -->
    <script>document.documentElement.setAttribute('data-theme',localStorage.getItem('cti-theme')||'dark');</script>
</head>
<body class="circuit-bg">

    <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
         NAVIGATION
         â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
    <nav class="nav" id="nav">
        <div class="nav-inner">
            <a href="#hero" class="nav-logo" aria-label="CTI Platform Home">
                <span class="accent-text">&lt;</span>CTI<span class="accent-text">/&gt;</span>
            </a>

            <ul class="nav-links" id="navLinks">
                <li><a href="#how-it-works">How It Works</a></li>
                <li><a href="#login" class="btn btn-sm">Access Terminal</a></li>
            </ul>

            <button class="theme-toggle" id="themeToggle" data-theme-toggle aria-label="Toggle theme">
                <!-- Sun: shown in dark mode â€” click to switch to light -->
                <svg class="theme-icon-sun" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                <!-- Moon: shown in light mode â€” click to switch to dark -->
                <svg class="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
            </button>
            <button class="nav-toggle" id="navToggle" aria-label="Toggle navigation">
                <span></span><span></span><span></span>
            </button>
        </div>

        <!-- Mobile menu -->
        <div class="mobile-menu hidden" id="mobileMenu">
            <a href="#how-it-works">How It Works</a>
            <a href="#login" class="btn btn-sm w-full">Access Terminal</a>
            <div class="mobile-menu-theme">
                <span class="label">// DISPLAY_MODE</span>
                <button class="theme-toggle" id="themeToggleMobile" data-theme-toggle aria-label="Toggle theme">
                    <svg class="theme-icon-sun" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
                    <svg class="theme-icon-moon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
                </button>
            </div>
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

                        <h1>
                            <span class="cyber-glitch neon-text" data-text="Cyber Threat">Cyber Threat</span>
                            <span class="neon-text-secondary">Intelligence</span>
                        </h1>

                        <p class="hero-sub">
                            Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
                        </p>

                        <div class="hero-actions">
                            <a href="#login" class="btn btn-glitch btn-lg">Start Scanning</a>
                            <a href="#features" class="btn btn-lg">Learn More</a>
                        </div>

                        <div class="hero-terminal">
                            <span class="label">$ cti-scan --target</span>
                            <span class="hero-typewriter accent-text blink-cursor" id="typewriter"></span>
                        </div>
                    </div>

                    <div class="hero-hud">
                        <div class="card-holo">
                            <div class="corner-tl"></div>
                            <div class="corner-tr"></div>
                            <div class="corner-bl"></div>
                            <div class="corner-br"></div>
                            <div class="hud-header">
                                <span class="label">// HUD â€” LIVE FEED</span>
                                <span class="badge badge-critical">&#9679; LIVE</span>
                            </div>
                            <div class="hud-stats">
                                <div class="hud-stat">
                                    <span class="stat-value">200+</span>
                                    <span class="stat-label">OSINT Modules</span>
                                </div>
                                <div class="hud-stat">
                                    <span class="stat-value neon-text-secondary" style="font-size:2rem">11</span>
                                    <span class="stat-label">Data Categories</span>
                                </div>
                            </div>
                            <div class="hud-bar">
                                <span class="label">Threat Level</span>
                                <div class="progress-track">
                                    <div class="progress-fill" style="width: 73%"></div>
                                </div>
                                <span class="label destructive-text">73% â€” HIGH</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>


        <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
             HOW IT WORKS
             â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
        <section class="section" id="how-it-works">
            <div class="container">
                <div class="section-header text-center">
                    <span class="label accent-text">&gt; Process.flow</span>
                    <h2>How It Works</h2>
                    <p class="section-desc">Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                </div>

                <div class="steps">
                    <div class="step">
                        <div class="step-number accent-text">01</div>
                        <div class="step-content">
                            <h3>Define Your Target</h3>
                            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                        </div>
                    </div>

                    <div class="step-connector"></div>

                    <div class="step">
                        <div class="step-number secondary-text">02</div>
                        <div class="step-content">
                            <h3>Launch the Scan</h3>
                            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                        </div>
                    </div>

                    <div class="step-connector"></div>

                    <div class="step">
                        <div class="step-number tertiary-text">03</div>
                        <div class="step-content">
                            <h3>Correlate & Enrich</h3>
                            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                        </div>
                    </div>

                    <div class="step-connector"></div>

                    <div class="step">
                        <div class="step-number accent-text">04</div>
                        <div class="step-content">
                            <h3>Review & Export</h3>
                            <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>


        <!-- â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
             LOGIN SECTION
             â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• -->
        <section class="section" id="login">
            <div class="container">
                <div class="login-wrapper">
                    <div class="login-info">
                        <span class="label accent-text">&gt; Auth.initialize</span>
                        <h2>Access The Terminal</h2>
                        <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                        <div class="login-features">
                            <div class="login-feature">
                                <span class="accent-text">&#10003;</span>
                                <span>Scan domains, IPs, emails, names, subnets, hostnames</span>
                            </div>
                            <div class="login-feature">
                                <span class="accent-text">&#10003;</span>
                                <span>200+ OSINT modules with independent configuration</span>
                            </div>
                            <div class="login-feature">
                                <span class="accent-text">&#10003;</span>
                                <span>Interactive scan results with data correlation</span>
                            </div>
                            <div class="login-feature">
                                <span class="accent-text">&#10003;</span>
                                <span>Scan history, module settings, and API management</span>
                            </div>
                        </div>
                    </div>

                    <div class="login-card card-holo">
                        <div class="corner-tl"></div>
                        <div class="corner-tr"></div>
                        <div class="corner-bl"></div>
                        <div class="corner-br"></div>

                        <div class="login-card-header">
                            <span class="label accent-text">// SECURE LOGIN</span>
                            <h3>Authenticate</h3>
                        </div>

                        <!-- Login Alert -->
                        <div class="alert alert-error hidden" id="loginError">
                            <span>&#9888;</span>
                            <span id="loginErrorMsg">Invalid credentials.</span>
                        </div>

                        <form id="loginForm" autocomplete="off" novalidate>
                            <div class="input-group mb-4">
                                <span class="prefix">&gt;</span>
                                <input
                                    type="email"
                                    id="loginEmail"
                                    class="input"
                                    placeholder="Enter email address"
                                    required
                                    autocomplete="email"
                                    aria-label="Email address"
                                >
                            </div>

                            <div class="input-group has-action mb-4">
                                <span class="prefix">&gt;</span>
                                <input
                                    type="password"
                                    id="loginPassword"
                                    class="input"
                                    placeholder="Enter password"
                                    required
                                    autocomplete="current-password"
                                    aria-label="Password"
                                >
                                <button
                                    type="button"
                                    class="input-action"
                                    id="toggleLoginPassword"
                                    aria-label="Show password"
                                    aria-controls="loginPassword"
                                    aria-pressed="false"
                                >
                                    <svg class="password-icon-show" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/>
                                        <circle cx="12" cy="12" r="3"/>
                                    </svg>
                                    <svg class="password-icon-hide hidden" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                        <path d="M10.6 5.6A10.9 10.9 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-2 2.8"/>
                                        <path d="M6.2 6.2C3.5 8.2 2 12 2 12s3.5 7 10 7a10 10 0 0 0 5.6-1.6"/>
                                        <path d="m2 2 20 20"/>
                                    </svg>
                                </button>
                            </div>

                            <button type="submit" class="btn btn-glitch w-full btn-lg" id="loginBtn">
                                <span class="spinner hidden" id="loginSpinner"></span>
                                <span id="loginBtnText">Login</span>
                            </button>
                        </form>

                        <!-- <div class="login-footer">
                            <span class="label">Default credentials:</span>
                            <code class="login-cred">admin@cti.local / Admin@1234</code>
                            <code class="login-cred">analyst@cti.local / Admin@1234</code>
                        </div> -->
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
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="18 15 12 9 6 15"/></svg>
    </button>

    <footer class="footer">
        <div class="container">
            <div class="footer-grid">
                <div class="footer-brand">
                    <span class="nav-logo">
                        <span class="accent-text">&lt;</span>CTI<span class="accent-text">/&gt;</span>
                    </span>
                    <p class="mt-2">Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
                </div>
                <div class="footer-col">
                    <h4 class="footer-heading">Navigate</h4>
                    <a href="#hero">Home</a>
                    <a href="#how-it-works">How It Works</a>
                </div>
                <div class="footer-col">
                    <h4 class="footer-heading">Quick Links</h4>
                    <a href="#login">Access Terminal</a>
                </div>
            </div>
            <hr class="divider">
            <div class="footer-bottom">
                <span class="label">&copy; 2026 CTI Platform. All rights reserved.</span>
                <span class="label accent-text">// SYSTEM OPERATIONAL</span>
            </div>
        </div>
    </footer>

    <script src="assets/js/theme.js?v=<?php echo filemtime('assets/js/theme.js'); ?>"></script>
    <script src="assets/js/auth.js?v=<?php echo filemtime('assets/js/auth.js'); ?>"></script>
    <script src="assets/js/landing.js?v=<?php echo filemtime('assets/js/landing.js'); ?>"></script>
</body>
</html>
