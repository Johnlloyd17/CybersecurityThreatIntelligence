<?php
// =============================================================================
//  CTI — APPLICATION CONFIGURATION
//  php/config.php
//
//  ⚠  This file is blocked from direct browser access by .htaccess.
//     Include it server-side: require_once __DIR__ . '/config.php';
// =============================================================================

// ── Environment ───────────────────────────────────────────────────────────────
// Auto-detected below based on hostname. No need to change manually.
// Controls error display, HSTS enforcement, and cookie Secure flag.

// ── Application Metadata ──────────────────────────────────────────────────────
define('APP_NAME',    'CTI Platform');
define('APP_VERSION', '1.0.0');

// ── Environment auto-detection ────────────────────────────────────────────────
// Treat any request from localhost / 127.0.0.1 as local development.
$_cti_host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
$_cti_is_local = in_array(strtolower(explode(':', $_cti_host)[0]), ['localhost', '127.0.0.1', '::1'], true);

define('APP_ENV', $_cti_is_local ? 'development' : 'production');

if (!function_exists('cti_required_env')) {
    function cti_required_env(string $key): string {
        $value = getenv($key);
        if ($value === false || trim($value) === '') {
            throw new RuntimeException("Missing required production environment variable: {$key}");
        }
        return $value;
    }
}

if (APP_ENV === 'production') {
    // Production values must come from the host environment, not committed defaults.
    // Set DB_NAME, DB_USER, and DB_PASS in Hostinger/server environment variables.
    // ── Production (Hostinger) ────────────────────────────────────────────────
    define('APP_URL', 'https://' . $_cti_host);   // no trailing slash

    define('DB_HOST',    getenv('DB_HOST') ?: 'localhost');
    define('DB_PORT',    getenv('DB_PORT') ?: '3306');
    define('DB_NAME',    cti_required_env('DB_NAME'));
    define('DB_USER',    cti_required_env('DB_USER'));
    define('DB_PASS',    cti_required_env('DB_PASS'));
} else {
    // ── Local development (XAMPP) ─────────────────────────────────────────────
    define('APP_URL', 'http://localhost/CybersecurityThreatIntelligence');   // no trailing slash

    define('DB_HOST',    getenv('DB_HOST') ?: 'localhost');
    define('DB_PORT',    getenv('DB_PORT') ?: '4306');
    define('DB_NAME',    getenv('DB_NAME') ?: 'cti_platform');
    define('DB_USER',    getenv('DB_USER') ?: 'root');
    define('DB_PASS',    getenv('DB_PASS') ?: '');
}

// ── Database Credentials ──────────────────────────────────────────────────────
define('DB_CHARSET', 'utf8mb4');    // Full Unicode (emoji-safe)

// ── Session Configuration ─────────────────────────────────────────────────────
define('SESSION_LIFETIME',    1800);   // 30 minutes (seconds)
define('SESSION_COOKIE_NAME', 'cti_sess');

// ── Security: CSRF ────────────────────────────────────────────────────────────
define('CSRF_TOKEN_NAME',    '_csrf_token');
define('CSRF_TOKEN_LENGTH',  32);         // bytes (produces 64-char hex)

// ── Security: Passwords ───────────────────────────────────────────────────────
define('PASSWORD_ALGO',    PASSWORD_BCRYPT);
define('PASSWORD_COST',    12);           // bcrypt work factor (10–14 recommended)
define('PASSWORD_MIN_LEN', 8);

// ── Security: Rate Limiting ───────────────────────────────────────────────────
define('LOGIN_MAX_ATTEMPTS',  5);         // max failed logins before lockout
define('LOGIN_LOCKOUT_SECS',  900);       // 15-minute lockout window

// ── Allowed Origins (CORS) ────────────────────────────────────────────────────
// Add your frontend domains here when you expose a REST API.
define('CORS_ALLOWED_ORIGINS', [
    'http://localhost',
    'http://localhost/CybersecurityThreatIntelligence',
    'https://' . $_cti_host,
    'http://'  . $_cti_host,
]);

// ── Content-Security-Policy Nonce ────────────────────────────────────────────
// SecurityHeaders::init() generates a per-request nonce so that trusted
// inline <script> blocks can be whitelisted without 'unsafe-inline'.
// Usage in a PHP template:
//   <script nonce="{ SecurityHeaders::nonce() }"> ... </script>
// (use <?= and close with the PHP closing tag in actual code)
// SecurityHeaders::init() must be called BEFORE any output.

// ── Error Reporting ───────────────────────────────────────────────────────────
// NEVER display errors to the browser - they corrupt JSON API responses and
// expose internal details. Always log instead. This applies in all environments.
ini_set('display_errors',         '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors',             '1');
error_reporting(E_ALL);
// To debug PHP locally, check XAMPP's Apache error log:
//   c:\xampp\apache\logs\error.log

// ── Session Bootstrap ─────────────────────────────────────────────────────────
// Called automatically by SecurityHeaders::init() — do not call session_start()
// elsewhere unless you know the session is not already active.
function cti_session_configure(): void {
    $secure   = (APP_ENV === 'production');   // Secure flag only on HTTPS
    $lifetime = SESSION_LIFETIME;

    session_name(SESSION_COOKIE_NAME);

    session_set_cookie_params([
        'lifetime' => $lifetime,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $secure,
        'httponly' => true,        // JS cannot read the cookie
        'samesite' => 'Strict',    // Cookie not sent cross-site (CSRF protection)
    ]);

    ini_set('session.gc_maxlifetime', (string) $lifetime);
    ini_set('session.use_strict_mode',   '1');
    ini_set('session.use_only_cookies',  '1');
    ini_set('session.use_trans_sid',     '0');
}
