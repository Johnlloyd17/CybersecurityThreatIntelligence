<?php
// =============================================================================
//  CTI — HTTP SECURE HEADERS (PHP Runtime Layer)
//  php/security-headers.php
//
//  This file mirrors the .htaccess headers in PHP so that:
//    • any page can send a UNIQUE per-request CSP nonce for inline scripts
//    • CORS logic can be conditioned on request data (method, origin, route)
//    • headers can be tightened or relaxed without touching Apache config
//
//  Usage (at the very top of every PHP page, before any output):
//
//    require_once __DIR__ . '/php/config.php';
//    require_once __DIR__ . '/php/security-headers.php';
//    SecurityHeaders::init();   // starts session + sends all headers
//
//  Then in your HTML template:
//    <script nonce="{ SecurityHeaders::nonce() }">
//        (use <?= and close with the PHP closing tag in actual code)
//    </script>
//
//  ⚠  This file is blocked from direct browser access by php/.htaccess.
// =============================================================================

class SecurityHeaders
{
    /** @var string|null  The per-request CSP nonce (base64-encoded random bytes) */
    private static ?string $nonce = null;

    /** @var bool  Tracks whether init() has already run for this request */
    private static bool $initialized = false;

    // =========================================================================
    //  PUBLIC API
    // =========================================================================

    /**
     * Call ONCE at the top of every PHP page, before any output.
     *
     * What it does:
     *  1. Configures and starts the PHP session securely
     *  2. Generates a fresh CSP nonce for this request
     *  3. Removes server-fingerprinting headers
     *  4. Sends all HTTP security headers
     *  5. Optionally handles a CORS preflight and exits
     *
     * @param  array<string, mixed>  $options  Override individual header values
     */
    public static function init(array $options = []): void
    {
        if (self::$initialized) {
            return;
        }
        self::$initialized = true;

        // 1. Secure session
        self::startSession();

        // 2. Generate nonce
        self::$nonce = self::generateNonce();

        // 3. Remove server fingerprints before anything else
        self::removeFingerprints();

        // 4. Handle CORS preflight (OPTIONS) — must run before other headers
        self::handleCors($options['cors_origin'] ?? null);

        // 5. Send security headers
        self::sendHeaders($options);
    }

    /**
     * Returns the nonce string for use in <script nonce="..."> tags.
     * init() must have been called first.
     */
    public static function nonce(): string
    {
        if (self::$nonce === null) {
            // Fallback: generate now (edge-case if someone calls nonce() before init())
            self::$nonce = self::generateNonce();
        }
        return self::$nonce;
    }

    /**
     * Generate and return a CSRF token, storing it in the session.
     * Compare submitted tokens with validateCsrf().
     */
    public static function csrfToken(): string
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            self::startSession();
        }

        if (empty($_SESSION[CSRF_TOKEN_NAME])) {
            $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(CSRF_TOKEN_LENGTH));
        }

        return $_SESSION[CSRF_TOKEN_NAME];
    }

    /**
     * Validate a CSRF token submitted with a form/AJAX request.
     *
     * @param  string  $submitted  The token value from the form field / header
     * @throws RuntimeException   on mismatch (or handle the bool return yourself)
     */
    public static function validateCsrf(string $submitted): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            self::startSession();
        }

        $stored = $_SESSION[CSRF_TOKEN_NAME] ?? '';

        // hash_equals() prevents timing attacks
        $valid = hash_equals($stored, $submitted);

        // Rotate the token after each use (synchronizer-token pattern)
        unset($_SESSION[CSRF_TOKEN_NAME]);

        return $valid;
    }

    // =========================================================================
    //  PRIVATE HELPERS
    // =========================================================================

    /** Generates a cryptographically random nonce (base64) */
    private static function generateNonce(): string
    {
        return base64_encode(random_bytes(16));   // 128-bit nonce, 24-char base64
    }

    /** Configure and start the PHP session */
    private static function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;   // Already started (e.g. by legacy code)
        }

        // Apply config from config.php if available, otherwise inline defaults
        if (function_exists('cti_session_configure')) {
            cti_session_configure();
        } else {
            $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
            session_set_cookie_params([
                'lifetime' => 1800,
                'path'     => '/',
                'secure'   => $secure,
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
            ini_set('session.use_strict_mode',  '1');
            ini_set('session.use_only_cookies', '1');
        }

        session_start();

        // Regenerate ID on first request (prevents session-fixation)
        if (empty($_SESSION['__id_regenerated'])) {
            session_regenerate_id(true);
            $_SESSION['__id_regenerated'] = true;
        }

        // Enforce session timeout
        $lifetime = defined('SESSION_LIFETIME') ? SESSION_LIFETIME : 1800;
        if (isset($_SESSION['__last_active'])) {
            if ((time() - $_SESSION['__last_active']) > $lifetime) {
                session_unset();
                session_destroy();
                session_start();
                session_regenerate_id(true);
            }
        }
        $_SESSION['__last_active'] = time();
    }

    /** Remove headers that expose server technology */
    private static function removeFingerprints(): void
    {
        header_remove('X-Powered-By');
        header_remove('Server');
    }

    /**
     * Send all security headers.
     *
     * @param  array<string, mixed>  $options
     *   Recognised keys (all optional):
     *     'csp'          – fully custom CSP string (replaces default)
     *     'hsts'         – bool|string: true = default; string = custom value
     *     'referrer'     – Referrer-Policy value
     *     'permissions'  – Permissions-Policy value
     *     'cors_origin'  – Access-Control-Allow-Origin value
     */
    private static function sendHeaders(array $options = []): void
    {
        $nonce = self::$nonce;

        // ── 1. Content-Security-Policy ────────────────────────────────────────
        // Uses a per-request nonce so specific inline <script nonce="..."> blocks
        // are whitelisted without needing 'unsafe-inline' for scripts.
        $defaultCsp  = "default-src 'self'; ";
        $defaultCsp .= "script-src 'self' 'nonce-{$nonce}'; ";
        $defaultCsp .= "style-src 'self' 'unsafe-inline'; ";    // remove 'unsafe-inline' once inline styles are in CSS
        $defaultCsp .= "img-src 'self' https://placehold.co data: blob:; ";
        $defaultCsp .= "font-src 'self'; ";
        $defaultCsp .= "connect-src 'self'; ";
        $defaultCsp .= "media-src 'none'; ";
        $defaultCsp .= "object-src 'none'; ";
        $defaultCsp .= "frame-src 'none'; ";
        $defaultCsp .= "frame-ancestors 'none'; ";
        $defaultCsp .= "base-uri 'self'; ";
        $defaultCsp .= "form-action 'self'; ";
        $defaultCsp .= "upgrade-insecure-requests";

        $csp = $options['csp'] ?? $defaultCsp;
        header("Content-Security-Policy: {$csp}");

        // ── 2. HSTS — auto-enabled on production (HTTPS), off on local dev ────
        $hstsEnabled = $options['hsts'] ?? (defined('APP_ENV') && APP_ENV === 'production');

        if ($hstsEnabled === true) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        } elseif (is_string($hstsEnabled) && $hstsEnabled !== '') {
            header("Strict-Transport-Security: {$hstsEnabled}");
        }

        // ── 3. X-Content-Type-Options ─────────────────────────────────────────
        header('X-Content-Type-Options: nosniff');

        // ── 4. X-Frame-Options (legacy) ───────────────────────────────────────
        header('X-Frame-Options: DENY');

        // ── 5. Referrer-Policy ────────────────────────────────────────────────
        $referrer = $options['referrer'] ?? 'strict-origin-when-cross-origin';
        header("Referrer-Policy: {$referrer}");

        // ── 6. Permissions-Policy ─────────────────────────────────────────────
        $defaultPermissions  = 'camera=(), microphone=(), geolocation=(), ';
        $defaultPermissions .= 'payment=(), usb=(), bluetooth=(), ';
        $defaultPermissions .= 'accelerometer=(), gyroscope=(), magnetometer=(), ';
        $defaultPermissions .= 'ambient-light-sensor=(), autoplay=(), ';
        $defaultPermissions .= 'fullscreen=(self), picture-in-picture=(self)';

        $permissions = $options['permissions'] ?? $defaultPermissions;
        header("Permissions-Policy: {$permissions}");

        // ── 7. CORS ───────────────────────────────────────────────────────────
        // Only send CORS headers when an origin is explicitly provided
        // (either via $options or matched from CORS_ALLOWED_ORIGINS).
        self::sendCorsHeaders($options['cors_origin'] ?? null);

       // ── 8. Cross-Origin Isolation ─────────────────────────────────────────
        // COEP: unsafe-none keeps cross-origin subresources working (tighten to require-corp on production)
        header('Cross-Origin-Embedder-Policy: unsafe-none');
        // COOP: same-origin-allow-popups prevents cross-origin opener attacks while permitting OAuth popups
        header('Cross-Origin-Opener-Policy: same-origin-allow-popups');
        // CORP: same-origin – only same-origin pages may embed our resources
        header('Cross-Origin-Resource-Policy: same-origin');

        // ── 9. Cache-Control (auth / private pages) ───────────────────────────
        if (self::isAuthPage()) {
            header('Cache-Control: no-store, no-cache, must-revalidate, private, max-age=0');
            header('Pragma: no-cache');
            header('Expires: 0');
        }
    }

    /**
     * Inspect the Origin header and send CORS response headers if the origin
     * is in the allow-list defined in config.php.
     *
     * @param string|null $overrideOrigin  Force a specific allowed origin value
     */
    private static function sendCorsHeaders(?string $overrideOrigin): void
    {
        if ($overrideOrigin !== null) {
            header("Access-Control-Allow-Origin: {$overrideOrigin}");
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-CSRF-Token');
            header('Access-Control-Max-Age: 86400');
            return;
        }

        $allowedOrigins = defined('CORS_ALLOWED_ORIGINS') ? CORS_ALLOWED_ORIGINS : [];
        if (empty($allowedOrigins)) {
            return;
        }

        $requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';
        if ($requestOrigin === '') {
            return;
        }

        if (in_array($requestOrigin, $allowedOrigins, true)) {
            header("Access-Control-Allow-Origin: {$requestOrigin}");
            header('Vary: Origin');   // Required when mirroring dynamic origins
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-CSRF-Token');
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Max-Age: 86400');
        }
    }

    /**
     * Handle CORS preflight OPTIONS request.
     * Must run early — before other headers or any output.
     */
    private static function handleCors(?string $overrideOrigin): void
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'OPTIONS') {
            return;
        }

        // Only respond to OPTIONS if Origin header is present
        if (!isset($_SERVER['HTTP_ORIGIN'])) {
            return;
        }

        self::sendCorsHeaders($overrideOrigin);
        header('Content-Length: 0');
        header('Content-Type: text/plain');
        http_response_code(204);
        exit;
    }

    /**
     * Determine whether the current PHP page is an auth/private page
     * (to set no-store cache headers).
     */
    private static function isAuthPage(): bool
    {
        $script   = basename($_SERVER['SCRIPT_FILENAME'] ?? '', '.php');
        $authPages = ['signin', 'signup', 'dashboard', 'activity', 'pings', 'hey', 'lineup', 'my-stuff', 'find'];
        return in_array($script, $authPages, true);
    }
}
