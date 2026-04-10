<?php
// =============================================================================
//  CTI — AUTHENTICATION API
//  php/api/auth.php
//
//  Endpoints:
//    POST  ?action=login     — Authenticate user (email + password)
//    POST  ?action=logout    — Destroy session
//    GET   ?action=session   — Check current session status
//
//  All responses are JSON. CSRF token is validated on login/logout.
//  Rate limiting is applied to login attempts.
//
//  ⚠  Requires php/config.php, php/db.php, php/security-headers.php,
//     php/InputSanitizer.php, php/RateLimiter.php
// =============================================================================

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../security-headers.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../InputSanitizer.php';
require_once __DIR__ . '/../RateLimiter.php';

// Initialize session + security headers (CSP nonce, CORS, etc.)
SecurityHeaders::init();

header('Content-Type: application/json; charset=utf-8');

// ── Route dispatcher ──────────────────────────────────────────────────────────
$action = $_GET['action'] ?? $_POST['action'] ?? '';

switch ($action) {
    case 'login':
        handleLogin();
        break;

    case 'logout':
        handleLogout();
        break;

    case 'session':
        handleSession();
        break;

    case 'csrf':
        handleCsrf();
        break;

    default:
        jsonResponse(400, ['error' => 'Unknown action.']);
}

// =============================================================================
//  HANDLERS
// =============================================================================

/**
 * POST ?action=login
 * Body: { email, password, _csrf_token }
 */
function handleLogin(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonResponse(405, ['error' => 'Method not allowed.']);
    }

    // Parse JSON body
    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    // CSRF validation
    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonResponse(403, ['error' => 'Invalid or expired CSRF token. Please refresh and try again.']);
    }

    // Validate input
    $result = InputSanitizer::validate($input, [
        'email'    => 'email',
        'password' => 'password',
    ]);

    if (!$result['ok']) {
        jsonResponse(422, ['error' => $result['errors'][0] ?? 'Validation failed.']);
    }

    $email    = $result['data']['email'];
    $password = $result['data']['password'];
    $ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // Rate limiting check
    if (!RateLimiter::isAllowed($email, $ip)) {
        $remaining = RateLimiter::lockoutRemainingSeconds($email, $ip);
        jsonResponse(429, [
            'error'   => 'Too many failed attempts. Please try again later.',
            'retry_after' => $remaining,
        ]);
    }

    // Look up user
    $user = DB::queryOne(
        'SELECT u.id, u.full_name, u.email, u.password_hash, u.is_active,
                r.name AS role_name
           FROM users u
           JOIN roles r ON r.id = u.role_id
          WHERE u.email = :email
          LIMIT 1',
        [':email' => $email]
    );

    if (!$user || !DB::verifyPassword($password, $user['password_hash'])) {
        RateLimiter::recordFailure($email, $ip);
        // Generic message — never reveal whether the email exists
        jsonResponse(401, ['error' => 'Invalid email or password.']);
    }

    if (!$user['is_active']) {
        jsonResponse(403, ['error' => 'Account is deactivated. Contact an administrator.']);
    }

    // Success — clear rate limiter and set up session
    RateLimiter::clearFailures($email, $ip);

    // Regenerate session ID to prevent fixation
    session_regenerate_id(true);

    $_SESSION['user_id']   = $user['id'];
    $_SESSION['user_name'] = $user['full_name'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['user_role'] = $user['role_name'];
    $_SESSION['login_at']  = time();

    // Update last_login_at
    DB::execute(
        'UPDATE users SET last_login_at = NOW() WHERE id = :id',
        [':id' => $user['id']]
    );

    jsonResponse(200, [
        'message' => 'Login successful.',
        'user'    => [
            'id'    => $user['id'],
            'name'  => $user['full_name'],
            'email' => $user['email'],
            'role'  => $user['role_name'],
        ],
    ]);
}

/**
 * POST ?action=logout
 */
function handleLogout(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonResponse(405, ['error' => 'Method not allowed.']);
    }

    session_unset();
    session_destroy();

    jsonResponse(200, ['message' => 'Logged out successfully.']);
}

/**
 * GET ?action=session
 * Returns the current user session info (or 401 if not logged in).
 */
function handleSession(): void
{
    if (empty($_SESSION['user_id'])) {
        jsonResponse(401, ['error' => 'Not authenticated.']);
    }

    jsonResponse(200, [
        'user' => [
            'id'    => $_SESSION['user_id'],
            'name'  => $_SESSION['user_name'],
            'email' => $_SESSION['user_email'],
            'role'  => $_SESSION['user_role'],
        ],
    ]);
}

/**
 * GET ?action=csrf
 * Returns a fresh CSRF token for the current session.
 */
function handleCsrf(): void
{
    jsonResponse(200, [
        'csrf_token' => SecurityHeaders::csrfToken(),
    ]);
}

// =============================================================================
//  HELPERS
// =============================================================================

/**
 * Send a JSON response and exit.
 *
 * @param int   $statusCode  HTTP status code
 * @param array $data        Response payload
 */
function jsonResponse(int $statusCode, array $data): void
{
    http_response_code($statusCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
