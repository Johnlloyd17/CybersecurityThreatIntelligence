<?php
// =============================================================================
//  CTI — SERVER-SIDE INPUT SANITIZER & SQL INJECTION GUARD
//  php/InputSanitizer.php
//
//  Based on OWASP WSTG-INPV-05 (Testing for SQL Injection) and the
//  SQL Injection Prevention Cheat Sheet.
//
//  Defence-in-depth strategy:
//    1. Whitelist validation  — only accept input that matches a known-good pattern
//    2. Type & length checks  — reject anything outside the expected shape
//    3. Injection detection   — log and block payloads matching known attack
//                               patterns (Union, Boolean, Error-based, etc.)
//    4. Output encoding       — htmlspecialchars() before rendering in HTML
//    5. Parameterized queries — enforced at DB layer (db.php) — NOT string escape
//
//  ⚠  This file is blocked from direct browser access by php/.htaccess.
//  ⚠  Sanitization here is a SECONDARY defence. The PRIMARY defence is always
//     to use prepared statements (see DB::query / DB::execute in db.php).
// =============================================================================

class InputSanitizer
{
    // =========================================================================
    //  SQL INJECTION SIGNATURE PATTERNS
    //  Covers all five OWASP technique classes:
    //    • Union-based   — UNION SELECT …
    //    • Boolean-based — OR 1=1, AND 1=1
    //    • Error-based   — CONVERT(), EXTRACTVALUE(), UTL_INADDR …
    //    • Time-delay    — SLEEP(), WAITFOR DELAY, BENCHMARK()
    //    • Stacked queries — ; DROP TABLE …
    //
    //  Also covers common evasion techniques from OWASP:
    //    • Null-byte injection   (%00)
    //    • SQL inline comments   (/**/, --)
    //    • URL-encoded payloads  (%27, %3D …)
    //    • HEX / CHAR encoding
    // =========================================================================

    /** @var array<int, string>  compiled regex patterns */
    private static array $SQL_PATTERNS = [];

    private static function sqlPatterns(): array
    {
        if (!empty(self::$SQL_PATTERNS)) {
            return self::$SQL_PATTERNS;
        }

        self::$SQL_PATTERNS = [
            // ── Union-based injection ─────────────────────────────────────────
            '/\bUNION\b[\s\S]*\bSELECT\b/i',

            // ── DML / DDL keywords that have no place in user input ───────────
            '/\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE|MERGE)\b/i',

            // ── Execution / procedure calls ───────────────────────────────────
            '/\b(EXEC|EXECUTE|CALL|SP_|XP_)\b/i',

            // ── Boolean logic injection: OR/AND with comparison ───────────────
            '/\b(OR|AND)\b\s+[\'"]?[\w\s]+[\'"]?\s*[=<>!]+/i',

            // ── Classic tautologies: 1=1, '1'='1', 'a'='a' ───────────────────
            '/[\'"]?\s*\d+\s*=\s*\d+\s*[\'"]?/i',
            '/[\'"][\w\s]+[\'"]?\s*=\s*[\'"][\w\s]+[\'"]/i',

            // ── SQL comments (evasion) ────────────────────────────────────────
            '/(--|#|\/\*|\*\/)/i',

            // ── Stacked queries ───────────────────────────────────────────────
            '/;\s*(DROP|INSERT|UPDATE|DELETE|CREATE|ALTER|EXEC|EXECUTE)/i',

            // ── Time-delay functions (MySQL / MSSQL / Oracle) ─────────────────
            '/\b(SLEEP|WAITFOR|BENCHMARK|PG_SLEEP)\b/i',

            // ── Error-based extraction functions ─────────────────────────────
            '/\b(EXTRACTVALUE|UPDATEXML|UTL_INADDR|UTL_HTTP|SYS\.EVAL)\b/i',

            // ── Information schema / privilege discovery ──────────────────────
            '/\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|ALL_TABLES|USER_TABLES)\b/i',

            // ── HEX / CHAR encoding evasion ───────────────────────────────────
            '/\b(CHAR|NCHAR|VARCHAR|CONVERT|CAST)\s*\(/i',
            '/0x[0-9a-fA-F]{4,}/i',          // hex literal e.g. 0x726F6F74

            // ── LOAD / INTO OUTFILE (file-system access) ──────────────────────
            '/\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b/i',

            // ── Null-byte injection ───────────────────────────────────────────
            '/\x00/',
            '/%00/',

            // ── URL-encoded single-quote evasion ─────────────────────────────
            '/%27|%22|%3B/i',

            // ── LIMIT exploitation (used in Union + Boolean) ──────────────────
            '/\bLIMIT\b\s+\d+\s*,\s*\d+/i',
        ];

        return self::$SQL_PATTERNS;
    }

    // =========================================================================
    //  PUBLIC — DETECTION
    // =========================================================================

    /**
     * Detect SQL injection payloads in a single string value.
     *
     * Returns true if any known attack pattern is found.
     * Applies URL-decoding and normalisation first to catch evasion attempts.
     *
     * Ref: OWASP WSTG-INPV-05 §Detection Techniques
     */
    public static function hasSQLInjection(string $value): bool
    {
        // Normalise: URL-decode, strip null bytes, collapse whitespace
        $normalised = self::normalise($value);

        foreach (self::sqlPatterns() as $pattern) {
            if (preg_match($pattern, $normalised)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Scan every value in an associative array (e.g. $_POST / $_GET).
     * Returns a list of field names that contain injection patterns, or [].
     *
     * @param  array<string, mixed>  $data
     * @return string[]  Field names that failed
     */
    public static function scanFields(array $data): array
    {
        $flagged = [];
        foreach ($data as $field => $value) {
            if (is_string($value) && self::hasSQLInjection($value)) {
                $flagged[] = $field;
            }
        }
        return $flagged;
    }

    // =========================================================================
    //  PUBLIC — VALIDATION (whitelist approach)
    // =========================================================================

    /**
     * Validate an e-mail address.
     * Uses PHP's built-in FILTER_VALIDATE_EMAIL (RFC 5321-ish).
     */
    public static function isValidEmail(string $email): bool
    {
        return strlen($email) <= 255
            && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validate a password against the minimum security policy.
     *  • At least PASSWORD_MIN_LEN characters
     *  • At least 1 uppercase letter
     *  • At least 1 lowercase letter
     *  • At least 1 digit
     *  • At least 1 special character
     *  • Maximum 128 characters (prevents bcrypt DoS)
     */
    public static function isValidPassword(string $password): bool
    {
        $min = defined('PASSWORD_MIN_LEN') ? PASSWORD_MIN_LEN : 8;
        if (strlen($password) < $min || strlen($password) > 128) {
            return false;
        }
        return preg_match('/[A-Z]/', $password)
            && preg_match('/[a-z]/', $password)
            && preg_match('/\d/',    $password)
            && preg_match('/[\W_]/', $password);
    }

    /**
     * Validate a full name (display name).
     * Allows Unicode letters, spaces, hyphens, apostrophes.
     * Min 2 chars, max 100 chars.
     */
    public static function isValidFullName(string $name): bool
    {
        $trimmed = trim($name);
        return strlen($trimmed) >= 2
            && strlen($trimmed) <= 100
            && preg_match("/^[\p{L}\s\-']+$/u", $trimmed);
    }

    /**
     * Validate an organisation / company name.
     * Allows letters, digits, spaces, common punctuation.
     */
    public static function isValidOrganisation(string $org): bool
    {
        $trimmed = trim($org);
        return strlen($trimmed) >= 2
            && strlen($trimmed) <= 150
            && preg_match("/^[\p{L}\p{N}\s\-',\.&]+$/u", $trimmed);
    }

    /**
     * Validate a generic text field (search, message, etc. — no SQL required).
     *
     * @param  string  $text
     * @param  int     $maxLen
     */
    public static function isValidText(string $text, int $maxLen = 1000): bool
    {
        return strlen($text) <= $maxLen;
    }

    // =========================================================================
    //  PUBLIC — SANITIZATION (clean + HTML-encode for output)
    // =========================================================================

    /**
     * Trim whitespace and encode HTML entities.
     * Use this when rendering untrusted data in HTML output.
     * (Never rely on this to make SQL safe — use prepared statements.)
     */
    public static function sanitizeString(string $value): string
    {
        return htmlspecialchars(trim($value), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Sanitize an e-mail: lowercase + trim; validation is separate.
     */
    public static function sanitizeEmail(string $email): string
    {
        return strtolower(trim($email));
    }

    /**
     * Strip everything except digits (optionally allow leading +/-).
     */
    public static function sanitizeInteger(string $value, bool $allowNegative = false): ?int
    {
        $filtered = filter_var(
            $value,
            FILTER_VALIDATE_INT,
            $allowNegative
                ? ['options' => ['min_range' => PHP_INT_MIN]]
                : ['options' => ['min_range' => 0]]
        );
        return $filtered !== false ? (int)$filtered : null;
    }

    // =========================================================================
    //  PUBLIC — COMBINED VALIDATE + SCAN (convenience wrapper)
    // =========================================================================

    /**
     * Run field-by-field validation AND SQL injection scan on a data array.
     *
     * @param  array<string, mixed>  $data       Raw input (e.g. from json_decode)
     * @param  array<string, string> $rules       Map of fieldName => rule
     *                                            Rules: 'email', 'password', 'fullname',
     *                                                   'organisation', 'text', 'int'
     * @return array{ok: bool, errors: string[], data: array<string, mixed>}
     */
    public static function validate(array $data, array $rules): array
    {
        $errors  = [];
        $cleaned = [];

        // ── 1. SQL injection scan across all fields ───────────────────────────
        $flagged = self::scanFields($data);
        if (!empty($flagged)) {
            // Log but return a generic error — OWASP says don't reveal internals
            self::logInjectionAttempt($flagged, $data);
            $errors[] = 'Invalid characters detected in one or more fields.';
            return ['ok' => false, 'errors' => $errors, 'data' => []];
        }

        // ── 2. Per-field validation ───────────────────────────────────────────
        foreach ($rules as $field => $rule) {
            $raw = isset($data[$field]) ? (string)$data[$field] : '';

            switch ($rule) {
                case 'email':
                    if (empty($raw)) {
                        $errors[] = "Email is required.";
                    } elseif (!self::isValidEmail($raw)) {
                        $errors[] = "Invalid email address.";
                    } else {
                        $cleaned[$field] = self::sanitizeEmail($raw);
                    }
                    break;

                case 'password':
                    if (empty($raw)) {
                        $errors[] = "Password is required.";
                    } elseif (!self::isValidPassword($raw)) {
                        $min = defined('PASSWORD_MIN_LEN') ? PASSWORD_MIN_LEN : 8;
                        $errors[] = "Password must be at least {$min} characters with uppercase, lowercase, number, and special character.";
                    } else {
                        $cleaned[$field] = $raw;   // Never sanitize/trim passwords
                    }
                    break;

                case 'fullname':
                    if (empty(trim($raw))) {
                        $errors[] = "Full name is required.";
                    } elseif (!self::isValidFullName($raw)) {
                        $errors[] = "Full name contains invalid characters.";
                    } else {
                        $cleaned[$field] = self::sanitizeString($raw);
                    }
                    break;

                case 'organisation':
                    if (!empty($raw) && !self::isValidOrganisation($raw)) {
                        $errors[] = "Organisation name contains invalid characters.";
                    } else {
                        $cleaned[$field] = self::sanitizeString($raw);
                    }
                    break;

                case 'text':
                    if (!self::isValidText($raw)) {
                        $errors[] = "Field '{$field}' is too long.";
                    } else {
                        $cleaned[$field] = self::sanitizeString($raw);
                    }
                    break;

                case 'int':
                    $intVal = self::sanitizeInteger($raw);
                    if ($intVal === null) {
                        $errors[] = "Field '{$field}' must be a valid number.";
                    } else {
                        $cleaned[$field] = $intVal;
                    }
                    break;

                default:
                    // Unknown rule — pass through with basic string sanitization
                    $cleaned[$field] = self::sanitizeString($raw);
            }
        }

        return [
            'ok'     => empty($errors),
            'errors' => $errors,
            'data'   => $cleaned,
        ];
    }

    // =========================================================================
    //  PRIVATE — HELPERS
    // =========================================================================

    /**
     * Normalise a string for reliable injection pattern matching:
     *  • URL-decode once (handles %27 → ')
     *  • Strip null bytes
     *  • Collapse multiple whitespace to a single space
     */
    private static function normalise(string $value): string
    {
        $decoded  = urldecode($value);           // %27 → ', %20 → space
        $noNull   = str_replace("\x00", '', $decoded);
        return preg_replace('/\s+/', ' ', $noNull) ?? $noNull;
    }

    /**
     * Write a structured security event to the PHP error log.
     * In production, pipe this to a dedicated SIEM / security log.
     *
     * OWASP note: NEVER return internal details to the HTTP response.
     *
     * @param  string[]              $fields  Flagged field names
     * @param  array<string, mixed>  $data    Raw payload (values redacted)
     */
    private static function logInjectionAttempt(array $fields, array $data): void
    {
        $ip        = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $uri       = $_SERVER['REQUEST_URI'] ?? 'unknown';
        $method    = $_SERVER['REQUEST_METHOD'] ?? 'unknown';
        $timestamp = gmdate('Y-m-d\TH:i:s\Z');

        // Redact values — log field names only
        $fieldList = implode(', ', $fields);

        error_log(
            "[SECURITY] {$timestamp} SQLI_ATTEMPT"
            . " ip={$ip}"
            . " method={$method}"
            . " uri={$uri}"
            . " flagged_fields=[{$fieldList}]"
        );
    }
}
