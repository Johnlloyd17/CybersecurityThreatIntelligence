<?php
// =============================================================================
//  CTI — RATE LIMITER
//  php/RateLimiter.php
//
//  Implements brute-force / credential-stuffing protection for authentication
//  endpoints, as recommended by OWASP Testing Guide §4.4.3
//  (Testing for Weak Lock Out Mechanism) and the Authentication Cheat Sheet.
//
//  Strategy:
//    • Track failed attempts per (IP + identifier) key in the DB
//    • Lock out after LOGIN_MAX_ATTEMPTS failures within LOGIN_LOCKOUT_SECS
//    • Automatic unlock once the window expires (no admin action required)
//    • Successful login clears the attempt counter for that key
//    • All queries are parameterized — SQL injection is not possible here
//
//  Requires table:  login_attempts  (created by sql/schema.sql)
//
//  ⚠  This file is blocked from direct browser access by php/.htaccess.
// =============================================================================

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

class RateLimiter
{
    // =========================================================================
    //  PUBLIC API
    // =========================================================================

    /**
     * Check whether a login attempt is allowed.
     *
     * Returns true  → request may proceed.
     * Returns false → client is locked out.
     *
     * @param  string  $identifier  Email or username being authenticated
     * @param  string  $ip          Client IP address
     */
    public static function isAllowed(string $identifier, string $ip): bool
    {
        try {
            self::purgeExpired();   // housekeeping: remove old windows first

            $key     = self::makeKey($identifier, $ip);
            $maxAtt  = defined('LOGIN_MAX_ATTEMPTS') ? LOGIN_MAX_ATTEMPTS : 5;
            $window  = defined('LOGIN_LOCKOUT_SECS') ? LOGIN_LOCKOUT_SECS : 900;

            $row = DB::queryOne(
                'SELECT attempts, first_attempt_at
                   FROM login_attempts
                  WHERE attempt_key = :key
                    AND first_attempt_at >= DATE_SUB(NOW(), INTERVAL :window SECOND)',
                [':key' => $key, ':window' => $window]
            );

            if ($row === null) {
                return true;                       // No record → allowed
            }

            return (int)$row['attempts'] < $maxAtt;
        } catch (Throwable $e) {
            // Rate-limit table unreachable — fail-open so the main auth query
            // can still run. The DB error will surface there if the DB is truly down.
            error_log('[RateLimiter] isAllowed failed: ' . $e->getMessage());
            return true;
        }
    }

    /**
     * Record a failed login attempt for the given identifier + IP.
     * Increments the counter if a window already exists, inserts otherwise.
     *
     * @param  string  $identifier
     * @param  string  $ip
     */
    public static function recordFailure(string $identifier, string $ip): void
    {
        $key = self::makeKey($identifier, $ip);

        try {
            // Upsert: increment if row exists within the window, else insert fresh
            DB::execute(
                'INSERT INTO login_attempts (attempt_key, attempts, first_attempt_at, last_attempt_at)
                      VALUES (:key, 1, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE
                      attempts        = IF(
                                          first_attempt_at >= DATE_SUB(NOW(), INTERVAL :window SECOND),
                                          attempts + 1,
                                          1
                                        ),
                      first_attempt_at = IF(
                                          first_attempt_at >= DATE_SUB(NOW(), INTERVAL :window2 SECOND),
                                          first_attempt_at,
                                          NOW()
                                        ),
                      last_attempt_at  = NOW()',
                [
                    ':key'     => $key,
                    ':window'  => defined('LOGIN_LOCKOUT_SECS') ? LOGIN_LOCKOUT_SECS : 900,
                    ':window2' => defined('LOGIN_LOCKOUT_SECS') ? LOGIN_LOCKOUT_SECS : 900,
                ]
            );
        } catch (Throwable $e) {
            error_log('[RateLimiter] recordFailure failed: ' . $e->getMessage());
        }

        self::logAttempt($identifier, $ip, false);
    }

    /**
     * Reset the attempt counter after a successful login.
     *
     * @param  string  $identifier
     * @param  string  $ip
     */
    public static function clearFailures(string $identifier, string $ip): void
    {
        $key = self::makeKey($identifier, $ip);

        try {
            DB::execute(
                'DELETE FROM login_attempts WHERE attempt_key = :key',
                [':key' => $key]
            );
        } catch (Throwable $e) {
            error_log('[RateLimiter] clearFailures failed: ' . $e->getMessage());
        }

        self::logAttempt($identifier, $ip, true);
    }

    /**
     * Return remaining seconds until the lockout for this key expires.
     * Returns 0 if not currently locked out.
     *
     * @param  string  $identifier
     * @param  string  $ip
     * @return int  Seconds remaining
     */
    public static function lockoutRemainingSeconds(string $identifier, string $ip): int
    {
        $key    = self::makeKey($identifier, $ip);
        $window = defined('LOGIN_LOCKOUT_SECS') ? LOGIN_LOCKOUT_SECS : 900;
        $maxAtt = defined('LOGIN_MAX_ATTEMPTS') ? LOGIN_MAX_ATTEMPTS : 5;

        $row = DB::queryOne(
            'SELECT attempts,
                    TIMESTAMPDIFF(SECOND, NOW(),
                        DATE_ADD(first_attempt_at, INTERVAL :window SECOND)
                    ) AS secs_left
               FROM login_attempts
              WHERE attempt_key = :key
                AND attempts    >= :max
                AND first_attempt_at >= DATE_SUB(NOW(), INTERVAL :window2 SECOND)',
            [
                ':key'     => $key,
                ':window'  => $window,
                ':max'     => $maxAtt,
                ':window2' => $window,
            ]
        );

        if ($row === null) {
            return 0;
        }

        return max(0, (int)$row['secs_left']);
    }

    // =========================================================================
    //  PRIVATE HELPERS
    // =========================================================================

    /**
     * Build the composite key stored in login_attempts.
     * We hash IP + identifier together so the key itself leaks nothing.
     */
    private static function makeKey(string $identifier, string $ip): string
    {
        return hash('sha256', strtolower(trim($identifier)) . '|' . $ip);
    }

    /**
     * Remove expired attempt windows to keep the table small.
     * Called on every isAllowed() check (lightweight — indexed on first_attempt_at).
     */
    private static function purgeExpired(): void
    {
        $window = defined('LOGIN_LOCKOUT_SECS') ? LOGIN_LOCKOUT_SECS : 900;

        try {
            DB::execute(
                'DELETE FROM login_attempts
                  WHERE first_attempt_at < DATE_SUB(NOW(), INTERVAL :window SECOND)',
                [':window' => $window]
            );
        } catch (Throwable $e) {
            // Non-fatal — log and continue
            error_log('[RateLimiter] purge failed: ' . $e->getMessage());
        }
    }

    /**
     * Structured security log entry (never exposed to the client).
     *
     * @param  string  $identifier  Hashed in the log for PII minimisation
     * @param  string  $ip
     * @param  bool    $success
     */
    private static function logAttempt(string $identifier, string $ip, bool $success): void
    {
        $ts     = gmdate('Y-m-d\TH:i:s\Z');
        $status = $success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILURE';
        // Hash the identifier before logging — protects user PII in log files
        $idHash = substr(hash('sha256', strtolower(trim($identifier))), 0, 12);

        error_log("[SECURITY] {$ts} {$status} ip={$ip} id_hash={$idHash}");
    }
}
