<?php
// =============================================================================
//  CTI — BACKGROUND SCAN WORKER  (CLI only)
//  php/background_scan.php
//
//  Spawned as a detached background process by query.php so the HTTP request
//  returns immediately with a scan_id — mirroring SpiderFoot's async scan
//  model where the UI polls for progress rather than blocking.
//
//  Usage:  php background_scan.php <scan_id> <user_id>
//
//  SECURITY: Exits immediately if not running under the PHP CLI SAPI.
//            This file must never be reachable over HTTP.
// =============================================================================

ob_start();
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// ── Hard CLI-only guard ───────────────────────────────────────────────────────
if (PHP_SAPI !== 'cli') {
    ob_end_clean();
    http_response_code(403);
    exit(1);
}

// Unlimited execution time — scans can legitimately take minutes
set_time_limit(0);
ignore_user_abort(true);

// ── Bootstrap environment for CLI ────────────────────────────────────────────
// Provide the minimum $_SERVER keys that config.php uses for environment
// detection so it always resolves to local / development mode.
if (!isset($_SERVER['HTTP_HOST']))   { $_SERVER['HTTP_HOST']   = 'localhost'; }
if (!isset($_SERVER['SERVER_NAME'])) { $_SERVER['SERVER_NAME'] = 'localhost'; }

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/OsintResult.php';
require_once __DIR__ . '/GlobalSettings.php';
require_once __DIR__ . '/OsintEngine.php';
require_once __DIR__ . '/ScanExecutor.php';

ob_end_clean();  // Discard any bootstrap output

// ── Parse arguments ───────────────────────────────────────────────────────────
$scanId = (int)($argv[1] ?? 0);
$userId = (int)($argv[2] ?? 0);

if ($scanId <= 0 || $userId <= 0) {
    error_log('[background_scan] Invalid arguments: scan_id=' . $scanId . ' user_id=' . $userId);
    exit(1);
}

// Prevent scans from being stuck forever in RUNNING if an uncaught fatal error
// terminates this worker unexpectedly (compile/runtime fatal in a module, etc.).
register_shutdown_function(static function () use ($scanId): void {
    $lastError = error_get_last();
    if (!$lastError) {
        return;
    }

    $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
    if (!in_array((int)($lastError['type'] ?? 0), $fatalTypes, true)) {
        return;
    }

    $message = trim((string)($lastError['message'] ?? 'Unknown fatal error'));
    $line = (int)($lastError['line'] ?? 0);
    $file = (string)($lastError['file'] ?? '');
    $detail = $message;
    if ($file !== '') {
        $detail .= ' @ ' . $file . ($line > 0 ? ':' . $line : '');
    }

    try {
        $row = DB::queryOne("SELECT status FROM scans WHERE id = :id LIMIT 1", [':id' => $scanId]);
        $status = strtolower((string)($row['status'] ?? ''));
        if (!in_array($status, ['starting', 'running'], true)) {
            return;
        }

        DB::execute(
            "UPDATE scans SET status = 'failed', finished_at = NOW() WHERE id = :id",
            [':id' => $scanId]
        );
        logScan($scanId, 'error', null, 'Scan worker fatal: ' . $detail);
    } catch (Throwable $ignored) {
        // Best-effort safety net only.
    }
});

// ── Load scan record ──────────────────────────────────────────────────────────
try {
    $scan = DB::queryOne(
        "SELECT * FROM scans WHERE id = :id AND status IN ('starting', 'running')",
        [':id' => $scanId]
    );
} catch (Throwable $e) {
    error_log('[background_scan] DB error loading scan #' . $scanId . ': ' . $e->getMessage());
    exit(1);
}

if (!$scan) {
    error_log('[background_scan] Scan #' . $scanId . ' not found or not in a runnable state — already finished or aborted?');
    exit(0);
}

// Transition to 'running' in case the HTTP thread created it as 'starting'
DB::execute(
    "UPDATE scans SET status = 'running' WHERE id = :id AND status = 'starting'",
    [':id' => $scanId]
);

// ── Parse selected modules ────────────────────────────────────────────────────
$selectedApis = $scan['selected_modules'] ?? '[]';
if (is_string($selectedApis)) {
    $selectedApis = json_decode($selectedApis, true) ?? [];
}

// ── Execute ───────────────────────────────────────────────────────────────────
try {
    ScanExecutor::run(
        $scanId,
        $userId,
        $scan['target_type'],
        $scan['target'],
        $selectedApis
    );
} catch (Throwable $e) {
    error_log('[background_scan] Fatal error for scan #' . $scanId . ': ' . $e->getMessage());
    try {
        DB::execute(
            "UPDATE scans SET status = 'failed', finished_at = NOW() WHERE id = :id",
            [':id' => $scanId]
        );
        logScan($scanId, 'error', null, 'Scan failed: ' . $e->getMessage());
    } catch (Throwable $ignored) {}
    exit(1);
}

exit(0);
