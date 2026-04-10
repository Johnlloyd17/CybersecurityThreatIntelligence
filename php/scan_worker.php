<?php
// =============================================================================
//  CTI — PARALLEL SCAN WORKER  (CLI only)
//  php/scan_worker.php
//
//  Entry point for concurrent module execution.  OsintEngine spawns one
//  instance of this script per module slot (up to max_concurrent_modules)
//  using proc_open, giving true parallel execution across OSINT modules —
//  analogous to SpiderFoot's multi-threaded module runner.
//
//  Input  (stdin)  : JSON object
//      {
//          "slug"        : string  — module slug (e.g. "virustotal")
//          "query_type"  : string  — domain | ip | url | hash | email | cve
//          "query_value" : string  — the target indicator
//          "api_key"     : string  — module API key (may be empty for free modules)
//          "base_url"    : string  — module base URL override
//          "api_name"    : string  — human-readable module name
//          "debug"       : bool    — enable verbose error_log output
//      }
//
//  Output (stdout) : JSON array of OsintResult::toArray() objects.
//
//  SECURITY: The script exits immediately with code 1 if not running under PHP
//  CLI SAPI.  It must never be reachable via HTTP.
// =============================================================================

// ── Buffer ALL output immediately so stray notices/warnings never corrupt JSON
ob_start();

// ── Redirect PHP errors to stderr, not stdout ────────────────────────────────
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// ── Top-level safety net: unhandled exceptions → valid JSON error on stdout ──
// The $workerSlug / $workerApiName vars are filled in after input parsing;
// at bootstrap time we use placeholder values.
$workerSlug    = 'worker';
$workerApiName = 'Worker';

set_exception_handler(static function (\Throwable $e) use (&$workerSlug, &$workerApiName): void {
    ob_end_clean();
    $msg = 'scan_worker bootstrap error: ' . $e->getMessage();
    error_log('[scan_worker] uncaught: ' . $msg);
    echo json_encode([[
        'api'         => $workerSlug,
        'api_name'    => $workerApiName,
        'score'       => 0,
        'severity'    => 'unknown',
        'confidence'  => 0,
        'response_ms' => 0,
        'summary'     => $msg,
        'tags'        => [$workerSlug, 'error'],
        'success'     => false,
        'error'       => $msg,
    ]]);
    exit(1);
});

// ── Hard CLI-only guard ───────────────────────────────────────────────────────
if (PHP_SAPI !== 'cli') {
    ob_end_clean();
    http_response_code(403);
    exit(1);
}

// ── Bootstrap environment for CLI ────────────────────────────────────────────
// Provide the minimum $_SERVER keys that config.php needs for environment
// auto-detection so it always resolves to local/development mode.
if (!isset($_SERVER['HTTP_HOST']))   { $_SERVER['HTTP_HOST']   = 'localhost'; }
if (!isset($_SERVER['SERVER_NAME'])) { $_SERVER['SERVER_NAME'] = 'localhost'; }

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/OsintResult.php';
require_once __DIR__ . '/GlobalSettings.php';
require_once __DIR__ . '/OsintEngine.php';

// ── Apply global HTTP settings ────────────────────────────────────────────────
GlobalSettings::load();
HttpClient::applyGlobalSettings();

// ── Read and validate input ───────────────────────────────────────────────────
$rawInput = stream_get_contents(STDIN);
$input    = json_decode($rawInput, true);

if (!is_array($input)) {
    ob_end_clean();
    echo json_encode([[
        'api' => 'worker', 'api_name' => 'Worker',
        'score' => 0, 'severity' => 'unknown', 'confidence' => 0, 'response_ms' => 0,
        'summary' => 'scan_worker: invalid JSON input', 'tags' => ['worker', 'error'],
        'success' => false, 'error' => 'scan_worker: invalid JSON input',
    ]]);
    exit(1);
}

$workerSlug    = (string)($input['slug']        ?? '');
$workerApiName = (string)($input['api_name']    ?? $workerSlug);
$queryType     = (string)($input['query_type']  ?? '');
$queryValue    = (string)($input['query_value'] ?? '');
$rootQueryType = (string)($input['root_query_type'] ?? $queryType);
$rootQueryValue= (string)($input['root_query_value'] ?? $queryValue);
$apiKey        = (string)($input['api_key']     ?? '');
$baseUrl       = (string)($input['base_url']    ?? '');
$debugMode     = (bool)  ($input['debug']       ?? false);
$workerModuleSettings = isset($input['module_settings']) && is_array($input['module_settings'])
    ? $input['module_settings']
    : null;

if ($workerSlug === '' || $queryType === '' || $queryValue === '') {
    ob_end_clean();
    echo json_encode([[
        'api' => $workerSlug ?: 'worker', 'api_name' => $workerApiName,
        'score' => 0, 'severity' => 'unknown', 'confidence' => 0, 'response_ms' => 0,
        'summary' => 'scan_worker: missing required fields', 'tags' => [$workerSlug, 'error'],
        'success' => false, 'error' => 'scan_worker: missing required fields',
    ]]);
    exit(1);
}

// ── Execute module ────────────────────────────────────────────────────────────
try {
    $results = OsintEngine::executeModule(
        $workerSlug,
        $queryType,
        $queryValue,
        $apiKey,
        $baseUrl,
        $workerApiName,
        $workerModuleSettings,
        $rootQueryType,
        $rootQueryValue
    );
} catch (\Throwable $e) {
    if ($debugMode) {
        error_log("[scan_worker] Exception in {$workerSlug}: " . $e->getMessage() . "\n" . $e->getTraceAsString());
    } else {
        error_log("[scan_worker] Exception in {$workerSlug}: " . $e->getMessage());
    }
    $results = [OsintResult::error($workerSlug, $workerApiName, $e->getMessage())];
}

// ── Discard any stray output and write clean JSON → stdout ───────────────────
$stray = ob_get_clean();
if ($stray !== '' && $stray !== false && $debugMode) {
    error_log("[scan_worker] discarded stray output ({$workerSlug}): " . substr($stray, 0, 200));
}

$output = array_map(
    static function ($r) {
        return $r instanceof OsintResult ? $r->toArray() : (is_array($r) ? $r : []);
    },
    is_array($results) ? $results : [$results]
);

echo json_encode($output, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
exit(0);
