<?php
// =============================================================================
//  Quick Module Test Script
//  Tests: AbuseIPDB, Shodan, APIVoid, AlienVault OTX
//
//  Usage: php php/test_modules.php
//         OR open in browser: http://localhost/CybersecurityThreatIntelligence/php/test_modules.php
// =============================================================================

// Ensure errors are visible
error_reporting(E_ALL);
ini_set('display_errors', '1');

$isCli = (php_sapi_name() === 'cli');
$nl    = $isCli ? "\n" : "<br>\n";
$bold  = fn($s) => $isCli ? "\033[1m{$s}\033[0m" : "<b>{$s}</b>";
$green = fn($s) => $isCli ? "\033[32m{$s}\033[0m" : "<span style='color:green'>{$s}</span>";
$red   = fn($s) => $isCli ? "\033[31m{$s}\033[0m" : "<span style='color:red'>{$s}</span>";
$yellow = fn($s) => $isCli ? "\033[33m{$s}\033[0m" : "<span style='color:orange'>{$s}</span>";

if (!$isCli) echo "<pre style='font-family:monospace;font-size:14px;padding:20px;'>";

echo $bold("═══════════════════════════════════════════════════════") . $nl;
echo $bold("  CTI Module Test — AbuseIPDB, Shodan, APIVoid, AlienVault") . $nl;
echo $bold("═══════════════════════════════════════════════════════") . $nl . $nl;

require_once __DIR__ . '/DB.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/OsintResult.php';
require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/ApiQuotaTracker.php';
require_once __DIR__ . '/modules/BaseApiModule.php';

// ── Define test targets ─────────────────────────────────────────────────────
$modules = [
    'abuseipdb' => [
        'file'       => __DIR__ . '/modules/AbuseIPDBModule.php',
        'class'      => 'AbuseIPDBModule',
        'queryType'  => 'ip',
        'queryValue' => '8.8.8.8',       // Google DNS — safe, clean IP
    ],
    'shodan' => [
        'file'       => __DIR__ . '/modules/ShodanModule.php',
        'class'      => 'ShodanModule',
        'queryType'  => 'ip',
        'queryValue' => '8.8.8.8',
    ],
    'apivoid' => [
        'file'       => __DIR__ . '/modules/ApiVoidModule.php',
        'class'      => 'ApiVoidModule',
        'queryType'  => 'ip',
        'queryValue' => '8.8.8.8',
    ],
    'alienvault' => [
        'file'       => __DIR__ . '/modules/AlienVaultModule.php',
        'class'      => 'AlienVaultModule',
        'queryType'  => 'ip',
        'queryValue' => '8.8.8.8',
    ],
];

// ── Load API keys from database ─────────────────────────────────────────────
echo $bold("1) Loading API keys from database...") . $nl;

$slugs = array_keys($modules);
$placeholders = implode(',', array_fill(0, count($slugs), '?'));
$pdo  = DB::connect();
$stmt = $pdo->prepare(
    "SELECT slug, name, api_key, base_url, is_enabled, requires_key, supported_types
     FROM api_configs WHERE slug IN ({$placeholders})"
);
$stmt->execute($slugs);
$configs = $stmt->fetchAll(PDO::FETCH_ASSOC);

$configMap = [];
foreach ($configs as $row) {
    $configMap[$row['slug']] = $row;
}

foreach ($slugs as $slug) {
    $cfg = $configMap[$slug] ?? null;
    if (!$cfg) {
        echo "   {$red('✗')} {$slug}: NOT FOUND in api_configs table" . $nl;
        continue;
    }

    $enabled    = $cfg['is_enabled'] ? $green('enabled') : $red('disabled');
    $hasKey     = !empty($cfg['api_key']) ? $green('has key') : $yellow('no key');
    $requiresKey = $cfg['requires_key'] ? 'required' : 'optional';
    $supported  = $cfg['supported_types'] ?? 'N/A';

    echo "   {$slug}: {$enabled} | {$hasKey} (key {$requiresKey}) | types: {$supported}" . $nl;
}
echo $nl;

// ── Test each module ────────────────────────────────────────────────────────
echo $bold("2) Running module tests...") . $nl . $nl;

$passCount = 0;
$failCount = 0;
$skipCount = 0;

foreach ($modules as $slug => $modInfo) {
    echo $bold("── {$slug} ──────────────────────────────────────") . $nl;

    $cfg = $configMap[$slug] ?? null;

    // Check prerequisites
    if (!$cfg) {
        echo "   {$red('SKIP')}: No config row in api_configs" . $nl . $nl;
        $skipCount++;
        continue;
    }

    if (!$cfg['is_enabled']) {
        echo "   {$yellow('SKIP')}: Module is disabled in api_configs" . $nl . $nl;
        $skipCount++;
        continue;
    }

    $apiKey  = $cfg['api_key'] ?? '';
    $baseUrl = $cfg['base_url'] ?? '';

    if ($cfg['requires_key'] && empty($apiKey)) {
        echo "   {$yellow('SKIP')}: Requires API key but none configured" . $nl . $nl;
        $skipCount++;
        continue;
    }

    // Load handler
    if (!file_exists($modInfo['file'])) {
        echo "   {$red('FAIL')}: Handler file not found: {$modInfo['file']}" . $nl . $nl;
        $failCount++;
        continue;
    }
    require_once $modInfo['file'];

    if (!class_exists($modInfo['class'])) {
        echo "   {$red('FAIL')}: Class {$modInfo['class']} not found after including file" . $nl . $nl;
        $failCount++;
        continue;
    }

    // Instantiate and execute
    $className = $modInfo['class'];
    $handler   = new $className();

    echo "   Query: {$modInfo['queryType']} → {$modInfo['queryValue']}" . $nl;

    $startTime = microtime(true);
    try {
        $result = $handler->execute($modInfo['queryType'], $modInfo['queryValue'], $apiKey, $baseUrl);

        // Normalize to array
        $results = ($result instanceof OsintResult) ? [$result] : (is_array($result) ? $result : []);
        $elapsed = round((microtime(true) - $startTime) * 1000);

        if (empty($results)) {
            echo "   {$red('FAIL')}: No results returned" . $nl;
            $failCount++;
        } else {
            $primary = $results[0];

            if ($primary->success) {
                echo "   {$green('PASS')}: Got result in {$elapsed}ms" . $nl;
                echo "   Score: {$primary->score} | Severity: {$primary->severity} | Confidence: {$primary->confidence}" . $nl;
                echo "   Summary: " . substr($primary->summary, 0, 120) . (strlen($primary->summary) > 120 ? '...' : '') . $nl;
                echo "   Tags: " . implode(', ', $primary->tags) . $nl;
                echo "   DataType: " . ($primary->dataType ?? 'N/A') . $nl;

                if (count($results) > 1) {
                    echo "   Enrichment elements: " . (count($results) - 1) . $nl;
                }

                $passCount++;
            } else {
                // Check if it's an auth/rate-limit issue vs a real failure
                $summary = $primary->summary ?? '';
                if (stripos($summary, 'Unauthorized') !== false || stripos($summary, '401') !== false || stripos($summary, '403') !== false) {
                    echo "   {$red('FAIL')}: Authentication error — API key may be invalid or expired" . $nl;
                    echo "   Detail: {$summary}" . $nl;
                } elseif (stripos($summary, 'rate') !== false || stripos($summary, '429') !== false) {
                    echo "   {$yellow('WARN')}: Rate limited — try again later" . $nl;
                    echo "   Detail: {$summary}" . $nl;
                } else {
                    echo "   {$red('FAIL')}: {$summary}" . $nl;
                }
                $failCount++;
            }
        }
    } catch (\Throwable $e) {
        $elapsed = round((microtime(true) - $startTime) * 1000);
        echo "   {$red('FAIL')}: Exception in {$elapsed}ms — " . $e->getMessage() . $nl;
        echo "   File: " . $e->getFile() . ':' . $e->getLine() . $nl;
        $failCount++;
    }

    echo $nl;
}

// ── Health checks ───────────────────────────────────────────────────────────
echo $bold("3) Running health checks...") . $nl . $nl;

foreach ($modules as $slug => $modInfo) {
    $cfg = $configMap[$slug] ?? null;
    if (!$cfg || !$cfg['is_enabled'] || ($cfg['requires_key'] && empty($cfg['api_key']))) {
        echo "   {$slug}: SKIPPED (no config/key/disabled)" . $nl;
        continue;
    }

    $className = $modInfo['class'];
    $handler   = new $className();
    $apiKey    = $cfg['api_key'] ?? '';
    $baseUrl   = $cfg['base_url'] ?? '';

    try {
        $health = $handler->healthCheck($apiKey, $baseUrl);
        $status = $health['status'] ?? 'unknown';
        $latency = $health['latency_ms'] ?? 0;
        $error  = $health['error'] ?? null;

        if ($status === 'healthy') {
            echo "   {$slug}: {$green('HEALTHY')} ({$latency}ms)" . $nl;
        } else {
            echo "   {$slug}: {$red($status)} ({$latency}ms) — {$error}" . $nl;
        }
    } catch (\Throwable $e) {
        echo "   {$slug}: {$red('EXCEPTION')} — " . $e->getMessage() . $nl;
    }
}

echo $nl;

// ── Summary ─────────────────────────────────────────────────────────────────
echo $bold("═══════════════════════════════════════════════════════") . $nl;
echo $bold("  SUMMARY: ") . $green("{$passCount} passed") . " | " . $red("{$failCount} failed") . " | " . $yellow("{$skipCount} skipped") . $nl;
echo $bold("═══════════════════════════════════════════════════════") . $nl;

if (!$isCli) echo "</pre>";
