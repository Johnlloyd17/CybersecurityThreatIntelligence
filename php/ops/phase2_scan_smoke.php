<?php
// =============================================================================
//  PHASE 2 OPS - INDIVIDUAL + BATCH SCAN SMOKE TEST
//  Verifies configured modules can execute standalone and in batch mode.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase2_scan_smoke.php [--top20] [--slugs=a,b,c] [--configured-only] [--include-disabled] [--batch-type=domain] [--strict]

Options:
  --top20            Use the roadmap Top-20 set (default when --slugs is omitted)
  --slugs=...        Comma-separated module slugs to test
  --configured-only  Skip key-required modules without configured key (default: true)
  --include-disabled Include disabled modules in test execution
  --batch-type=...   Query type for batch test (default: domain)
  --strict           Exit non-zero if any executed individual module fails
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$configuredOnly = !array_key_exists('configured-only', $args) || ops_bool($args, 'configured-only', true);
$includeDisabled = ops_bool($args, 'include-disabled', false);
$batchType = strtolower(ops_str($args, 'batch-type', 'domain'));
$strict = ops_bool($args, 'strict', false);

$roadmapAliases = [
    'greynoise' => 'greynoise',
    'urlscan' => 'urlscan',
    'alienvault-otx' => 'alienvault',
    'securitytrails' => 'securitytrails',
    'censys' => 'censys',
    'hybrid-analysis' => 'hybrid-analysis',
    'malwarebazaar' => 'abuse-ch',
    'threatfox' => 'threatfox',
    'ipinfo' => 'ipinfo',
    'hunter-io' => 'hunter',
    'haveibeenpwned' => 'haveibeenpwned',
    'whoisxml' => 'whoisxml',
    'binaryedge' => 'binaryedge',
    'fullhunt' => 'fullhunt',
    'leakix' => 'leakix',
    'networksdb' => 'networksdb',
    'threatminer' => 'threatminer',
    'threatcrowd' => 'threatcrowd',
    'crtsh' => 'crt-sh',
    'dnsgrep' => 'dnsgrep',
];

$customSlugs = ops_csv_list(ops_str($args, 'slugs', ''));
$targets = [];
if (!empty($customSlugs)) {
    foreach ($customSlugs as $slug) {
        $targets[] = ['canonical' => $slug, 'slug' => $slug];
    }
} else {
    foreach ($roadmapAliases as $canonical => $slug) {
        $targets[] = ['canonical' => $canonical, 'slug' => $slug];
    }
}

$rows = DB::query(
    "SELECT slug, name, requires_key, is_enabled,
            (api_key IS NOT NULL AND api_key <> '') AS has_key,
            supported_types
     FROM api_configs"
);
$configMap = [];
foreach ($rows as $row) {
    $configMap[(string)$row['slug']] = $row;
}

$individual = [];
$eligibleBatchSlugs = [];

fwrite(STDOUT, "Phase 2 Individual + Batch Smoke Test\n");
fwrite(STDOUT, "Configured-only: " . ($configuredOnly ? 'yes' : 'no') . "\n");
fwrite(STDOUT, "Include disabled: " . ($includeDisabled ? 'yes' : 'no') . "\n\n");

foreach ($targets as $t) {
    $canonical = $t['canonical'];
    $slug = $t['slug'];
    $cfg = $configMap[$slug] ?? null;

    if ($cfg === null) {
        $individual[] = [
            'canonical' => $canonical,
            'slug' => $slug,
            'status' => 'missing',
            'executed' => false,
            'reason' => 'Module slug not found in api_configs.',
        ];
        fwrite(STDOUT, sprintf("[MISSING] %-16s -> %-14s\n", $canonical, $slug));
        continue;
    }

    $requiresKey = (int)$cfg['requires_key'] === 1;
    $hasKey = (int)$cfg['has_key'] === 1;
    $isEnabled = (int)$cfg['is_enabled'] === 1;
    $supportedTypes = ops_supported_types($cfg);
    $queryType = $supportedTypes[0] ?? 'domain';
    $queryValue = ops_pick_sample_target($queryType);

    if (!$includeDisabled && !$isEnabled) {
        $individual[] = [
            'canonical' => $canonical,
            'slug' => $slug,
            'status' => 'skipped',
            'executed' => false,
            'reason' => 'Module is disabled.',
            'query_type' => $queryType,
            'query_value' => $queryValue,
        ];
        fwrite(STDOUT, sprintf("[SKIPPED] %-16s -> %-14s (disabled)\n", $canonical, $slug));
        continue;
    }

    if ($configuredOnly && $requiresKey && !$hasKey) {
        $individual[] = [
            'canonical' => $canonical,
            'slug' => $slug,
            'status' => 'skipped',
            'executed' => false,
            'reason' => 'Module requires key but key is not configured.',
            'query_type' => $queryType,
            'query_value' => $queryValue,
        ];
        fwrite(STDOUT, sprintf("[SKIPPED] %-16s -> %-14s (missing key)\n", $canonical, $slug));
        continue;
    }

    $started = microtime(true);
    $raw = OsintEngine::query($queryType, $queryValue, [$slug], 0, null);
    $elapsedMs = (int)round((microtime(true) - $started) * 1000);

    $successCount = 0;
    $errorSummaries = [];
    foreach ($raw as $r) {
        if (($r['success'] ?? false) === true) {
            $successCount++;
        } else {
            $errorSummaries[] = (string)($r['error'] ?? $r['summary'] ?? 'unknown error');
        }
    }

    $status = $successCount > 0 ? 'passed' : 'failed';
    $reason = $status === 'passed'
        ? "success_count={$successCount}"
        : (empty($errorSummaries) ? 'No successful result.' : implode(' | ', array_slice($errorSummaries, 0, 2)));

    if ($status === 'passed' && in_array($batchType, $supportedTypes, true)) {
        $eligibleBatchSlugs[] = $slug;
    }

    $individual[] = [
        'canonical' => $canonical,
        'slug' => $slug,
        'status' => $status,
        'executed' => true,
        'elapsed_ms' => $elapsedMs,
        'query_type' => $queryType,
        'query_value' => $queryValue,
        'result_count' => count($raw),
        'success_count' => $successCount,
        'reason' => $reason,
    ];

    fwrite(
        STDOUT,
        sprintf(
            "[%s] %-16s -> %-14s %5dms (%s)\n",
            strtoupper($status),
            $canonical,
            $slug,
            $elapsedMs,
            $reason
        )
    );
}

$batch = [
    'executed' => false,
    'status' => 'skipped',
    'reason' => '',
    'query_type' => $batchType,
    'query_value' => ops_pick_sample_target($batchType),
    'requested_modules' => array_values(array_unique($eligibleBatchSlugs)),
    'module_results' => [],
];

if (count($eligibleBatchSlugs) < 2) {
    $batch['reason'] = 'Need at least 2 eligible modules for batch test.';
    fwrite(STDOUT, "\n[BATCH SKIPPED] {$batch['reason']}\n");
} else {
    $batchStarted = microtime(true);
    $batchRaw = OsintEngine::query($batchType, $batch['query_value'], $eligibleBatchSlugs, 0, null);
    $batchElapsedMs = (int)round((microtime(true) - $batchStarted) * 1000);

    $byModule = [];
    foreach ($eligibleBatchSlugs as $slug) {
        $byModule[$slug] = ['success_count' => 0, 'result_count' => 0, 'errors' => []];
    }

    foreach ($batchRaw as $row) {
        $slug = (string)($row['api'] ?? '');
        if (!isset($byModule[$slug])) {
            continue;
        }

        $byModule[$slug]['result_count']++;
        if (($row['success'] ?? false) === true) {
            $byModule[$slug]['success_count']++;
        } else {
            $byModule[$slug]['errors'][] = (string)($row['error'] ?? $row['summary'] ?? 'unknown error');
        }
    }

    $failedModules = 0;
    $moduleResults = [];
    foreach ($byModule as $slug => $stat) {
        $passed = $stat['success_count'] > 0;
        if (!$passed) {
            $failedModules++;
        }
        $moduleResults[] = [
            'slug' => $slug,
            'status' => $passed ? 'passed' : 'failed',
            'result_count' => $stat['result_count'],
            'success_count' => $stat['success_count'],
            'error_preview' => implode(' | ', array_slice($stat['errors'], 0, 2)),
        ];
    }

    $batch['executed'] = true;
    $batch['elapsed_ms'] = $batchElapsedMs;
    $batch['result_count'] = count($batchRaw);
    $batch['module_results'] = $moduleResults;
    $batch['status'] = $failedModules === 0 ? 'passed' : 'failed';
    $batch['reason'] = $failedModules === 0
        ? 'All modules produced successful results in batch mode.'
        : "{$failedModules} module(s) did not return successful batch results.";

    fwrite(
        STDOUT,
        sprintf(
            "\n[BATCH %s] modules=%d elapsed=%dms - %s\n",
            strtoupper($batch['status']),
            count($eligibleBatchSlugs),
            $batchElapsedMs,
            $batch['reason']
        )
    );
}

$summary = [
    'total_targets' => count($targets),
    'executed_individual' => count(array_filter($individual, static fn($r) => ($r['executed'] ?? false) === true)),
    'individual_passed' => count(array_filter($individual, static fn($r) => ($r['status'] ?? '') === 'passed')),
    'individual_failed' => count(array_filter($individual, static fn($r) => ($r['status'] ?? '') === 'failed')),
    'individual_skipped' => count(array_filter($individual, static fn($r) => ($r['status'] ?? '') === 'skipped')),
    'individual_missing' => count(array_filter($individual, static fn($r) => ($r['status'] ?? '') === 'missing')),
    'batch_status' => $batch['status'],
];

$report = [
    'generated_at_utc' => gmdate('c'),
    'configured_only' => $configuredOnly,
    'include_disabled' => $includeDisabled,
    'batch_type' => $batchType,
    'summary' => $summary,
    'individual' => $individual,
    'batch' => $batch,
];

$reportPath = ops_write_json_report($report, 'phase2_scan_smoke');
fwrite(STDOUT, "\nReport: {$reportPath}\n");

$hasIndividualFailures = $summary['individual_failed'] > 0;
if ($strict && $hasIndividualFailures) {
    exit(2);
}
exit(0);

