<?php
// =============================================================================
//  PHASE 5 OPS - LOAD TEST RUNNER
//  Runs repeated multi-module scans and captures latency/success metrics.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase5_load_test.php [--iterations=5] [--query-type=domain] [--query-value=example.com] [--modules=a,b,c] [--module-limit=20] [--configured-only] [--strict] [--min-success-rate=80]

Options:
  --iterations=...       Number of repeated scan runs (default: 5)
  --query-type=...       domain|ip|url|hash|email|cve (default: domain)
  --query-value=...      Target value (default picked from query type)
  --modules=...          Optional comma-separated module slugs
  --module-limit=...     Max modules when auto-selecting (default: 20)
  --configured-only      Skip key-required modules without key (default: true)
  --include-disabled     Include disabled modules in auto selection
  --strict               Exit non-zero if success rate falls below threshold
  --min-success-rate=... Required success rate in strict mode (default: 80)
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$iterations = max(1, ops_int($args, 'iterations', 5));
$queryType = strtolower(ops_str($args, 'query-type', 'domain'));
$queryValue = ops_str($args, 'query-value', ops_pick_sample_target($queryType));
$moduleLimit = max(1, ops_int($args, 'module-limit', 20));
$configuredOnly = !array_key_exists('configured-only', $args) || ops_bool($args, 'configured-only', true);
$includeDisabled = ops_bool($args, 'include-disabled', false);
$strict = ops_bool($args, 'strict', false);
$minSuccessRate = (float)ops_int($args, 'min-success-rate', 80);

$requestedModules = ops_csv_list(strtolower(ops_str($args, 'modules', '')));

$rows = DB::query(
    "SELECT slug, name, is_enabled, requires_key, supported_types,
            (api_key IS NOT NULL AND api_key <> '') AS has_key
     FROM api_configs
     ORDER BY slug"
);

$selected = [];
if (!empty($requestedModules)) {
    $allowed = array_flip($requestedModules);
    foreach ($rows as $row) {
        $slug = strtolower((string)$row['slug']);
        if (isset($allowed[$slug])) {
            $selected[] = $row;
        }
    }
} else {
    foreach ($rows as $row) {
        $isEnabled = (int)$row['is_enabled'] === 1;
        $requiresKey = (int)$row['requires_key'] === 1;
        $hasKey = (int)$row['has_key'] === 1;
        if (!$includeDisabled && !$isEnabled) {
            continue;
        }
        if ($configuredOnly && $requiresKey && !$hasKey) {
            continue;
        }

        $supported = ops_supported_types($row);
        if (!empty($supported) && !in_array($queryType, $supported, true)) {
            continue;
        }

        $selected[] = $row;
        if (count($selected) >= $moduleLimit) {
            break;
        }
    }
}

if (empty($selected)) {
    fwrite(STDERR, "[phase5] No modules selected for load test.\n");
    exit(1);
}

$selectedSlugs = array_map(static fn($r) => (string)$r['slug'], $selected);
$selectedMap = [];
foreach ($selectedSlugs as $slug) {
    $selectedMap[$slug] = true;
}

$percentile = static function (array $values, float $p): float {
    if (empty($values)) {
        return 0.0;
    }
    sort($values, SORT_NUMERIC);
    $n = count($values);
    if ($n === 1) {
        return (float)$values[0];
    }
    $index = ($p / 100.0) * ($n - 1);
    $lower = (int)floor($index);
    $upper = (int)ceil($index);
    if ($lower === $upper) {
        return (float)$values[$lower];
    }
    $weight = $index - $lower;
    return ((1.0 - $weight) * (float)$values[$lower]) + ($weight * (float)$values[$upper]);
};

fwrite(STDOUT, "Phase 5 Load Test Runner\n");
fwrite(STDOUT, "Iterations       : {$iterations}\n");
fwrite(STDOUT, "Query            : {$queryType} {$queryValue}\n");
fwrite(STDOUT, "Module count     : " . count($selectedSlugs) . "\n");
fwrite(STDOUT, "Configured-only  : " . ($configuredOnly ? 'yes' : 'no') . "\n");
fwrite(STDOUT, "Include disabled : " . ($includeDisabled ? 'yes' : 'no') . "\n\n");

$iterationResults = [];
$latencies = [];
$totalModulePasses = 0;
$totalPossiblePasses = $iterations * count($selectedSlugs);

for ($i = 1; $i <= $iterations; $i++) {
    $started = microtime(true);
    $raw = OsintEngine::query($queryType, $queryValue, $selectedSlugs, 0, null);
    $elapsedMs = (int)round((microtime(true) - $started) * 1000);
    $latencies[] = $elapsedMs;

    $byModule = [];
    foreach ($selectedSlugs as $slug) {
        $byModule[$slug] = ['result_count' => 0, 'success_count' => 0, 'errors' => []];
    }

    foreach ($raw as $row) {
        $slug = (string)($row['api'] ?? '');
        if (!isset($selectedMap[$slug])) {
            continue;
        }
        $byModule[$slug]['result_count']++;
        if (($row['success'] ?? false) === true) {
            $byModule[$slug]['success_count']++;
        } else {
            $byModule[$slug]['errors'][] = (string)($row['error'] ?? $row['summary'] ?? 'unknown error');
        }
    }

    $passModules = 0;
    $failedModules = [];
    foreach ($byModule as $slug => $stats) {
        if ($stats['success_count'] > 0) {
            $passModules++;
        } else {
            $failedModules[] = [
                'slug' => $slug,
                'error_preview' => implode(' | ', array_slice($stats['errors'], 0, 1)),
            ];
        }
    }

    $totalModulePasses += $passModules;
    $successRate = count($selectedSlugs) > 0 ? round(($passModules / count($selectedSlugs)) * 100, 2) : 0.0;

    $iterationResults[] = [
        'iteration' => $i,
        'elapsed_ms' => $elapsedMs,
        'result_count' => count($raw),
        'passed_modules' => $passModules,
        'failed_modules' => count($failedModules),
        'success_rate' => $successRate,
        'failed_module_preview' => array_slice($failedModules, 0, 5),
    ];

    fwrite(
        STDOUT,
        sprintf(
            "[ITER %02d] elapsed=%5dms passed=%d/%d success_rate=%.2f%%\n",
            $i,
            $elapsedMs,
            $passModules,
            count($selectedSlugs),
            $successRate
        )
    );
}

$overallSuccessRate = $totalPossiblePasses > 0
    ? round(($totalModulePasses / $totalPossiblePasses) * 100, 2)
    : 0.0;

$summary = [
    'iterations' => $iterations,
    'module_count' => count($selectedSlugs),
    'total_possible_module_passes' => $totalPossiblePasses,
    'total_module_passes' => $totalModulePasses,
    'overall_success_rate' => $overallSuccessRate,
    'latency_min_ms' => empty($latencies) ? 0 : min($latencies),
    'latency_avg_ms' => empty($latencies) ? 0 : (int)round(array_sum($latencies) / count($latencies)),
    'latency_p50_ms' => round($percentile($latencies, 50), 2),
    'latency_p95_ms' => round($percentile($latencies, 95), 2),
    'latency_max_ms' => empty($latencies) ? 0 : max($latencies),
];

$report = [
    'generated_at_utc' => gmdate('c'),
    'query_type' => $queryType,
    'query_value' => $queryValue,
    'configured_only' => $configuredOnly,
    'include_disabled' => $includeDisabled,
    'selected_modules' => $selectedSlugs,
    'summary' => $summary,
    'iterations' => $iterationResults,
];
$reportPath = ops_write_json_report($report, 'phase5_load_test');

fwrite(STDOUT, "\nSummary:\n");
foreach ($summary as $k => $v) {
    if (is_float($v)) {
        fwrite(STDOUT, sprintf("  %-30s : %.2f\n", $k, $v));
    } else {
        fwrite(STDOUT, sprintf("  %-30s : %s\n", $k, (string)$v));
    }
}
fwrite(STDOUT, "Report: {$reportPath}\n");

if ($strict && $overallSuccessRate < $minSuccessRate) {
    fwrite(
        STDERR,
        sprintf(
            "[phase5] Overall success rate %.2f%% is below required %.2f%%.\n",
            $overallSuccessRate,
            $minSuccessRate
        )
    );
    exit(2);
}

exit(0);
