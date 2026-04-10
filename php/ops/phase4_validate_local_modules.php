<?php
// =============================================================================
//  PHASE 4 OPS - LOCAL MODULE VALIDATION RUNNER
//  Executes upgraded local modules against known targets and records results.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase4_validate_local_modules.php [--config=php/ops/phase4_targets.json] [--strict]

Options:
  --config=...   Path to validation matrix JSON file
  --strict       Exit non-zero if any configured module fails
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$strict = ops_bool($args, 'strict', false);
$defaultConfig = __DIR__ . '/phase4_targets.json';
$configPathArg = ops_str($args, 'config', $defaultConfig);

if (!preg_match('/^[A-Za-z]:[\\\\\\/]/', $configPathArg)) {
    $configPath = realpath(getcwd() . DIRECTORY_SEPARATOR . $configPathArg) ?: realpath($configPathArg);
} else {
    $configPath = realpath($configPathArg);
}

if ($configPath === false || !is_file($configPath)) {
    fwrite(STDERR, "[phase4] Config not found: {$configPathArg}\n");
    exit(1);
}

$rawCfg = json_decode((string)file_get_contents($configPath), true);
if (!is_array($rawCfg)) {
    fwrite(STDERR, "[phase4] Invalid JSON in config: {$configPath}\n");
    exit(1);
}

$matrix = $rawCfg['module_matrix'] ?? [];
if (!is_array($matrix) || empty($matrix)) {
    fwrite(STDERR, "[phase4] module_matrix is empty in {$configPath}\n");
    exit(1);
}

$rows = DB::query(
    "SELECT slug, name, is_enabled, requires_key,
            (api_key IS NOT NULL AND api_key <> '') AS has_key
     FROM api_configs"
);
$configMap = [];
foreach ($rows as $row) {
    $configMap[(string)$row['slug']] = $row;
}

fwrite(STDOUT, "Phase 4 Local Module Validation\n");
fwrite(STDOUT, "Config: {$configPath}\n\n");

$results = [];
$summary = [
    'total' => count($matrix),
    'passed' => 0,
    'failed' => 0,
    'missing' => 0,
    'skipped' => 0,
];

foreach ($matrix as $entry) {
    if (!is_array($entry)) {
        continue;
    }

    $slug = (string)($entry['slug'] ?? '');
    $queryType = strtolower((string)($entry['query_type'] ?? 'domain'));
    $queryValue = (string)($entry['query_value'] ?? ops_pick_sample_target($queryType));

    if ($slug === '') {
        continue;
    }

    $cfg = $configMap[$slug] ?? null;
    if ($cfg === null) {
        $summary['missing']++;
        $results[] = [
            'slug' => $slug,
            'query_type' => $queryType,
            'query_value' => $queryValue,
            'status' => 'missing',
            'reason' => 'Module slug not found in api_configs.',
        ];
        fwrite(STDOUT, sprintf("[MISSING] %-18s (%s %s)\n", $slug, $queryType, $queryValue));
        continue;
    }

    $isEnabled = (int)$cfg['is_enabled'] === 1;
    $requiresKey = (int)$cfg['requires_key'] === 1;
    $hasKey = (int)$cfg['has_key'] === 1;

    if (!$isEnabled) {
        $summary['skipped']++;
        $results[] = [
            'slug' => $slug,
            'query_type' => $queryType,
            'query_value' => $queryValue,
            'status' => 'skipped',
            'reason' => 'Module is disabled.',
        ];
        fwrite(STDOUT, sprintf("[SKIPPED] %-18s (disabled)\n", $slug));
        continue;
    }

    if ($requiresKey && !$hasKey) {
        $summary['skipped']++;
        $results[] = [
            'slug' => $slug,
            'query_type' => $queryType,
            'query_value' => $queryValue,
            'status' => 'skipped',
            'reason' => 'Module requires key but no key is configured.',
        ];
        fwrite(STDOUT, sprintf("[SKIPPED] %-18s (missing key)\n", $slug));
        continue;
    }

    $started = microtime(true);
    $raw = OsintEngine::query($queryType, $queryValue, [$slug], 0, null);
    $elapsedMs = (int)round((microtime(true) - $started) * 1000);

    $successCount = 0;
    $bestScore = 0.0;
    $bestSeverity = 'unknown';
    $errors = [];
    foreach ($raw as $row) {
        if (($row['success'] ?? false) === true) {
            $successCount++;
            $score = (float)($row['score'] ?? 0);
            if ($score >= $bestScore) {
                $bestScore = $score;
                $bestSeverity = (string)($row['severity'] ?? 'unknown');
            }
        } else {
            $errors[] = (string)($row['error'] ?? $row['summary'] ?? 'unknown error');
        }
    }

    $status = $successCount > 0 ? 'passed' : 'failed';
    if ($status === 'passed') {
        $summary['passed']++;
    } else {
        $summary['failed']++;
    }

    $results[] = [
        'slug' => $slug,
        'query_type' => $queryType,
        'query_value' => $queryValue,
        'status' => $status,
        'elapsed_ms' => $elapsedMs,
        'result_count' => count($raw),
        'success_count' => $successCount,
        'best_score' => $bestScore,
        'best_severity' => $bestSeverity,
        'error_preview' => implode(' | ', array_slice($errors, 0, 2)),
    ];

    $detail = $status === 'passed'
        ? "success_count={$successCount}, best_severity={$bestSeverity}, score={$bestScore}"
        : (empty($errors) ? 'no successful result' : implode(' | ', array_slice($errors, 0, 1)));

    fwrite(
        STDOUT,
        sprintf(
            "[%s] %-18s %5dms (%s)\n",
            strtoupper($status),
            $slug,
            $elapsedMs,
            $detail
        )
    );
}

$report = [
    'generated_at_utc' => gmdate('c'),
    'config_path' => $configPath,
    'summary' => $summary,
    'results' => $results,
];

$reportPath = ops_write_json_report($report, 'phase4_local_validation');
fwrite(STDOUT, "\nSummary:\n");
foreach ($summary as $k => $v) {
    fwrite(STDOUT, sprintf("  %-8s : %d\n", $k, $v));
}
fwrite(STDOUT, "Report: {$reportPath}\n");

if ($strict && $summary['failed'] > 0) {
    exit(2);
}
exit(0);

