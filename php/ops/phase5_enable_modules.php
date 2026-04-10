<?php
// =============================================================================
//  PHASE 5 OPS - PRODUCTION MODULE ENABLEMENT
//  Enables modules in api_configs with safety filters.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase5_enable_modules.php [--slugs=a,b,c] [--all] [--allow-missing-key] [--allow-empty-base-url] [--apply] [--strict]

Options:
  --slugs=...             Optional comma-separated slug subset
  --all                   Ignore safety filters and enable all selected rows
  --allow-missing-key     Allow enabling modules that require key but have no key
  --allow-empty-base-url  Allow enabling modules with empty base_url
  --apply                 Persist changes (default is dry-run)
  --strict                Exit non-zero if any selected module is skipped
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$apply = ops_bool($args, 'apply', false);
$strict = ops_bool($args, 'strict', false);
$forceAll = ops_bool($args, 'all', false);
$allowMissingKey = ops_bool($args, 'allow-missing-key', false) || $forceAll;
$allowEmptyBaseUrl = ops_bool($args, 'allow-empty-base-url', false) || $forceAll;
$slugFilter = array_flip(ops_csv_list(strtolower(ops_str($args, 'slugs', ''))));

$rows = DB::query(
    "SELECT slug, name, is_enabled, requires_key, base_url,
            (api_key IS NOT NULL AND api_key <> '') AS has_key
     FROM api_configs
     ORDER BY slug"
);

if (empty($rows)) {
    fwrite(STDERR, "[phase5] No rows found in api_configs.\n");
    exit(1);
}

$summary = [
    'selected' => 0,
    'already_enabled' => 0,
    'eligible_disabled' => 0,
    'would_enable' => 0,
    'enabled' => 0,
    'skipped' => 0,
];
$results = [];
$toEnable = [];

fwrite(STDOUT, "Phase 5 Module Enablement\n");
fwrite(STDOUT, "Mode                 : " . ($apply ? 'APPLY' : 'DRY-RUN') . "\n");
fwrite(STDOUT, "Force all            : " . ($forceAll ? 'yes' : 'no') . "\n");
fwrite(STDOUT, "Allow missing key    : " . ($allowMissingKey ? 'yes' : 'no') . "\n");
fwrite(STDOUT, "Allow empty base_url : " . ($allowEmptyBaseUrl ? 'yes' : 'no') . "\n\n");

foreach ($rows as $row) {
    $slug = (string)$row['slug'];
    if (!empty($slugFilter) && !isset($slugFilter[strtolower($slug)])) {
        continue;
    }

    $summary['selected']++;
    $isEnabled = (int)$row['is_enabled'] === 1;
    $requiresKey = (int)$row['requires_key'] === 1;
    $hasKey = (int)$row['has_key'] === 1;
    $baseUrl = trim((string)($row['base_url'] ?? ''));

    if (!$forceAll) {
        if (!$allowEmptyBaseUrl && $baseUrl === '') {
            $summary['skipped']++;
            $results[] = [
                'slug' => $slug,
                'status' => 'skipped',
                'reason' => 'Empty base_url.',
            ];
            fwrite(STDOUT, sprintf("[SKIPPED] %-20s (empty base_url)\n", $slug));
            continue;
        }

        if (!$allowMissingKey && $requiresKey && !$hasKey) {
            $summary['skipped']++;
            $results[] = [
                'slug' => $slug,
                'status' => 'skipped',
                'reason' => 'Requires API key but no key configured.',
            ];
            fwrite(STDOUT, sprintf("[SKIPPED] %-20s (missing key)\n", $slug));
            continue;
        }
    }

    if ($isEnabled) {
        $summary['already_enabled']++;
        $results[] = [
            'slug' => $slug,
            'status' => 'already_enabled',
            'reason' => '',
        ];
        fwrite(STDOUT, sprintf("[UNCHANGED] %-20s already enabled\n", $slug));
        continue;
    }

    $summary['eligible_disabled']++;
    if ($apply) {
        $toEnable[] = $slug;
        $summary['enabled']++;
        $results[] = [
            'slug' => $slug,
            'status' => 'enabled',
            'reason' => '',
        ];
        fwrite(STDOUT, sprintf("[ENABLED] %-20s\n", $slug));
    } else {
        $summary['would_enable']++;
        $results[] = [
            'slug' => $slug,
            'status' => 'would_enable',
            'reason' => '',
        ];
        fwrite(STDOUT, sprintf("[WOULD_ENABLE] %-20s\n", $slug));
    }
}

if ($apply && !empty($toEnable)) {
    DB::transaction(static function () use ($toEnable): void {
        foreach ($toEnable as $slug) {
            DB::execute(
                "UPDATE api_configs SET is_enabled = 1, updated_at = NOW() WHERE slug = :slug",
                [':slug' => $slug]
            );
        }
    });
}

$report = [
    'generated_at_utc' => gmdate('c'),
    'apply_mode' => $apply,
    'force_all' => $forceAll,
    'allow_missing_key' => $allowMissingKey,
    'allow_empty_base_url' => $allowEmptyBaseUrl,
    'summary' => $summary,
    'results' => $results,
];
$reportPath = ops_write_json_report($report, 'phase5_enable_modules');

fwrite(STDOUT, "\nSummary:\n");
foreach ($summary as $k => $v) {
    fwrite(STDOUT, sprintf("  %-18s : %d\n", $k, $v));
}
fwrite(STDOUT, "Report: {$reportPath}\n");

if ($strict && $summary['skipped'] > 0) {
    exit(2);
}

exit(0);
