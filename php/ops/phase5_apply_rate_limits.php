<?php
// =============================================================================
//  PHASE 5 OPS - RATE LIMIT PROFILE APPLIER
//  Applies a baseline rate-limit profile to api_configs.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase5_apply_rate_limits.php [--profile=php/ops/phase5_rate_limits_profile.json] [--apply] [--slugs=a,b,c] [--strict]

Options:
  --profile=...  Path to rate-limit profile JSON
  --apply        Persist changes (default is dry-run)
  --slugs=...    Optional comma-separated slug subset
  --strict       Exit non-zero if any selected slug cannot be evaluated
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$apply = ops_bool($args, 'apply', false);
$strict = ops_bool($args, 'strict', false);
$slugFilter = array_flip(ops_csv_list(strtolower(ops_str($args, 'slugs', ''))));
$defaultProfile = __DIR__ . '/phase5_rate_limits_profile.json';
$profileArg = ops_str($args, 'profile', $defaultProfile);

if (!preg_match('/^[A-Za-z]:[\\\\\\/]/', $profileArg)) {
    $profilePath = realpath(getcwd() . DIRECTORY_SEPARATOR . $profileArg) ?: realpath($profileArg);
} else {
    $profilePath = realpath($profileArg);
}

if ($profilePath === false || !is_file($profilePath)) {
    fwrite(STDERR, "[phase5] Rate-limit profile not found: {$profileArg}\n");
    exit(1);
}

$profile = json_decode((string)file_get_contents($profilePath), true);
if (!is_array($profile)) {
    fwrite(STDERR, "[phase5] Invalid profile JSON: {$profilePath}\n");
    exit(1);
}

$defaults = is_array($profile['defaults'] ?? null) ? $profile['defaults'] : [];
$categoryDefaults = is_array($profile['category_defaults'] ?? null) ? $profile['category_defaults'] : [];
$overrides = is_array($profile['overrides'] ?? null) ? $profile['overrides'] : [];
$minRate = (int)($profile['min_rate'] ?? 1);
$maxRate = (int)($profile['max_rate'] ?? 300);

$rows = DB::query(
    "SELECT slug, name, category, base_url, requires_key, rate_limit
     FROM api_configs
     ORDER BY slug"
);

if (empty($rows)) {
    fwrite(STDERR, "[phase5] No rows found in api_configs.\n");
    exit(1);
}

$computeTarget = static function (array $row) use ($overrides, $categoryDefaults, $defaults, $minRate, $maxRate): ?int {
    $slug = strtolower((string)($row['slug'] ?? ''));
    $category = strtolower((string)($row['category'] ?? ''));
    $baseUrl = strtolower((string)($row['base_url'] ?? ''));
    $requiresKey = (int)($row['requires_key'] ?? 0) === 1;

    $target = null;

    if (array_key_exists($slug, $overrides)) {
        $target = (int)$overrides[$slug];
    } elseif (str_starts_with($baseUrl, 'local://') && array_key_exists('local', $defaults)) {
        $target = (int)$defaults['local'];
    } elseif ($category !== '' && array_key_exists($category, $categoryDefaults)) {
        $target = (int)$categoryDefaults[$category];
    } elseif ($requiresKey && array_key_exists('requires_key', $defaults)) {
        $target = (int)$defaults['requires_key'];
    } elseif (array_key_exists('no_key', $defaults)) {
        $target = (int)$defaults['no_key'];
    }

    if ($target === null) {
        return null;
    }

    if ($target < $minRate) {
        $target = $minRate;
    }
    if ($target > $maxRate) {
        $target = $maxRate;
    }
    return $target;
};

$summary = [
    'selected' => 0,
    'evaluated' => 0,
    'unchanged' => 0,
    'would_update' => 0,
    'updated' => 0,
    'unresolved' => 0,
];
$results = [];
$updates = [];

fwrite(STDOUT, "Phase 5 Rate Limit Profile Applier\n");
fwrite(STDOUT, "Profile: {$profilePath}\n");
fwrite(STDOUT, "Mode   : " . ($apply ? 'APPLY' : 'DRY-RUN') . "\n\n");

foreach ($rows as $row) {
    $slug = (string)$row['slug'];
    if (!empty($slugFilter) && !isset($slugFilter[strtolower($slug)])) {
        continue;
    }

    $summary['selected']++;
    $current = (int)($row['rate_limit'] ?? 0);
    $target = $computeTarget($row);

    if ($target === null) {
        $summary['unresolved']++;
        $results[] = [
            'slug' => $slug,
            'status' => 'unresolved',
            'current_rate_limit' => $current,
            'target_rate_limit' => null,
        ];
        fwrite(STDOUT, sprintf("[UNRESOLVED] %-20s current=%d\n", $slug, $current));
        continue;
    }

    $summary['evaluated']++;
    if ($current === $target) {
        $summary['unchanged']++;
        $results[] = [
            'slug' => $slug,
            'status' => 'unchanged',
            'current_rate_limit' => $current,
            'target_rate_limit' => $target,
        ];
        fwrite(STDOUT, sprintf("[UNCHANGED] %-20s rate=%d\n", $slug, $current));
        continue;
    }

    $status = $apply ? 'updated' : 'would_update';
    if ($apply) {
        $updates[] = ['slug' => $slug, 'target' => $target];
        $summary['updated']++;
    } else {
        $summary['would_update']++;
    }

    $results[] = [
        'slug' => $slug,
        'status' => $status,
        'current_rate_limit' => $current,
        'target_rate_limit' => $target,
    ];

    fwrite(STDOUT, sprintf("[%s] %-20s %d -> %d\n", strtoupper($status), $slug, $current, $target));
}

if ($apply && !empty($updates)) {
    DB::transaction(static function () use ($updates): void {
        foreach ($updates as $u) {
            DB::execute(
                "UPDATE api_configs
                 SET rate_limit = :rate_limit, updated_at = NOW()
                 WHERE slug = :slug",
                [
                    ':rate_limit' => (int)$u['target'],
                    ':slug' => (string)$u['slug'],
                ]
            );
        }
    });
}

$report = [
    'generated_at_utc' => gmdate('c'),
    'profile_path' => $profilePath,
    'apply_mode' => $apply,
    'summary' => $summary,
    'results' => $results,
];
$reportPath = ops_write_json_report($report, 'phase5_rate_limits');

fwrite(STDOUT, "\nSummary:\n");
foreach ($summary as $k => $v) {
    fwrite(STDOUT, sprintf("  %-12s : %d\n", $k, $v));
}
fwrite(STDOUT, "Report: {$reportPath}\n");

if ($strict && $summary['unresolved'] > 0) {
    exit(2);
}

exit(0);
