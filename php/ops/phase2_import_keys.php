<?php
// =============================================================================
//  PHASE 2 OPS - API KEY MANIFEST IMPORTER
//  Imports Top-20 (or custom) API keys from a JSON manifest into api_configs.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase2_import_keys.php [--file=php/ops/phase2_key_manifest.example.json] [--apply] [--strict]

Options:
  --file=...   Path to JSON manifest (default: phase2_key_manifest.example.json)
  --apply      Persist key updates to api_configs (default is dry-run)
  --strict     Exit non-zero if any module is missing or any manifest item has no usable key
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$apply = ops_bool($args, 'apply', false);
$strict = ops_bool($args, 'strict', false);
$defaultFile = __DIR__ . '/phase2_key_manifest.example.json';
$fileArg = ops_str($args, 'file', $defaultFile);

if (!preg_match('/^[A-Za-z]:[\\\\\\/]/', $fileArg)) {
    $filePath = realpath(getcwd() . DIRECTORY_SEPARATOR . $fileArg) ?: realpath($fileArg);
} else {
    $filePath = realpath($fileArg);
}

if ($filePath === false || !is_file($filePath)) {
    fwrite(STDERR, "[phase2] Manifest file not found: {$fileArg}\n");
    exit(1);
}

$manifest = json_decode((string)file_get_contents($filePath), true);
if (!is_array($manifest)) {
    fwrite(STDERR, "[phase2] Invalid JSON manifest: {$filePath}\n");
    exit(1);
}

$items = $manifest['keys'] ?? $manifest;
if (!is_array($items)) {
    fwrite(STDERR, "[phase2] Manifest must contain a \"keys\" array.\n");
    exit(1);
}

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

$rows = DB::query(
    "SELECT slug, name, requires_key, is_enabled,
            (api_key IS NOT NULL AND api_key <> '') AS has_key
     FROM api_configs"
);
$configMap = [];
foreach ($rows as $row) {
    $configMap[(string)$row['slug']] = $row;
}

$isPlaceholder = static function (string $value): bool {
    $v = strtoupper(trim($value));
    if ($v === '') {
        return true;
    }
    if (str_starts_with($v, 'REPLACE_WITH_')) {
        return true;
    }
    if (str_contains($v, 'YOUR_') && str_contains($v, '_KEY')) {
        return true;
    }
    if ($v === 'CHANGEME' || $v === 'TODO') {
        return true;
    }
    return false;
};

$results = [];
$summary = [
    'items_total' => 0,
    'missing_slug' => 0,
    'invalid_entry' => 0,
    'skipped_no_key' => 0,
    'would_update' => 0,
    'updated' => 0,
];

fwrite(STDOUT, "Phase 2 API Key Manifest Importer\n");
fwrite(STDOUT, "Manifest: {$filePath}\n");
fwrite(STDOUT, "Mode    : " . ($apply ? 'APPLY' : 'DRY-RUN') . "\n\n");

foreach ($items as $idx => $item) {
    $summary['items_total']++;

    if (!is_array($item)) {
        $summary['invalid_entry']++;
        $results[] = [
            'index' => $idx,
            'status' => 'invalid',
            'reason' => 'Manifest entry is not an object.',
        ];
        fwrite(STDOUT, sprintf("[INVALID] index=%d (entry is not an object)\n", (int)$idx));
        continue;
    }

    $canonical = strtolower(trim((string)($item['canonical'] ?? $item['module'] ?? '')));
    $rawSlug = strtolower(trim((string)($item['slug'] ?? '')));
    $slug = $rawSlug !== '' ? $rawSlug : ($roadmapAliases[$canonical] ?? $canonical);
    $apiKey = trim((string)($item['api_key'] ?? ''));
    $enabled = array_key_exists('is_enabled', $item)
        ? (bool)$item['is_enabled']
        : (array_key_exists('enabled', $item) ? (bool)$item['enabled'] : true);

    if ($slug === '') {
        $summary['invalid_entry']++;
        $results[] = [
            'index' => $idx,
            'status' => 'invalid',
            'reason' => 'Missing canonical/module/slug fields.',
        ];
        fwrite(STDOUT, sprintf("[INVALID] index=%d (missing slug)\n", (int)$idx));
        continue;
    }

    if (!isset($configMap[$slug])) {
        $summary['missing_slug']++;
        $results[] = [
            'index' => $idx,
            'canonical' => $canonical,
            'slug' => $slug,
            'status' => 'missing',
            'reason' => 'Slug not found in api_configs.',
        ];
        fwrite(STDOUT, sprintf("[MISSING] %-16s -> %-16s\n", $canonical !== '' ? $canonical : $slug, $slug));
        continue;
    }

    if ($isPlaceholder($apiKey)) {
        $summary['skipped_no_key']++;
        $results[] = [
            'index' => $idx,
            'canonical' => $canonical,
            'slug' => $slug,
            'status' => 'skipped',
            'reason' => 'No usable API key value in manifest entry.',
        ];
        fwrite(STDOUT, sprintf("[SKIPPED] %-16s -> %-16s (no usable key)\n", $canonical !== '' ? $canonical : $slug, $slug));
        continue;
    }

    $masked = str_repeat('*', max(0, strlen($apiKey) - 4)) . substr($apiKey, -4);
    $action = $apply ? 'updated' : 'would_update';

    if ($apply) {
        DB::execute(
            "UPDATE api_configs
             SET api_key = :api_key, is_enabled = :enabled, updated_at = NOW()
             WHERE slug = :slug",
            [
                ':api_key' => $apiKey,
                ':enabled' => $enabled ? 1 : 0,
                ':slug' => $slug,
            ]
        );
        $summary['updated']++;
    } else {
        $summary['would_update']++;
    }

    $results[] = [
        'index' => $idx,
        'canonical' => $canonical,
        'slug' => $slug,
        'status' => $action,
        'enabled' => $enabled,
        'masked_key' => $masked,
    ];

    fwrite(
        STDOUT,
        sprintf(
            "[%s] %-16s -> %-16s key=%s enabled=%s\n",
            strtoupper($action),
            $canonical !== '' ? $canonical : $slug,
            $slug,
            $masked,
            $enabled ? 'yes' : 'no'
        )
    );
}

$report = [
    'generated_at_utc' => gmdate('c'),
    'manifest_path' => $filePath,
    'apply_mode' => $apply,
    'summary' => $summary,
    'results' => $results,
];

$reportPath = ops_write_json_report($report, 'phase2_key_import');
fwrite(STDOUT, "\nSummary:\n");
foreach ($summary as $k => $v) {
    fwrite(STDOUT, sprintf("  %-14s : %d\n", $k, $v));
}
fwrite(STDOUT, "Report: {$reportPath}\n");

if ($strict && ($summary['missing_slug'] > 0 || $summary['skipped_no_key'] > 0 || $summary['invalid_entry'] > 0)) {
    exit(2);
}

exit(0);
