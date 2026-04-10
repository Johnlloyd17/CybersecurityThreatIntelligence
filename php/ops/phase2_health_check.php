<?php
// =============================================================================
//  PHASE 2 OPS - API HEALTH CHECK RUNNER
//  Runs health checks for Top-20 roadmap modules (or a custom slug list)
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase2_health_check.php [--top20] [--slugs=a,b,c] [--configured-only] [--strict]

Options:
  --top20            Use the roadmap Top-20 set (default when --slugs is omitted)
  --slugs=...        Comma-separated module slugs to check
  --configured-only  Skip key-required modules that do not have an API key configured
  --strict           Exit non-zero if any checked module is not healthy
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$configuredOnly = ops_bool($args, 'configured-only', false);
$strict = ops_bool($args, 'strict', false);

// Roadmap aliases: canonical name => actual platform slug
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

$roadmapNotes = [
    'alienvault-otx' => 'Mapped to platform slug "alienvault".',
    'malwarebazaar' => 'Mapped to platform slug "abuse-ch" (MalwareBazaar/ThreatFox endpoint family).',
    'hunter-io' => 'Mapped to platform slug "hunter".',
    'crtsh' => 'Mapped to platform slug "crt-sh".',
];

$customSlugs = ops_csv_list(ops_str($args, 'slugs', ''));
$targets = [];
if (!empty($customSlugs)) {
    foreach ($customSlugs as $slug) {
        $targets[] = ['canonical' => $slug, 'slug' => $slug, 'note' => ''];
    }
} else {
    foreach ($roadmapAliases as $canonical => $slug) {
        $targets[] = [
            'canonical' => $canonical,
            'slug' => $slug,
            'note' => $roadmapNotes[$canonical] ?? '',
        ];
    }
}

$rows = DB::query(
    "SELECT slug, name, requires_key, is_enabled,
            (api_key IS NOT NULL AND api_key <> '') AS has_key
     FROM api_configs"
);

$configMap = [];
foreach ($rows as $row) {
    $configMap[(string)$row['slug']] = $row;
}

$results = [];
$counts = [
    'healthy' => 0,
    'degraded' => 0,
    'down' => 0,
    'unknown' => 0,
    'missing' => 0,
    'skipped' => 0,
];

fwrite(STDOUT, "Phase 2 Health Check Runner\n");
fwrite(STDOUT, "Configured-only: " . ($configuredOnly ? 'yes' : 'no') . "\n\n");

foreach ($targets as $t) {
    $canonical = $t['canonical'];
    $slug = $t['slug'];
    $note = $t['note'];

    $cfg = $configMap[$slug] ?? null;
    if ($cfg === null) {
        $counts['missing']++;
        $results[] = [
            'canonical' => $canonical,
            'slug' => $slug,
            'status' => 'missing',
            'error' => 'Module slug not found in api_configs.',
            'latency_ms' => 0,
            'requires_key' => null,
            'has_key' => null,
            'is_enabled' => null,
            'note' => $note,
        ];
        fwrite(STDOUT, sprintf("[MISSING] %-16s -> %-14s %s\n", $canonical, $slug, $note));
        continue;
    }

    $requiresKey = (int)$cfg['requires_key'] === 1;
    $hasKey = (int)$cfg['has_key'] === 1;
    $isEnabled = (int)$cfg['is_enabled'] === 1;

    if ($configuredOnly && $requiresKey && !$hasKey) {
        $counts['skipped']++;
        $results[] = [
            'canonical' => $canonical,
            'slug' => $slug,
            'status' => 'skipped',
            'error' => 'Skipped because requires_key=1 and key is not configured.',
            'latency_ms' => 0,
            'requires_key' => $requiresKey,
            'has_key' => $hasKey,
            'is_enabled' => $isEnabled,
            'note' => $note,
        ];
        fwrite(STDOUT, sprintf("[SKIPPED] %-16s -> %-14s (missing key)\n", $canonical, $slug));
        continue;
    }

    $health = OsintEngine::healthCheck($slug);
    $status = (string)($health['status'] ?? 'unknown');
    $latency = (int)($health['latency_ms'] ?? 0);
    $error = (string)($health['error'] ?? '');

    if (!array_key_exists($status, $counts)) {
        $status = 'unknown';
    }
    $counts[$status]++;

    $results[] = [
        'canonical' => $canonical,
        'slug' => $slug,
        'status' => $status,
        'error' => $error,
        'latency_ms' => $latency,
        'requires_key' => $requiresKey,
        'has_key' => $hasKey,
        'is_enabled' => $isEnabled,
        'note' => $note,
    ];

    $errorSuffix = $error !== '' ? " | {$error}" : '';
    fwrite(
        STDOUT,
        sprintf(
            "[%s] %-16s -> %-14s %4dms%s\n",
            strtoupper($status),
            $canonical,
            $slug,
            $latency,
            $errorSuffix
        )
    );
}

$report = [
    'generated_at_utc' => gmdate('c'),
    'configured_only' => $configuredOnly,
    'strict_mode' => $strict,
    'summary' => $counts,
    'results' => $results,
];

$reportPath = ops_write_json_report($report, 'phase2_health_check');

fwrite(STDOUT, "\nSummary:\n");
foreach ($counts as $k => $v) {
    fwrite(STDOUT, sprintf("  %-8s : %d\n", $k, $v));
}
fwrite(STDOUT, "Report: {$reportPath}\n");

$failed = ($counts['down'] + $counts['degraded'] + $counts['unknown'] + $counts['missing']) > 0;
if ($strict && $failed) {
    exit(2);
}
exit(0);

