<?php
// =============================================================================
//  CTI - OPS BOOTSTRAP
//  Shared helpers for operational CLI scripts in php/ops/
// =============================================================================

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "[ops] This script must run from CLI.\n");
    exit(1);
}

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../GlobalSettings.php';
require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../OsintEngine.php';
require_once __DIR__ . '/../ScanExecutor.php';

/**
 * Parse CLI args into a simple key/value map.
 * Supports:
 *   --flag
 *   --key=value
 */
function ops_parse_args(array $argv): array
{
    $out = [];
    foreach (array_slice($argv, 1) as $arg) {
        if (!str_starts_with($arg, '--')) {
            continue;
        }

        $raw = substr($arg, 2);
        if ($raw === '') {
            continue;
        }

        $eqPos = strpos($raw, '=');
        if ($eqPos === false) {
            $out[$raw] = true;
            continue;
        }

        $key = substr($raw, 0, $eqPos);
        $val = substr($raw, $eqPos + 1);
        $out[$key] = $val;
    }

    return $out;
}

function ops_bool(array $args, string $key, bool $default = false): bool
{
    if (!array_key_exists($key, $args)) {
        return $default;
    }
    $val = $args[$key];
    if (is_bool($val)) {
        return $val;
    }
    $norm = strtolower(trim((string)$val));
    return in_array($norm, ['1', 'true', 'yes', 'on'], true);
}

function ops_int(array $args, string $key, int $default): int
{
    if (!array_key_exists($key, $args)) {
        return $default;
    }
    return (int)$args[$key];
}

function ops_str(array $args, string $key, string $default = ''): string
{
    if (!array_key_exists($key, $args)) {
        return $default;
    }
    return trim((string)$args[$key]);
}

function ops_csv_list(string $value): array
{
    if ($value === '') {
        return [];
    }
    $parts = array_map('trim', explode(',', $value));
    return array_values(array_filter($parts, static fn($v) => $v !== ''));
}

function ops_table_exists(string $table): bool
{
    try {
        $row = DB::queryOne(
            "SELECT 1 AS present
             FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = :table
             LIMIT 1",
            [':table' => $table]
        );
        return (bool)$row;
    } catch (Throwable $e) {
        return false;
    }
}

function ops_column_exists(string $table, string $column): bool
{
    try {
        $row = DB::queryOne(
            "SELECT 1 AS present
             FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE()
               AND TABLE_NAME = :table
               AND COLUMN_NAME = :column
             LIMIT 1",
            [':table' => $table, ':column' => $column]
        );
        return (bool)$row;
    } catch (Throwable $e) {
        return false;
    }
}

function ops_write_json_report(array $payload, string $prefix): string
{
    $dir = __DIR__ . '/reports';
    if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
        throw new RuntimeException("Unable to create report directory: {$dir}");
    }

    $ts = gmdate('Ymd_His');
    $path = $dir . '/' . $prefix . '_' . $ts . '.json';
    $encoded = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($encoded === false) {
        throw new RuntimeException('Failed to encode JSON report.');
    }
    file_put_contents($path, $encoded);
    return $path;
}

function ops_supported_types(array $apiConfigRow): array
{
    $raw = $apiConfigRow['supported_types'] ?? '[]';
    if (is_array($raw)) {
        return array_values(array_map('strval', $raw));
    }
    $decoded = json_decode((string)$raw, true);
    if (!is_array($decoded)) {
        return [];
    }
    return array_values(array_map('strval', $decoded));
}

function ops_pick_sample_target(string $queryType): string
{
    return match (strtolower($queryType)) {
        'ip' => '8.8.8.8',
        'url' => 'https://example.com',
        'hash' => '44d88612fea8a8f36de82e1278abb02f',
        'email' => 'test@example.com',
        'cve' => 'CVE-2021-44228',
        'phone' => '+12025550123',
        'username' => 'admin',
        'bitcoin' => '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        default => 'example.com',
    };
}

function ops_print_usage(string $usage): void
{
    fwrite(STDOUT, $usage . PHP_EOL);
}

