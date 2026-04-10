<?php
// =============================================================================
//  CTI - HEADLESS CLI SCAN RUNNER
//  cti.php
//
//  Usage examples:
//    php cti.php -M
//    php cti.php -s example.com -t domain -u passive -o json
//    php cti.php -s example.com -t domain -m virustotal,alienvault -o csv --persist
// =============================================================================

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This script can only run from the command line.\n");
    exit(1);
}

if (!isset($_SERVER['HTTP_HOST'])) {
    $_SERVER['HTTP_HOST'] = 'localhost';
}
if (!isset($_SERVER['SERVER_NAME'])) {
    $_SERVER['SERVER_NAME'] = 'localhost';
}

require_once __DIR__ . '/php/config.php';
require_once __DIR__ . '/php/db.php';
require_once __DIR__ . '/php/GlobalSettings.php';
require_once __DIR__ . '/php/OsintEngine.php';
require_once __DIR__ . '/php/ScanExecutor.php';

const CTI_CLI_ALLOWED_TYPES = ['domain', 'ip', 'url', 'hash', 'email', 'cve', 'username', 'phone', 'bitcoin'];

/** @return array<string,mixed> */
function ctiCliOptions(): array
{
    return getopt(
        'hVMs:t:m:u:o:n:',
        ['help', 'version', 'modules', 'target:', 'type:', 'use-case:', 'output:', 'name:', 'persist', 'user-id:']
    ) ?: [];
}

function ctiCliUsage(): string
{
    return <<<TXT
CTI Platform CLI

Usage:
  php cti.php -s <target> -t <type> [-m module1,module2] [-u all|footprint|investigate|passive] [-o json|csv] [--persist] [--user-id N]
  php cti.php -M

Options:
  -h, --help           Show this help text
  -V, --version        Show app version
  -M, --modules        List enabled modules and exit
  -s, --target         Target indicator to scan
  -t, --type           Target type: domain, ip, url, hash, email, cve, username, phone, bitcoin
  -m                   Comma-separated module slugs to run
  -u, --use-case       Use-case preset: all, footprint, investigate, passive
  -o, --output         Output format: json or csv (default: json)
  -n, --name           Optional persisted scan name
      --persist        Save the run into scans/query_history before output
      --user-id        User ID to own the persisted scan (defaults to first admin)
TXT;
}

/** @return array<string,mixed> */
function ctiCliLoadModuleCatalog(): array
{
    $rows = DB::query(
        'SELECT slug, name, category, is_enabled FROM api_configs ORDER BY slug ASC'
    );

    $catalog = [];
    foreach ($rows as $row) {
        $slug = strtolower(trim((string)($row['slug'] ?? '')));
        if ($slug === '') {
            continue;
        }
        $catalog[$slug] = [
            'slug' => $slug,
            'name' => (string)($row['name'] ?? $slug),
            'category' => strtolower(trim((string)($row['category'] ?? ''))),
            'is_enabled' => !empty($row['is_enabled']),
        ];
    }

    return $catalog;
}

/** @return array<int,string> */
function ctiCliSelectModules(array $catalog, ?string $useCase, array $explicitSlugs): array
{
    $useCase = strtolower(trim((string)$useCase));
    $profiles = [
        'all' => null,
        'footprint' => ['dns', 'osint', 'infra', 'extract', 'tools'],
        'investigate' => ['threat', 'malware', 'network', 'blocklist', 'leaks'],
        'passive' => ['dns', 'osint', 'blocklist', 'leaks', 'identity'],
    ];

    if ($explicitSlugs !== []) {
        return array_values(array_filter(array_map(
            static fn($slug): string => strtolower(trim((string)$slug)),
            $explicitSlugs
        ), static fn(string $slug): bool => isset($catalog[$slug])));
    }

    $categories = $profiles[$useCase] ?? null;
    $selected = [];
    foreach ($catalog as $slug => $module) {
        if (empty($module['is_enabled'])) {
            continue;
        }
        if (is_array($categories) && !in_array($module['category'], $categories, true)) {
            continue;
        }
        $selected[] = $slug;
    }

    return $selected;
}

function ctiCliResolveUserId(?string $requestedUserId): int
{
    if ($requestedUserId !== null && ctype_digit($requestedUserId)) {
        $userId = (int)$requestedUserId;
        $row = DB::queryOne('SELECT id FROM users WHERE id = :id LIMIT 1', [':id' => $userId]);
        if ($row) {
            return $userId;
        }
    }

    $row = DB::queryOne(
        "SELECT u.id
           FROM users u
           JOIN roles r ON r.id = u.role_id
          WHERE r.name = 'admin'
          ORDER BY u.id ASC
          LIMIT 1"
    );
    if ($row) {
        return (int)$row['id'];
    }

    $row = DB::queryOne('SELECT id FROM users ORDER BY id ASC LIMIT 1');
    if ($row) {
        return (int)$row['id'];
    }

    throw new RuntimeException('No users found. Create an admin account before using --persist.');
}

function ctiCliTableExists(string $table): bool
{
    $row = DB::queryOne(
        "SELECT 1
           FROM information_schema.tables
          WHERE table_schema = :schema
            AND table_name = :table
          LIMIT 1",
        [':schema' => DB_NAME, ':table' => $table]
    );
    return $row !== null;
}

function ctiCliColumnExists(string $table, string $column): bool
{
    $row = DB::queryOne(
        "SELECT 1
           FROM information_schema.columns
          WHERE table_schema = :schema
            AND table_name = :table
            AND column_name = :column
          LIMIT 1",
        [':schema' => DB_NAME, ':table' => $table, ':column' => $column]
    );
    return $row !== null;
}

/** @return array<string,string> */
function ctiCliLoadKeyValueMap(string $table, string $keyColumn, string $valueColumn): array
{
    $map = [];
    if (!ctiCliTableExists($table)) {
        return $map;
    }

    foreach (DB::query("SELECT {$keyColumn}, {$valueColumn} FROM {$table}") as $row) {
        $map[(string)$row[$keyColumn]] = (string)($row[$valueColumn] ?? '');
    }
    return $map;
}

/** @return array<string,array<string,string>> */
function ctiCliLoadNestedSettingsMap(): array
{
    $map = [];
    if (!ctiCliTableExists('module_settings')) {
        return $map;
    }

    foreach (DB::query('SELECT module_slug, setting_key, setting_value FROM module_settings') as $row) {
        $slug = strtolower(trim((string)($row['module_slug'] ?? '')));
        $key = trim((string)($row['setting_key'] ?? ''));
        if ($slug === '' || $key === '') {
            continue;
        }
        if (!isset($map[$slug])) {
            $map[$slug] = [];
        }
        $map[$slug][$key] = (string)($row['setting_value'] ?? '');
    }

    return $map;
}

/** @return array<string,mixed> */
function ctiCliBuildSnapshot(string $scanName, string $queryType, string $queryValue, string $useCase, array $selectedModules): array
{
    $moduleSettings = [];
    $allModuleSettings = ctiCliLoadNestedSettingsMap();
    foreach ($selectedModules as $slug) {
        $normalized = strtolower(trim((string)$slug));
        if (isset($allModuleSettings[$normalized])) {
            $moduleSettings[$normalized] = $allModuleSettings[$normalized];
        }
    }

    return [
        'scan_name' => $scanName,
        'query_type' => $queryType,
        'query_value' => $queryValue,
        'use_case' => $useCase !== '' ? $useCase : 'custom',
        'selected_modules' => array_values($selectedModules),
        'module_count' => count($selectedModules),
        'mode' => 'cli',
        'source_scan_id' => null,
        'captured_at' => gmdate('c'),
        'global_settings' => ctiCliLoadKeyValueMap('platform_settings', 'setting_key', 'setting_value'),
        'module_settings' => $moduleSettings,
    ];
}

function ctiCliInsertScan(int $userId, string $scanName, string $queryValue, string $queryType, string $useCase, array $selectedModules): int
{
    $params = [
        ':uid' => $userId,
        ':name' => $scanName,
        ':target' => $queryValue,
        ':ttype' => $queryType,
        ':uc' => $useCase !== '' ? $useCase : null,
        ':mods' => json_encode(array_values($selectedModules), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    ];

    if (ctiCliColumnExists('scans', 'config_snapshot')) {
        return (int)DB::insert(
            "INSERT INTO scans (user_id, name, target, target_type, status, use_case, selected_modules, config_snapshot, started_at)
             VALUES (:uid, :name, :target, :ttype, 'starting', :uc, :mods, :snapshot, NOW())",
            $params + [
                ':snapshot' => json_encode(
                    ctiCliBuildSnapshot($scanName, $queryType, $queryValue, $useCase, $selectedModules),
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                ),
            ]
        );
    }

    return (int)DB::insert(
        "INSERT INTO scans (user_id, name, target, target_type, status, use_case, selected_modules, started_at)
         VALUES (:uid, :name, :target, :ttype, 'starting', :uc, :mods, NOW())",
        $params
    );
}

/** @param array<int,array<string,mixed>> $rows */
function ctiCliOutput(array $rows, string $format): void
{
    if ($format === 'csv') {
        $out = fopen('php://output', 'wb');
        fputcsv($out, ['api', 'api_name', 'query_type', 'query_value', 'score', 'severity', 'summary', 'enrichment_pass', 'source_ref', 'status']);
        foreach ($rows as $row) {
            fputcsv($out, [
                $row['api'] ?? $row['api_source'] ?? '',
                $row['api_name'] ?? '',
                $row['query_type'] ?? '',
                $row['query_value'] ?? '',
                $row['score'] ?? $row['risk_score'] ?? 0,
                $row['severity'] ?? '',
                $row['summary'] ?? $row['result_summary'] ?? '',
                $row['enrichment_pass'] ?? 0,
                $row['source_ref'] ?? 'ROOT',
                $row['status'] ?? '',
            ]);
        }
        fclose($out);
        return;
    }

    echo json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
}

$options = ctiCliOptions();

if (isset($options['h']) || isset($options['help'])) {
    echo ctiCliUsage() . PHP_EOL;
    exit(0);
}

if (isset($options['V']) || isset($options['version'])) {
    echo APP_NAME . ' ' . APP_VERSION . PHP_EOL;
    exit(0);
}

$catalog = ctiCliLoadModuleCatalog();
if (isset($options['M']) || isset($options['modules'])) {
    echo json_encode(array_values($catalog), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    exit(0);
}

$target = trim((string)($options['s'] ?? $options['target'] ?? ''));
$queryType = strtolower(trim((string)($options['t'] ?? $options['type'] ?? '')));
$useCase = strtolower(trim((string)($options['u'] ?? $options['use-case'] ?? 'all')));
$output = strtolower(trim((string)($options['o'] ?? $options['output'] ?? 'json')));
$scanName = trim((string)($options['n'] ?? $options['name'] ?? ''));
$persist = isset($options['persist']);
$explicitModules = array_values(array_filter(array_map('trim', explode(',', (string)($options['m'] ?? ''))), fn($value) => $value !== ''));

if ($target === '') {
    fwrite(STDERR, "Missing target. Use -s <target>.\n");
    exit(1);
}
if (!in_array($queryType, CTI_CLI_ALLOWED_TYPES, true)) {
    fwrite(STDERR, "Invalid target type. Use one of: " . implode(', ', CTI_CLI_ALLOWED_TYPES) . "\n");
    exit(1);
}
if (!in_array($output, ['json', 'csv'], true)) {
    fwrite(STDERR, "Invalid output format. Use json or csv.\n");
    exit(1);
}

$selectedModules = ctiCliSelectModules($catalog, $useCase, $explicitModules);
if ($selectedModules === []) {
    fwrite(STDERR, "No modules selected. Use -m or choose a use case with enabled modules.\n");
    exit(1);
}

$selectedModules = OsintEngine::sortSlugsByPriority($selectedModules, OsintEngine::loadApiConfigs($selectedModules));

if ($persist) {
    $userId = ctiCliResolveUserId(isset($options['user-id']) ? (string)$options['user-id'] : null);
    $finalScanName = $scanName !== '' ? $scanName : 'CLI Scan - ' . $target;
    $scanId = ctiCliInsertScan($userId, $finalScanName, $target, $queryType, $useCase, $selectedModules);
    DB::execute("UPDATE scans SET status = 'running' WHERE id = :id", [':id' => $scanId]);
    logScan($scanId, 'info', null, "CLI scan started for {$target} ({$queryType})");
    ScanExecutor::run($scanId, $userId, $queryType, $target, $selectedModules);

    $rows = DB::query(
        "SELECT qh.id,
                qh.query_type,
                qh.query_value,
                qh.api_source AS api,
                ac.name AS api_name,
                qh.risk_score AS score,
                qh.result_summary AS summary,
                qh.status,
                qh.enrichment_pass,
                qh.source_ref
           FROM query_history qh
           LEFT JOIN api_configs ac ON ac.slug = qh.api_source
          WHERE qh.scan_id = :sid
          ORDER BY qh.queried_at ASC, qh.id ASC",
        [':sid' => $scanId]
    );

    if ($output === 'json') {
        echo json_encode([
            'scan_id' => $scanId,
            'target' => $target,
            'query_type' => $queryType,
            'use_case' => $useCase,
            'selected_modules' => $selectedModules,
            'results' => $rows,
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
    } else {
        ctiCliOutput($rows, 'csv');
    }
    exit(0);
}

$results = OsintEngine::queryWithEnrichment($queryType, $target, $selectedModules, 0, null);
ctiCliOutput($results, $output);
exit(0);
