<?php
// =============================================================================
//  CTI — SCAN PARITY ENGINE
//  php/ScanParity.php
//
//  Implements the parity guarantee system:
//    1. Freeze all scan behavior per run (settings, module versions, endpoints)
//    2. Pin DNS resolution strategy (system, pinned resolver, DNS-over-HTTPS)
//    3. Time-lock live collection (strict window with per-call timestamps)
//    4. Deterministic transformation pipeline (normalize, sort, dedupe)
//    5. Wire up evidence collection to HttpClient
//
//  Two guarantee levels:
//    - Live Parity Mode: very high match via strict controls
//    - Replay Parity Mode: 100% reproducible from stored evidence (see ReplayEngine)
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/GlobalSettings.php';
require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/OsintEngine.php';
require_once __DIR__ . '/RawEvidenceStore.php';
require_once __DIR__ . '/HttpClient.php';

class ScanParity
{
    /** @var int Scan ID */
    private int $scanId;

    /** @var RawEvidenceStore Evidence store instance */
    private RawEvidenceStore $evidenceStore;

    /** @var string Microsecond-precision scan start timestamp */
    private string $scanStartTs;

    /** @var array Frozen global settings */
    private array $frozenGlobalSettings;

    /** @var array Frozen API configs for selected modules */
    private array $frozenApiConfigs;

    /** @var array Frozen module handler file hashes */
    private array $moduleVersions;

    /** @var array Frozen endpoint versions (slug → base_url) */
    private array $endpointVersions;

    /** @var array Deterministic module execution order */
    private array $moduleOrder;

    /** @var array Canonical type mapping table */
    private array $typeMappingTable;

    /** @var array Dedupe key rules */
    private array $dedupeKeys;

    /** @var array Normalization rules */
    private array $normalizationRules;

    /** @var string DNS strategy: 'system', 'pinned', 'doh' */
    private string $dnsStrategy;

    /** @var string|null Pinned DNS resolver IP */
    private ?string $dnsResolverIp;

    /** @var array DNS resolution cache built during scan */
    private array $dnsCache = [];

    /** @var bool Whether parity config table exists */
    private bool $parityTableExists;

    public function __construct(int $scanId)
    {
        $this->scanId = $scanId;
        $this->evidenceStore = new RawEvidenceStore($scanId);
        $this->scanStartTs = $this->microTimestamp();
        $this->parityTableExists = $this->tableExists('scan_parity_config');
    }

    // =========================================================================
    //  1. FREEZE SCAN BEHAVIOR
    // =========================================================================

    /**
     * Freeze all scan configuration at scan start.
     * Call this before any module execution begins.
     *
     * @param array $selectedSlugs Module slugs selected for this scan
     * @param array $apiConfigs    Loaded API configs for selected modules
     */
    public function freezeConfiguration(array $selectedSlugs, array $apiConfigs): void
    {
        // Record scan start timestamp
        $this->recordScanStartTs();

        // Freeze global settings snapshot
        GlobalSettings::load();
        $this->frozenGlobalSettings = GlobalSettings::all();

        // Freeze API configs
        $this->frozenApiConfigs = $apiConfigs;

        // Compute module handler file hashes
        $this->moduleVersions = $this->computeModuleVersions($selectedSlugs);

        // Freeze endpoint versions
        $this->endpointVersions = [];
        foreach ($apiConfigs as $slug => $config) {
            $this->endpointVersions[$slug] = [
                'base_url' => $config['base_url'] ?? '',
                'slug'     => $slug,
            ];
        }

        // Deterministic module execution order (priority, then category, then slug)
        $this->moduleOrder = OsintEngine::sortSlugsByPriority($selectedSlugs, $apiConfigs);

        // Freeze canonical type mapping table
        $this->typeMappingTable = $this->buildTypeMappingTable();

        // Freeze dedupe and normalization rules
        $this->dedupeKeys = $this->buildDedupeRules();
        $this->normalizationRules = $this->buildNormalizationRules();

        // DNS strategy
        $this->dnsStrategy = $this->frozenGlobalSettings['dns_resolver'] ?? '';
        if ($this->dnsStrategy !== '') {
            $this->dnsResolverIp = $this->dnsStrategy;
            $this->dnsStrategy = 'pinned';
        } else {
            $this->dnsResolverIp = null;
            $this->dnsStrategy = 'system';
        }

        // Wire up evidence collection to HttpClient
        $this->wireEvidenceCollection();

        // Persist parity config
        $this->saveFrozenConfig();
    }

    /**
     * Get the deterministic module execution order.
     * Modules are sorted by priority/category to match the live scheduler.
     */
    public function getModuleOrder(): array
    {
        return $this->moduleOrder;
    }

    /**
     * Get the evidence store instance.
     */
    public function getEvidenceStore(): RawEvidenceStore
    {
        return $this->evidenceStore;
    }

    // =========================================================================
    //  2. DNS RESOLUTION PINNING
    // =========================================================================

    /**
     * Resolve a hostname and cache the result.
     * Uses the pinned resolver strategy for consistency.
     *
     * @return array{ip: string, ttl: int, resolved_at: string}|null
     */
    public function resolveAndCache(string $hostname): ?array
    {
        if (isset($this->dnsCache[$hostname])) {
            return $this->dnsCache[$hostname];
        }

        $records = @dns_get_record($hostname, DNS_A);
        if (empty($records)) {
            return null;
        }

        $entry = [
            'ip'          => $records[0]['ip'] ?? '',
            'ttl'         => $records[0]['ttl'] ?? 0,
            'resolved_at' => $this->microTimestamp(),
        ];

        $this->dnsCache[$hostname] = $entry;
        return $entry;
    }

    /**
     * Get the full DNS cache built during the scan.
     */
    public function getDnsCache(): array
    {
        return $this->dnsCache;
    }

    // =========================================================================
    //  3. TIME-LOCK LIVE COLLECTION
    // =========================================================================

    /**
     * Get the scan start timestamp (microsecond precision).
     */
    public function getScanStartTs(): string
    {
        return $this->scanStartTs;
    }

    /**
     * Close the collection window (called when scan finishes).
     */
    public function closeCollectionWindow(): void
    {
        $windowEnd = $this->microTimestamp();

        if ($this->parityTableExists) {
            try {
                DB::execute(
                    "UPDATE scan_parity_config
                     SET scan_window_end = :end, dns_cache = :dns
                     WHERE scan_id = :sid",
                    [
                        ':end' => $windowEnd,
                        ':dns' => json_encode($this->dnsCache),
                        ':sid' => $this->scanId,
                    ]
                );
            } catch (\Throwable $e) {
                error_log("[ScanParity] Failed to close collection window: " . $e->getMessage());
            }
        }
    }

    // =========================================================================
    //  4. DETERMINISTIC TRANSFORMATION PIPELINE
    // =========================================================================

    /**
     * Normalize and sort results deterministically before counting.
     * This ensures Type, Unique, and Total are computed the same way every run.
     *
     * @param array $results Raw results from modules
     * @return array Normalized, sorted, deduplicated results
     */
    public static function normalizeResults(array $results): array
    {
        // Step 1: Normalize each result
        $normalized = array_map([self::class, 'normalizeResult'], $results);

        // Step 2: Sort deterministically (by api slug, then data_type, then summary hash)
        usort($normalized, function ($a, $b) {
            $cmp = strcmp($a['api'] ?? '', $b['api'] ?? '');
            if ($cmp !== 0) return $cmp;

            $cmp = strcmp($a['data_type'] ?? '', $b['data_type'] ?? '');
            if ($cmp !== 0) return $cmp;

            $cmp = ($a['enrichment_pass'] ?? 0) <=> ($b['enrichment_pass'] ?? 0);
            if ($cmp !== 0) return $cmp;

            return strcmp(
                self::resultDedupeKey($a),
                self::resultDedupeKey($b)
            );
        });

        // Step 3: Deduplicate using fixed dedupe keys
        $seen = [];
        $deduplicated = [];
        foreach ($normalized as $r) {
            $key = self::resultDedupeKey($r);
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $deduplicated[] = $r;
        }

        return $deduplicated;
    }

    /**
     * Normalize a single result for deterministic comparison.
     */
    public static function normalizeResult(array $result): array
    {
        // Normalize summary: collapse whitespace, trim, lowercase for comparison
        if (isset($result['summary'])) {
            $result['summary'] = trim($result['summary']);
        }

        // Normalize data_type to canonical form
        if (isset($result['data_type'])) {
            $result['data_type'] = trim($result['data_type']);
        }

        // Normalize tags: sort alphabetically, deduplicate
        if (isset($result['tags']) && is_array($result['tags'])) {
            $result['tags'] = array_values(array_unique($result['tags']));
            sort($result['tags']);
        }

        // Normalize discoveries: sort by type then value
        if (isset($result['discoveries']) && is_array($result['discoveries'])) {
            usort($result['discoveries'], function ($a, $b) {
                $cmp = strcmp($a['type'] ?? '', $b['type'] ?? '');
                return $cmp !== 0 ? $cmp : strcmp($a['value'] ?? '', $b['value'] ?? '');
            });
        }

        return $result;
    }

    /**
     * Compute a deterministic dedupe key for a result.
     * Uses the same fields as ScanExecutor::findingSignature but is static.
     */
    public static function resultDedupeKey(array $r): string
    {
        $summary = preg_replace('/\s+/', ' ', strtolower(trim($r['summary'] ?? ''))) ?: '';
        return hash('sha256', implode('|', [
            strtolower(trim($r['api'] ?? '')),
            strtolower(trim($r['query_type'] ?? '')),
            strtolower(trim($r['enriched_from'] ?? $r['query_value'] ?? '')),
            strtolower(trim($r['data_type'] ?? '')),
            $summary,
        ]));
    }

    /**
     * Compute Type/Unique/Total counts from normalized results.
     * Matches SpiderFoot's Browse tab counting logic.
     *
     * @return array{types: array<string, array{total: int, unique: int, values: string[]}>, total_elements: int, unique_elements: int}
     */
    public static function computeCounts(array $normalizedResults): array
    {
        $types = [];
        $uniqueKeys = [];

        foreach ($normalizedResults as $r) {
            if (!($r['success'] ?? true) || isset($r['error'])) {
                continue;
            }

            $dataType = $r['data_type'] ?? $r['query_type'] ?? 'Unknown';
            $value = $r['enriched_from'] ?? $r['summary'] ?? '';
            $dedupeKey = self::resultDedupeKey($r);

            if (!isset($types[$dataType])) {
                $types[$dataType] = ['total' => 0, 'unique' => 0, 'values' => []];
            }

            $types[$dataType]['total']++;

            if (!isset($uniqueKeys[$dedupeKey])) {
                $uniqueKeys[$dedupeKey] = true;
                $types[$dataType]['unique']++;
                $types[$dataType]['values'][] = $value;
            }
        }

        // Sort types alphabetically for deterministic output
        ksort($types);

        return [
            'types'           => $types,
            'total_elements'  => array_sum(array_column($types, 'total')),
            'unique_elements' => array_sum(array_column($types, 'unique')),
        ];
    }

    /**
     * Apply fixed "unresolved" rules — mark results that could not be verified.
     */
    public static function applyUnresolvedRules(array $results): array
    {
        foreach ($results as &$r) {
            if (($r['success'] ?? true) && ($r['score'] ?? 0) === 0 && ($r['confidence'] ?? 0) === 0) {
                $r['_unresolved'] = true;
            } else {
                $r['_unresolved'] = false;
            }
        }
        unset($r);
        return $results;
    }

    // =========================================================================
    //  INTERNAL: Wire evidence collection
    // =========================================================================

    /**
     * Wire the evidence store into HttpClient via callback.
     */
    private function wireEvidenceCollection(): void
    {
        $store = $this->evidenceStore;
        HttpClient::setEvidenceCallback(
            function (
                string  $moduleSlug,
                string  $method,
                string  $url,
                ?array  $requestParams,
                array   $requestHeaders,
                int     $httpStatus,
                string  $responseBody,
                int     $elapsedMs,
                ?string $error,
                ?string $paginationCursor,
                ?int    $pageNumber,
                int     $enrichmentPass,
                string  $sourceRef,
                ?string $dnsResolver,
                ?array  $dnsResponse
            ) use ($store): ?int {
                return $store->record(
                    $moduleSlug, $method, $url, $requestParams, $requestHeaders,
                    $httpStatus, $responseBody, $elapsedMs, $error,
                    $paginationCursor, $pageNumber, $enrichmentPass, $sourceRef,
                    $dnsResolver, $dnsResponse
                );
            }
        );
    }

    /**
     * Disconnect evidence collection (call when scan finishes).
     */
    public function disconnectEvidence(): void
    {
        HttpClient::setEvidenceCallback(null);
        HttpClient::setModuleContext('', 0, 'ROOT');
    }

    // =========================================================================
    //  INTERNAL: Persist frozen config
    // =========================================================================

    private function saveFrozenConfig(): void
    {
        if (!$this->parityTableExists) {
            return;
        }

        try {
            DB::execute(
                "INSERT INTO scan_parity_config
                    (scan_id, frozen_at, module_versions, endpoint_versions,
                     api_configs_snapshot, global_settings, dns_strategy,
                     dns_resolver_ip, dns_cache, module_execution_order,
                     type_mapping_table, dedupe_keys, normalization_rules,
                     scan_window_start)
                 VALUES
                    (:sid, NOW(6), :mod_ver, :ep_ver,
                     :api_snap, :global, :dns_strat,
                     :dns_ip, :dns_cache, :mod_order,
                     :type_map, :dedupe, :norm,
                     :window_start)
                 ON DUPLICATE KEY UPDATE
                     frozen_at = NOW(6),
                     module_versions = VALUES(module_versions),
                     endpoint_versions = VALUES(endpoint_versions),
                     api_configs_snapshot = VALUES(api_configs_snapshot),
                     global_settings = VALUES(global_settings),
                     dns_strategy = VALUES(dns_strategy),
                     dns_resolver_ip = VALUES(dns_resolver_ip),
                     dns_cache = VALUES(dns_cache),
                     module_execution_order = VALUES(module_execution_order),
                     type_mapping_table = VALUES(type_mapping_table),
                     dedupe_keys = VALUES(dedupe_keys),
                     normalization_rules = VALUES(normalization_rules),
                     scan_window_start = VALUES(scan_window_start)",
                [
                    ':sid'          => $this->scanId,
                    ':mod_ver'      => json_encode($this->moduleVersions),
                    ':ep_ver'       => json_encode($this->endpointVersions),
                    ':api_snap'     => json_encode($this->redactApiConfigs($this->frozenApiConfigs)),
                    ':global'       => json_encode($this->redactGlobalSettings($this->frozenGlobalSettings)),
                    ':dns_strat'    => $this->dnsStrategy,
                    ':dns_ip'       => $this->dnsResolverIp,
                    ':dns_cache'    => json_encode($this->dnsCache),
                    ':mod_order'    => json_encode($this->moduleOrder),
                    ':type_map'     => json_encode($this->typeMappingTable),
                    ':dedupe'       => json_encode($this->dedupeKeys),
                    ':norm'         => json_encode($this->normalizationRules),
                    ':window_start' => $this->scanStartTs,
                ]
            );
        } catch (\Throwable $e) {
            error_log("[ScanParity] Failed to save frozen config: " . $e->getMessage());
        }
    }

    private function recordScanStartTs(): void
    {
        try {
            if ($this->tableExists('scans') && $this->columnExists('scans', 'scan_start_ts')) {
                DB::execute(
                    "UPDATE scans SET scan_start_ts = :ts WHERE id = :id",
                    [':ts' => $this->scanStartTs, ':id' => $this->scanId]
                );
            }
        } catch (\Throwable $e) {
            error_log("[ScanParity] Failed to record scan start timestamp: " . $e->getMessage());
        }
    }

    // =========================================================================
    //  INTERNAL: Build frozen snapshots
    // =========================================================================

    private function computeModuleVersions(array $slugs): array
    {
        $versions = [];
        $modulesDir = __DIR__ . '/modules/';

        // Get handler map via reflection (OsintEngine::$handlerMap is private)
        foreach ($slugs as $slug) {
            $handlerFile = $modulesDir . ucfirst(
                str_replace(' ', '', ucwords(str_replace('-', ' ', $slug)))
            ) . 'Module.php';

            // Try common naming patterns
            $candidates = [
                $handlerFile,
                $modulesDir . $slug . '.php',
            ];

            foreach ($candidates as $path) {
                if (file_exists($path)) {
                    $versions[$slug] = [
                        'file' => basename($path),
                        'hash' => md5_file($path),
                        'size' => filesize($path),
                    ];
                    break;
                }
            }

            if (!isset($versions[$slug])) {
                $versions[$slug] = ['file' => 'unknown', 'hash' => '', 'size' => 0];
            }
        }

        return $versions;
    }

    private function buildTypeMappingTable(): array
    {
        $ref = new \ReflectionClass(EventTypes::class);
        $constants = $ref->getConstants();
        $mapping = [];

        foreach ($constants as $name => $value) {
            if (!is_string($value) || $name === 'ROOT') continue;
            $queryType = EventTypes::toQueryType($value);
            $mapping[$value] = [
                'constant'   => $name,
                'label'      => $value,
                'query_type' => $queryType,
                'enrichable' => EventTypes::isEnrichable($value),
            ];
        }

        ksort($mapping);
        return $mapping;
    }

    private function buildDedupeRules(): array
    {
        return [
            'method'     => 'sha256',
            'fields'     => ['api', 'query_type', 'query_value', 'data_type', 'summary'],
            'normalize'  => ['collapse_whitespace', 'lowercase', 'trim'],
            'separator'  => '|',
        ];
    }

    private function buildNormalizationRules(): array
    {
        return [
            'summary'     => ['trim', 'collapse_whitespace'],
            'data_type'   => ['trim'],
            'tags'        => ['sort', 'deduplicate'],
            'discoveries' => ['sort_by_type_value'],
            'sort_order'  => ['api', 'data_type', 'enrichment_pass', 'dedupe_key'],
        ];
    }

    private function redactApiConfigs(array $configs): array
    {
        $redacted = [];
        foreach ($configs as $slug => $config) {
            $copy = $config;
            if (isset($copy['api_key']) && $copy['api_key'] !== '') {
                $copy['api_key'] = '***' . substr($copy['api_key'], -4);
            }
            $redacted[$slug] = $copy;
        }
        return $redacted;
    }

    private function redactGlobalSettings(array $settings): array
    {
        $sensitive = ['socks_password', 'socks_username'];
        $redacted = $settings;
        foreach ($sensitive as $key) {
            if (isset($redacted[$key]) && $redacted[$key] !== '') {
                $redacted[$key] = '***REDACTED***';
            }
        }
        return $redacted;
    }

    // =========================================================================
    //  INTERNAL: Helpers
    // =========================================================================

    private function microTimestamp(): string
    {
        return (new \DateTime())->format('Y-m-d H:i:s.u');
    }

    private function tableExists(string $table): bool
    {
        try {
            if (function_exists('tableExists')) {
                return tableExists($table);
            }
            $result = DB::queryOne(
                "SELECT COUNT(*) AS n FROM information_schema.tables
                 WHERE table_schema = DATABASE() AND table_name = :t",
                [':t' => $table]
            );
            return (int)($result['n'] ?? 0) > 0;
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function columnExists(string $table, string $column): bool
    {
        try {
            if (function_exists('columnExists')) {
                return columnExists($table, $column);
            }
            $result = DB::queryOne(
                "SELECT COUNT(*) AS n FROM information_schema.columns
                 WHERE table_schema = DATABASE() AND table_name = :t AND column_name = :c",
                [':t' => $table, ':c' => $column]
            );
            return (int)($result['n'] ?? 0) > 0;
        } catch (\Throwable $e) {
            return false;
        }
    }

    // =========================================================================
    //  STATIC: Load frozen config for replay
    // =========================================================================

    /**
     * Load the frozen parity configuration for a completed scan.
     *
     * @return array|null Frozen config or null if not found
     */
    public static function loadFrozenConfig(int $scanId): ?array
    {
        try {
            $row = DB::queryOne(
                "SELECT * FROM scan_parity_config WHERE scan_id = :sid",
                [':sid' => $scanId]
            );
            if (!$row) return null;

            // Decode JSON fields
            foreach (['module_versions', 'endpoint_versions', 'api_configs_snapshot',
                       'global_settings', 'dns_cache', 'module_execution_order',
                       'type_mapping_table', 'dedupe_keys', 'normalization_rules'] as $field) {
                if (isset($row[$field]) && is_string($row[$field])) {
                    $row[$field] = json_decode($row[$field], true) ?? [];
                }
            }

            return $row;
        } catch (\Throwable $e) {
            error_log("[ScanParity] Failed to load frozen config for scan #{$scanId}: " . $e->getMessage());
            return null;
        }
    }
}
