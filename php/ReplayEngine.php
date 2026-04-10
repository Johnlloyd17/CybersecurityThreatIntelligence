<?php
// =============================================================================
//  CTI — REPLAY PARITY ENGINE
//  php/ReplayEngine.php
//
//  Provides 100% reproducible scan results by re-running the entire
//  transformation pipeline against stored raw API responses (scan_evidence).
//
//  No live API calls are made — all data comes from the evidence table.
//  The frozen parity config (scan_parity_config) controls the transformation
//  rules so the output is byte-identical to the original scan.
//
//  Usage:
//    $replay = new ReplayEngine($originalScanId);
//    $result = $replay->replay($newScanId, $userId);
// =============================================================================

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/RawEvidenceStore.php';
require_once __DIR__ . '/ScanParity.php';
require_once __DIR__ . '/OsintResult.php';
require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/GlobalSettings.php';

class ReplayEngine
{
    /** @var int Source scan ID to replay from */
    private int $sourceScanId;

    /** @var array|null Frozen parity config from source scan */
    private ?array $frozenConfig;

    /** @var array Evidence rows from source scan */
    private array $evidence;

    public function __construct(int $sourceScanId)
    {
        $this->sourceScanId = $sourceScanId;
        $this->frozenConfig = ScanParity::loadFrozenConfig($sourceScanId);
        $this->evidence = RawEvidenceStore::loadForScan($sourceScanId);
    }

    /**
     * Check if this scan can be replayed.
     */
    public function canReplay(): array
    {
        $issues = [];

        if (empty($this->evidence)) {
            $issues[] = 'No evidence data found for source scan #' . $this->sourceScanId;
        }

        if ($this->frozenConfig === null) {
            $issues[] = 'No frozen parity config found for source scan #' . $this->sourceScanId
                      . '. The scan may pre-date the parity system.';
        }

        return [
            'can_replay' => empty($issues),
            'issues'     => $issues,
            'evidence_count' => count($this->evidence),
            'has_config'     => $this->frozenConfig !== null,
        ];
    }

    /**
     * Replay a scan from stored evidence.
     *
     * Creates a new scan record with parity_mode='replay', then processes
     * each evidence row through the module's response parser to produce
     * results identical to the original.
     *
     * @param int $newScanId Pre-created scan ID for the replay
     * @param int $userId    User performing the replay
     * @return array{success: bool, results: array, counts: array, errors: string[]}
     */
    public function replay(int $newScanId, int $userId): array
    {
        $errors = [];
        $allResults = [];

        if (empty($this->evidence)) {
            return [
                'success' => false,
                'results' => [],
                'counts'  => [],
                'errors'  => ['No evidence data available for replay.'],
            ];
        }

        // Group evidence by module slug, preserving call order
        $byModule = [];
        foreach ($this->evidence as $ev) {
            $slug = $ev['module_slug'] ?? 'unknown';
            $byModule[$slug][] = $ev;
        }

        // Use frozen module execution order if available
        $moduleOrder = $this->frozenConfig['module_execution_order'] ?? array_keys($byModule);

        // Process each module's evidence
        foreach ($moduleOrder as $slug) {
            if (!isset($byModule[$slug])) continue;

            $moduleEvidence = $byModule[$slug];

            foreach ($moduleEvidence as $ev) {
                $responseBody = $ev['response_body'] ?? '';
                $httpStatus   = (int)($ev['http_status'] ?? 0);
                $error        = $ev['error_message'] ?? null;
                $elapsedMs    = (int)($ev['elapsed_ms'] ?? 0);
                $enrichPass   = (int)($ev['enrichment_pass'] ?? 0);
                $sourceRef    = $ev['source_ref'] ?? 'ROOT';

                // Attempt to decode the response as JSON
                $jsonData = null;
                if ($responseBody !== '') {
                    $decoded = json_decode($responseBody, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        $jsonData = $decoded;
                    }
                }

                // Build a synthetic HttpClient response
                $httpResult = [
                    'status'     => $httpStatus,
                    'body'       => $responseBody,
                    'json'       => $jsonData,
                    'elapsed_ms' => $elapsedMs,
                    'error'      => $error,
                ];

                // Try to invoke the module's response parser
                $moduleResults = $this->parseModuleResponse($slug, $httpResult, $ev);

                if ($moduleResults === null) {
                    // Fallback: reconstruct a minimal result from evidence metadata
                    $result = $this->reconstructFromEvidence($slug, $ev);
                    $allResults[] = $result;
                } else {
                    foreach ($moduleResults as $r) {
                        $r['enrichment_pass'] = $enrichPass;
                        $r['source_ref'] = $sourceRef;
                        if ($enrichPass > 0) {
                            $r['enriched_from'] = $this->extractEnrichedFrom($ev);
                        }
                        $r['_evidence_id'] = (int)($ev['id'] ?? 0);
                        $r['_replayed'] = true;
                        $allResults[] = $r;
                    }
                }
            }
        }

        // Apply deterministic transformation pipeline
        $normalized = ScanParity::normalizeResults($allResults);
        $normalized = ScanParity::applyUnresolvedRules($normalized);
        $counts = ScanParity::computeCounts($normalized);

        // Persist results to query_history under the new scan ID
        $this->persistReplayResults($newScanId, $userId, $normalized);

        return [
            'success' => true,
            'results' => $normalized,
            'counts'  => $counts,
            'errors'  => $errors,
        ];
    }

    /**
     * Get replay metadata for display.
     */
    public function getReplayInfo(): array
    {
        $stats = RawEvidenceStore::getScanStats($this->sourceScanId);

        return [
            'source_scan_id'  => $this->sourceScanId,
            'evidence_count'  => count($this->evidence),
            'has_frozen_config' => $this->frozenConfig !== null,
            'evidence_stats'  => $stats,
            'frozen_config'   => $this->frozenConfig ? [
                'frozen_at'          => $this->frozenConfig['frozen_at'] ?? null,
                'dns_strategy'       => $this->frozenConfig['dns_strategy'] ?? null,
                'module_count'       => count($this->frozenConfig['module_execution_order'] ?? []),
                'scan_window_start'  => $this->frozenConfig['scan_window_start'] ?? null,
                'scan_window_end'    => $this->frozenConfig['scan_window_end'] ?? null,
            ] : null,
        ];
    }

    // =========================================================================
    //  INTERNAL: Module response parsing
    // =========================================================================

    /**
     * Attempt to invoke a module's response parser against stored evidence.
     *
     * @return array|null Array of result arrays, or null if parsing not possible
     */
    private function parseModuleResponse(string $slug, array $httpResult, array $evidence): ?array
    {
        // Load the module handler if available
        $handlerFile = $this->resolveHandlerFile($slug);
        if (!$handlerFile || !file_exists($handlerFile)) {
            return null;
        }

        try {
            require_once $handlerFile;
            $className = $this->slugToClassName($slug);

            if (!class_exists($className)) {
                return null;
            }

            // Check if the module has a static parseResponse method (replay-friendly)
            if (method_exists($className, 'parseResponse')) {
                $results = $className::parseResponse($httpResult, $slug);
                return $this->ensureResultArrayFormat($results, $slug);
            }

            return null;
        } catch (\Throwable $e) {
            error_log("[ReplayEngine] Failed to parse response for {$slug}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Reconstruct a minimal result from evidence metadata when module parsing
     * is not available.
     */
    private function reconstructFromEvidence(string $slug, array $evidence): array
    {
        $httpStatus = (int)($evidence['http_status'] ?? 0);
        $error = $evidence['error_message'] ?? null;
        $responseBody = $evidence['response_body'] ?? '';
        $jsonData = json_decode($responseBody, true);

        $isSuccess = $httpStatus >= 200 && $httpStatus < 300 && $error === null;

        return [
            'api'             => $slug,
            'api_name'        => $slug,
            'score'           => 0,
            'severity'        => $isSuccess ? 'info' : 'unknown',
            'confidence'      => 0,
            'response_ms'     => (int)($evidence['elapsed_ms'] ?? 0),
            'summary'         => $isSuccess
                ? "Replayed from evidence (raw response available)"
                : "Error during original scan: " . ($error ?? "HTTP {$httpStatus}"),
            'tags'            => [$slug, 'replayed'],
            'success'         => $isSuccess,
            'error'           => $error,
            'data_type'       => null,
            'enrichment_pass' => (int)($evidence['enrichment_pass'] ?? 0),
            'source_ref'      => $evidence['source_ref'] ?? 'ROOT',
            '_evidence_id'    => (int)($evidence['id'] ?? 0),
            '_replayed'       => true,
            '_raw_available'  => true,
        ];
    }

    /**
     * Persist replay results to query_history.
     */
    private function persistReplayResults(int $scanId, int $userId, array $results): void
    {
        foreach ($results as $r) {
            $isError = !($r['success'] ?? true) || isset($r['error']);
            $queryType = $r['query_type'] ?? 'unknown';
            $queryValue = $r['enriched_from'] ?? $r['query_value'] ?? '';

            try {
                DB::execute(
                    "INSERT INTO query_history
                        (user_id, scan_id, query_type, query_value, api_source, data_type,
                         result_summary, risk_score, status, response_time,
                         enrichment_pass, source_ref, enriched_from, evidence_id)
                     VALUES (:uid, :sid, :qt, :qv, :api, :dt,
                             :summary, :score, :status, :resp,
                             :epass, :sref, :efrom, :eid)",
                    [
                        ':uid'     => $userId,
                        ':sid'     => $scanId,
                        ':qt'      => $queryType,
                        ':qv'      => $queryValue,
                        ':api'     => $r['api'] ?? '',
                        ':dt'      => $r['data_type'] ?? null,
                        ':summary' => $r['summary'] ?? '',
                        ':score'   => $r['score'] ?? 0,
                        ':status'  => $isError ? 'failed' : 'completed',
                        ':resp'    => $r['response_ms'] ?? 0,
                        ':epass'   => $r['enrichment_pass'] ?? 0,
                        ':sref'    => $r['source_ref'] ?? 'ROOT',
                        ':efrom'   => $r['enriched_from'] ?? null,
                        ':eid'     => $r['_evidence_id'] ?? null,
                    ]
                );
            } catch (\Throwable $e) {
                error_log("[ReplayEngine] Failed to persist replay result: " . $e->getMessage());
            }
        }
    }

    // =========================================================================
    //  INTERNAL: Helpers
    // =========================================================================

    private function resolveHandlerFile(string $slug): ?string
    {
        $modulesDir = __DIR__ . '/modules/';

        // Try the standard naming convention
        $parts = explode('-', $slug);
        $className = implode('', array_map('ucfirst', $parts)) . 'Module.php';
        $path = $modulesDir . $className;

        if (file_exists($path)) {
            return $path;
        }

        // Try DnsblModule for DNSBL slugs
        $dnsblSlugs = ['sorbs', 'spamcop', 'spamhaus-zen', 'uceprotect', 'dronebl', 'surbl'];
        if (in_array($slug, $dnsblSlugs, true)) {
            $path = $modulesDir . 'DnsblModule.php';
            if (file_exists($path)) return $path;
        }

        return null;
    }

    private function slugToClassName(string $slug): string
    {
        $parts = explode('-', $slug);
        return implode('', array_map('ucfirst', $parts)) . 'Module';
    }

    private function extractEnrichedFrom(array $evidence): ?string
    {
        $url = $evidence['endpoint_url'] ?? '';
        // Try to extract the query target from the URL
        if (preg_match('/(?:ip_addresses|hosts?|domain)\/([^\/\?]+)/', $url, $m)) {
            return urldecode($m[1]);
        }
        return null;
    }

    private function ensureResultArrayFormat($results, string $slug): array
    {
        if (!is_array($results)) return [];

        $formatted = [];
        foreach ((array)$results as $r) {
            if ($r instanceof OsintResult) {
                $formatted[] = $r->toArray();
            } elseif (is_array($r)) {
                $formatted[] = $r;
            }
        }

        return $formatted;
    }
}
