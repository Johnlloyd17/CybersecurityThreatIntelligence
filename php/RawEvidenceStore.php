<?php
// =============================================================================
//  CTI — RAW EVIDENCE STORE
//  php/RawEvidenceStore.php
//
//  Records every outbound API call made during a scan: endpoint, params,
//  status, response body hash, full payload, pagination cursors, and DNS
//  resolution data.  Used by the Parity System for:
//    - Audit trail of exactly what data was collected
//    - Replay Parity Mode (re-run from stored snapshots)
//    - SpiderFoot diff validation (trace where differences originate)
// =============================================================================

require_once __DIR__ . '/db.php';

class RawEvidenceStore
{
    /** @var int Current scan ID */
    private int $scanId;

    /** @var int Auto-incrementing call order counter for deterministic ordering */
    private int $callOrder = 0;

    /** @var bool Whether evidence storage is enabled (table must exist) */
    private bool $enabled;

    /** @var array Headers that should be redacted in stored evidence */
    private const REDACT_HEADERS = ['x-apikey', 'authorization', 'api-key', 'x-api-key', 'key'];

    public function __construct(int $scanId)
    {
        $this->scanId = $scanId;
        $this->enabled = $this->tableExists();
    }

    /**
     * Record a single outbound API call and its response.
     *
     * @param string      $moduleSlug     Module that made the call
     * @param string      $method         HTTP method (GET, POST, etc.)
     * @param string      $url            Full request URL
     * @param array|null  $requestParams  POST body or structured params
     * @param array       $requestHeaders Outbound headers (will be redacted)
     * @param int         $httpStatus     HTTP response status code
     * @param string      $responseBody   Raw response body
     * @param int         $elapsedMs      Response time in milliseconds
     * @param string|null $error          Error message if any
     * @param string|null $paginationCursor Pagination cursor/token
     * @param int|null    $pageNumber     Page number for paginated results
     * @param int         $enrichmentPass Enrichment pass number
     * @param string      $sourceRef      Source reference for enrichment chain
     * @param string|null $dnsResolver    DNS resolver used
     * @param array|null  $dnsResponse    DNS resolution result
     * @return int|null   The evidence row ID, or null if storage failed/disabled
     */
    public function record(
        string  $moduleSlug,
        string  $method,
        string  $url,
        ?array  $requestParams,
        array   $requestHeaders,
        int     $httpStatus,
        string  $responseBody,
        int     $elapsedMs,
        ?string $error = null,
        ?string $paginationCursor = null,
        ?int    $pageNumber = null,
        int     $enrichmentPass = 0,
        string  $sourceRef = 'ROOT',
        ?string $dnsResolver = null,
        ?array  $dnsResponse = null
    ): ?int {
        if (!$this->enabled) {
            return null;
        }

        $this->callOrder++;
        $responseHash = hash('sha256', $responseBody);
        $responseSize = strlen($responseBody);
        $redactedHeaders = $this->redactHeaders($requestHeaders);

        try {
            DB::execute(
                "INSERT INTO scan_evidence
                    (scan_id, module_slug, call_order, http_method, endpoint_url,
                     request_params, request_headers, http_status, response_hash,
                     response_body, response_size, elapsed_ms, error_message,
                     pagination_cursor, page_number, enrichment_pass, source_ref,
                     dns_resolver, dns_response, called_at)
                 VALUES
                    (:scan_id, :slug, :call_order, :method, :url,
                     :params, :headers, :status, :hash,
                     :body, :size, :elapsed, :error,
                     :cursor, :page, :epass, :sref,
                     :dns_resolver, :dns_response, NOW(6))",
                [
                    ':scan_id'      => $this->scanId,
                    ':slug'         => $moduleSlug,
                    ':call_order'   => $this->callOrder,
                    ':method'       => strtoupper($method),
                    ':url'          => $url,
                    ':params'       => $requestParams !== null ? json_encode($requestParams) : null,
                    ':headers'      => json_encode($redactedHeaders),
                    ':status'       => $httpStatus,
                    ':hash'         => $responseHash,
                    ':body'         => $responseBody,
                    ':size'         => $responseSize,
                    ':elapsed'      => $elapsedMs,
                    ':error'        => $error,
                    ':cursor'       => $paginationCursor,
                    ':page'         => $pageNumber,
                    ':epass'        => $enrichmentPass,
                    ':sref'         => $sourceRef,
                    ':dns_resolver' => $dnsResolver,
                    ':dns_response' => $dnsResponse !== null ? json_encode($dnsResponse) : null,
                ]
            );

            return (int)DB::connect()->lastInsertId();
        } catch (\Throwable $e) {
            error_log("[RawEvidenceStore] Failed to record evidence for {$moduleSlug}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Load all evidence rows for a scan (used by ReplayEngine).
     *
     * @return array Evidence rows ordered by call_order
     */
    public static function loadForScan(int $scanId): array
    {
        try {
            return DB::query(
                "SELECT * FROM scan_evidence
                 WHERE scan_id = :sid
                 ORDER BY call_order ASC",
                [':sid' => $scanId]
            );
        } catch (\Throwable $e) {
            error_log("[RawEvidenceStore] Failed to load evidence for scan #{$scanId}: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Load evidence for a specific module within a scan.
     */
    public static function loadForModule(int $scanId, string $moduleSlug): array
    {
        try {
            return DB::query(
                "SELECT * FROM scan_evidence
                 WHERE scan_id = :sid AND module_slug = :slug
                 ORDER BY call_order ASC",
                [':sid' => $scanId, ':slug' => $moduleSlug]
            );
        } catch (\Throwable $e) {
            error_log("[RawEvidenceStore] Failed to load module evidence: " . $e->getMessage());
            return [];
        }
    }

    /**
     * Get evidence summary statistics for a scan.
     */
    public static function getScanStats(int $scanId): array
    {
        try {
            $row = DB::queryOne(
                "SELECT
                    COUNT(*) AS total_calls,
                    COUNT(DISTINCT module_slug) AS modules_called,
                    SUM(response_size) AS total_response_bytes,
                    AVG(elapsed_ms) AS avg_response_ms,
                    MIN(called_at) AS first_call_at,
                    MAX(called_at) AS last_call_at,
                    SUM(CASE WHEN http_status >= 200 AND http_status < 300 THEN 1 ELSE 0 END) AS success_count,
                    SUM(CASE WHEN error_message IS NOT NULL THEN 1 ELSE 0 END) AS error_count
                 FROM scan_evidence
                 WHERE scan_id = :sid",
                [':sid' => $scanId]
            );
            return $row ?: [];
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Get the current call order (for external tracking).
     */
    public function getCallOrder(): int
    {
        return $this->callOrder;
    }

    /**
     * Redact sensitive headers (API keys) before storing.
     */
    private function redactHeaders(array $headers): array
    {
        $redacted = [];
        foreach ($headers as $key => $value) {
            $lowerKey = strtolower($key);
            if (in_array($lowerKey, self::REDACT_HEADERS, true)) {
                $redacted[$key] = '***REDACTED***';
            } else {
                $redacted[$key] = $value;
            }
        }
        return $redacted;
    }

    /**
     * Check if the scan_evidence table exists.
     */
    private function tableExists(): bool
    {
        try {
            if (function_exists('tableExists')) {
                return tableExists('scan_evidence');
            }
            $result = DB::queryOne(
                "SELECT COUNT(*) AS n FROM information_schema.tables
                 WHERE table_schema = DATABASE() AND table_name = 'scan_evidence'"
            );
            return (int)($result['n'] ?? 0) > 0;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
