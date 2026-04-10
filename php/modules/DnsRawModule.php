<?php
// =============================================================================
//  CTI — DNS Raw Records Module
//  Internal tool (no external API). Supports: domain
//  Uses dns_get_record() with DNS_ALL for comprehensive record retrieval
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsRawModule extends BaseApiModule
{
    private const API_ID   = 'dns-raw';
    private const API_NAME = 'DNS Raw Records';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $startTime = microtime(true);

        try {
            $records = @dns_get_record($queryValue, DNS_ALL);
        } catch (\Exception $e) {
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $elapsedMs);
        }

        $elapsedMs = (int)((microtime(true) - $startTime) * 1000);

        if (!$records || count($records) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $elapsedMs);
        }

        $totalRecords = count($records);

        // Group records by type
        $grouped = [];
        foreach ($records as $rec) {
            $type = isset($rec['type']) ? $rec['type'] : 'UNKNOWN';
            if (!isset($grouped[$type])) {
                $grouped[$type] = [];
            }
            $grouped[$type][] = $rec;
        }

        $typeCounts = [];
        foreach ($grouped as $type => $recs) {
            $typeCounts[$type] = count($recs);
        }

        $score = min(15, (int)($totalRecords / 3));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 80 + min(15, $totalRecords));

        $parts = ["Domain {$queryValue}: {$totalRecords} DNS record(s) found"];

        $typeList = [];
        foreach ($typeCounts as $type => $cnt) {
            $typeList[] = "{$type}({$cnt})";
        }
        $parts[] = "Record types: " . implode(', ', $typeList);

        // Highlight notable records
        if (isset($grouped['MX'])) {
            $mxTargets = [];
            foreach ($grouped['MX'] as $mx) {
                if (isset($mx['target'])) $mxTargets[] = $mx['target'];
            }
            if (!empty($mxTargets)) {
                $parts[] = "Mail servers: " . implode(', ', array_slice($mxTargets, 0, 5));
            }
        }

        if (isset($grouped['TXT'])) {
            $txtCount = count($grouped['TXT']);
            $parts[] = "{$txtCount} TXT record(s) found (may include SPF, DKIM, verification)";
        }

        if (isset($grouped['NS'])) {
            $nsTargets = [];
            foreach ($grouped['NS'] as $ns) {
                if (isset($ns['target'])) $nsTargets[] = $ns['target'];
            }
            if (!empty($nsTargets)) {
                $parts[] = "Nameservers: " . implode(', ', array_slice($nsTargets, 0, 5));
            }
        }

        $tags = [self::API_ID, 'domain', 'dns', 'records'];
        if (isset($grouped['MX'])) $tags[] = 'mail';
        if (isset($grouped['TXT'])) $tags[] = 'txt_records';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $elapsedMs, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['total_records' => $totalRecords, 'type_counts' => $typeCounts, 'records' => array_slice($records, 0, 50)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $startTime = microtime(true);
        try {
            $records = @dns_get_record('google.com', DNS_A);
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            if ($records && count($records) > 0) {
                return ['status' => 'healthy', 'latency_ms' => $elapsedMs, 'error' => null];
            }
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => 'DNS resolution failed'];
        } catch (\Exception $e) {
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => $e->getMessage()];
        }
    }
}
