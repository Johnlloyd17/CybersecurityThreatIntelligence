<?php
// =============================================================================
//  CTI — Farsight DNSDB Module
//  API Docs: https://docs.dnsdb.info/
//  Auth: X-API-Key header. Supports: domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsdbModule extends BaseApiModule
{
    private const API_ID   = 'dnsdb';
    private const API_NAME = 'Farsight DNSDB';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        if ($queryType === 'domain') {
            $url = 'https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/*.' . urlencode($queryValue);
        } else {
            $url = 'https://api.dnsdb.info/dnsdb/v2/lookup/rdata/ip/' . urlencode($queryValue);
        }

        $resp = HttpClient::get($url, ['X-API-Key' => $apiKey, 'Accept' => 'application/jsonl'], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $lines = array_filter(explode("\n", trim($resp['body'])));
        $records = [];
        foreach ($lines as $line) {
            $rec = json_decode($line, true);
            if ($rec && isset($rec['obj'])) $records[] = $rec['obj'];
        }

        if (empty($records)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $count = count($records);
        $score = min(25, $count);
        $severity = OsintResult::scoreToSeverity($score);

        $rrnames = array_unique(array_map(fn($r) => $r['rrname'] ?? '', array_slice($records, 0, 8)));
        $preview = implode(', ', array_filter($rrnames));
        $summary = "{$queryValue}: {$count} DNSDB records. Sample: {$preview}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, $queryType, 'passive_dns'], rawData: $records, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/example.com', ['X-API-Key' => $apiKey, 'Accept' => 'application/jsonl'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
