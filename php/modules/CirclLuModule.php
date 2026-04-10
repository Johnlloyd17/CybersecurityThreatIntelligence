<?php
// =============================================================================
//  CTI — CIRCL PassiveDNS Module
//  API Docs: https://www.circl.lu/services/passive-dns/
//  Auth: Basic Auth (user:pass as apiKey). Supports: domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CirclLuModule extends BaseApiModule
{
    private const API_ID   = 'circl-lu';
    private const API_NAME = 'CIRCL PassiveDNS';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://www.circl.lu/pdns/query/' . urlencode($queryValue);
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get($url, ['Authorization' => $authHeader], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        // CIRCL returns NDJSON (one JSON object per line)
        $lines = array_filter(explode("\n", trim($resp['body'])));
        $records = [];
        foreach ($lines as $line) {
            $rec = json_decode($line, true);
            if ($rec) $records[] = $rec;
        }

        if (empty($records)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $count = count($records);
        $score = min(30, $count);
        $severity = OsintResult::scoreToSeverity($score);

        $rrnames = array_unique(array_map(fn($r) => $r['rrname'] ?? '', array_slice($records, 0, 10)));
        $preview = implode(', ', array_filter($rrnames));
        $summary = "{$queryValue}: {$count} passive DNS records found. Sample: {$preview}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 75,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, $queryType, 'passive_dns'], rawData: $records, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get('https://www.circl.lu/pdns/query/circl.lu', ['Authorization' => $authHeader], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
