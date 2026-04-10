<?php
// =============================================================================
//  CTI — LeakCheck Module
//  Queries LeakCheck API for credential leak/breach data.
//  API Docs: https://wiki.leakcheck.io/en/api
//  Supports: email, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class LeakCheckModule extends BaseApiModule
{
    private const API_ID   = 'leakcheck';
    private const API_NAME = 'LeakCheck';
    private const SUPPORTED = ['email', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://leakcheck.io/api/v2', '/');
        $headers = ['X-API-Key' => $apiKey];

        $type = ($queryType === 'email') ? 'email' : 'domain';
        $url  = "{$baseUrl}/query/" . urlencode($queryValue) . "?type={$type}";

        $resp = HttpClient::get($url, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json    = $resp['json'];
        $results = $json['result'] ?? $json['data'] ?? [];

        if (empty($results)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $totalLeaks = count($results);
        $sources = [];
        foreach ($results as $r) {
            $src = $r['source']['name'] ?? $r['source'] ?? 'unknown';
            if ($src) $sources[$src] = ($sources[$src] ?? 0) + 1;
        }

        $score      = min(90, 30 + $totalLeaks * 8);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 70 + $totalLeaks * 3);

        arsort($sources);
        $topSources = array_slice(array_keys($sources), 0, 5);

        $summary = "LeakCheck: {$queryValue} found in {$totalLeaks} breach(es).";
        if (!empty($topSources)) $summary .= ' Sources: ' . implode(', ', $topSources) . '.';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: [self::API_ID, $queryType, 'data_leak', 'breach'],
            rawData: [
                'total_leaks' => $totalLeaks,
                'sources'     => $sources,
                'results'     => array_slice($results, 0, 50),
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://leakcheck.io/api/v2', '/');
        $resp = HttpClient::get("{$baseUrl}/query/test@example.com?type=email", ['X-API-Key' => $apiKey]);
        return [
            'status'     => ($resp['status'] === 200 || $resp['status'] === 404) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
