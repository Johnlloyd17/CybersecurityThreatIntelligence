<?php
// =============================================================================
//  CTI — Intelligence X Module
//  Queries Intelligence X search API for leaked data, darknet mentions, etc.
//  API Docs: https://intelx.io/developers
//  Supports: ip, domain, url, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class IntelXModule extends BaseApiModule
{
    private const API_ID   = 'intelx';
    private const API_NAME = 'Intelligence X';
    private const SUPPORTED = ['ip', 'domain', 'url', 'email'];

    // Bucket type mapping
    private const BUCKETS = [
        1 => 'Pastes',
        2 => 'Leaks / Dumps',
        3 => 'Darknet',
        4 => 'Documents',
        5 => 'Whois',
        6 => 'Public Web',
        7 => 'DNSDB',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://2.intelx.io', '/');
        $headers = [
            'x-key'        => $apiKey,
            'Content-Type' => 'application/json',
        ];

        // Step 1: Start a search
        $searchBody = json_encode([
            'term'      => $queryValue,
            'maxresults'=> min(100, $this->maxResults()),
            'media'     => 0,   // All media types
            'timeout'   => 10,
            'sort'      => 2,   // Relevance
        ]);

        $resp = HttpClient::post("{$baseUrl}/intelligent/search", $searchBody, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $searchId = $resp['json']['id'] ?? '';
        if (!$searchId) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'No search ID returned', $resp['elapsed_ms']);
        }

        // Step 2: Fetch results (poll with small delay)
        usleep(500000); // 500ms
        $resultsResp = HttpClient::get(
            "{$baseUrl}/intelligent/search/result?id=" . urlencode($searchId) . "&limit=100",
            $headers
        );

        $totalMs = $resp['elapsed_ms'] + ($resultsResp['elapsed_ms'] ?? 0);

        if ($resultsResp['error'] || $resultsResp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Failed to fetch results: ' . ($resultsResp['error'] ?? "HTTP {$resultsResp['status']}"), $totalMs);
        }

        $records = $resultsResp['json']['records'] ?? [];
        $status  = $resultsResp['json']['status']  ?? 0;

        if (empty($records)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $totalMs);
        }

        $totalHits = count($records);
        $buckets   = [];
        $sources   = [];
        $dates     = [];

        foreach ($records as $rec) {
            $bucket = $rec['bucket'] ?? '';
            if ($bucket) $buckets[$bucket] = ($buckets[$bucket] ?? 0) + 1;

            $name = $rec['name'] ?? '';
            if ($name) $sources[] = $name;

            $date = $rec['date'] ?? '';
            if ($date) $dates[] = $date;
        }

        // Score based on what was found
        $score = 0;
        if (isset($buckets['darknet']) || isset($buckets['Darknet'])) $score = max($score, 80);
        if (isset($buckets['leaks']) || isset($buckets['Leaks / Dumps'])) $score = max($score, 75);
        if (isset($buckets['pastes']) || isset($buckets['Pastes'])) $score = max($score, 50);
        $score = max($score, min(65, $totalHits * 5));

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 60 + $totalHits * 3);

        arsort($buckets);
        $bucketSummary = [];
        foreach (array_slice($buckets, 0, 5, true) as $b => $c) {
            $bucketSummary[] = "{$b}: {$c}";
        }

        $summary = "Intelligence X: {$totalHits} result(s) for {$queryValue}. Sources: " . implode(', ', $bucketSummary) . '.';

        $resultTags = [self::API_ID, $queryType, 'osint', 'leak_search'];
        if (isset($buckets['darknet']) || isset($buckets['Darknet'])) $resultTags[] = 'darknet';
        if (isset($buckets['leaks']) || isset($buckets['Leaks / Dumps'])) $resultTags[] = 'data_leak';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $totalMs,
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'total_results' => $totalHits,
                'buckets'       => $buckets,
                'sample_sources'=> array_slice($sources, 0, 20),
                'date_range'    => !empty($dates) ? [min($dates), max($dates)] : null,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://2.intelx.io', '/');
        $headers = ['x-key' => $apiKey];
        $resp = HttpClient::get("{$baseUrl}/authenticate/info", $headers);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
