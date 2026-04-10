<?php
// =============================================================================
//  CTI — IntelligenceX Module
//  API Docs: https://intelx.io/developers
//  Auth: x-key header
//  Endpoint: POST https://2.intelx.io/intelligent/search
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class IntelligenceXModule extends BaseApiModule
{
    private const API_ID   = 'intelligencex';
    private const API_NAME = 'IntelligenceX';
    private const SUPPORTED = ['ip', 'domain', 'email', 'url', 'hash', 'username', 'phone', 'keyword'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://2.intelx.io', '/');

        // Step 1: Submit search
        $searchUrl = "{$base}/intelligent/search";
        $headers = [
            'x-key'        => $apiKey,
            'Content-Type'  => 'application/json',
        ];
        $body = json_encode([
            'term'       => $queryValue,
            'maxresults' => 10,
            'media'      => 0,
        ]);

        $resp = HttpClient::post($searchUrl, $headers, $body, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $searchData = $resp['json'];
        if (!$searchData) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON from search', $resp['elapsed_ms']);

        $searchId = $searchData['id'] ?? null;
        if (!$searchId) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'No search ID returned', $resp['elapsed_ms']);
        }

        $elapsedSearch = $resp['elapsed_ms'];

        // Step 2: Fetch results (poll once after brief wait)
        $resultUrl = "{$base}/intelligent/search/result?id=" . urlencode($searchId) . "&limit=10";
        $resultResp = HttpClient::get($resultUrl, ['x-key' => $apiKey], 20);

        $totalElapsed = $elapsedSearch + $resultResp['elapsed_ms'];

        if ($resultResp['error'] || $resultResp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resultResp['error'] ?? 'Failed to fetch results', $totalElapsed);
        if ($resultResp['status'] < 200 || $resultResp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resultResp['status']} on result fetch", $totalElapsed);

        $resultData = $resultResp['json'];
        if (!$resultData) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON from results', $totalElapsed);

        $records = $resultData['records'] ?? [];
        $recordCount = count($records);
        $status = $resultData['status'] ?? -1;

        if ($recordCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $totalElapsed);
        }

        // Analyze records: pastes, leaks, etc.
        $buckets = [];
        $sources = [];
        foreach ($records as $record) {
            $bucket = $record['bucket'] ?? 'unknown';
            $buckets[$bucket] = ($buckets[$bucket] ?? 0) + 1;
            $name = $record['name'] ?? '';
            if ($name) $sources[] = $name;
        }

        // Score based on leak presence
        $score = 0;
        $leakCount  = ($buckets['leaks'] ?? 0) + ($buckets['darknet'] ?? 0);
        $pasteCount = $buckets['pastes'] ?? 0;
        if ($leakCount > 0) $score += min(60, $leakCount * 15);
        if ($pasteCount > 0) $score += min(30, $pasteCount * 5);
        if ($recordCount > 5) $score += 10;
        $score = min(100, max($score, $recordCount * 3));

        $bucketSummary = [];
        foreach ($buckets as $b => $c) {
            $bucketSummary[] = "{$b}: {$c}";
        }

        $sourceSample = implode(', ', array_slice($sources, 0, 5));
        $summary = "IntelligenceX found {$recordCount} record(s) for \"{$queryValue}\". " .
                   "Categories: " . implode(', ', $bucketSummary) . ". " .
                   "Sample sources: {$sourceSample}";

        $tags = [self::API_ID, $queryType, 'darkweb', 'leaks'];
        if ($leakCount > 0) $tags[] = 'data_leak';
        if ($pasteCount > 0) $tags[] = 'paste_found';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(90, 55 + $recordCount * 3),
            responseMs: $totalElapsed, summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: ['search_id' => $searchId, 'records' => $records, 'status' => $status],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://2.intelx.io', '/');
        $url = "{$base}/authenticate/info";
        $resp = HttpClient::get($url, ['x-key' => $apiKey], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
