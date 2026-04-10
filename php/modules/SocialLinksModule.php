<?php
// =============================================================================
//  CTI — Social Links Module
//  API Docs: https://sociallinks.io/
//  Auth: Authorization: Bearer {key}. Supports: username, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SocialLinksModule extends BaseApiModule
{
    private const API_ID   = 'social-links';
    private const API_NAME = 'Social Links';
    private const SUPPORTED = ['username', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.sociallinks.io/search?' . http_build_query(['query' => $queryValue]);
        $resp = HttpClient::get($url, ['Authorization' => 'Bearer ' . $apiKey], 25);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $results = $data['results'] ?? $data;
        if (!is_array($results) || empty($results)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $count = count($results);
        $score = min(30, $count * 5);
        $severity = OsintResult::scoreToSeverity($score);

        $platforms = array_unique(array_map(fn($r) => $r['platform'] ?? $r['source'] ?? '', array_slice($results, 0, 10)));
        $preview = implode(', ', array_filter($platforms));
        $summary = "{$queryValue}: {$count} social profiles found. Platforms: {$preview}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 70,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, $queryType, 'social_media'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.sociallinks.io/search?query=test', ['Authorization' => 'Bearer ' . $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
