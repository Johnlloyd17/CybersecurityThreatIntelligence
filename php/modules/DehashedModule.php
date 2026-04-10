<?php
// =============================================================================
//  CTI — Dehashed Module
//  API Docs: https://www.dehashed.com/docs
//  Auth: Basic Auth. Supports: email, username, ip, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DehashedModule extends BaseApiModule
{
    private const API_ID   = 'dehashed';
    private const API_NAME = 'Dehashed';
    private const SUPPORTED = ['email', 'username', 'ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.dehashed.com/search?' . http_build_query(['query' => $queryValue]);
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get($url, ['Authorization' => $authHeader, 'Accept' => 'application/json'], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $total = $data['total'] ?? 0;
        $entries = $data['entries'] ?? [];

        if ($total === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $score = min(90, 30 + (int)log($total + 1, 2) * 5);
        $severity = OsintResult::scoreToSeverity($score);

        $databases = array_unique(array_map(fn($e) => $e['database_name'] ?? '', array_slice($entries, 0, 10)));
        $preview = implode(', ', array_filter($databases));
        $summary = "{$queryValue}: {$total} leaked records found. Databases: {$preview}.";

        $tags = [self::API_ID, $queryType, 'breach', 'leak'];
        if ($total > 10) $tags[] = 'high_exposure';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get('https://api.dehashed.com/search?query=test@example.com', ['Authorization' => $authHeader, 'Accept' => 'application/json'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
