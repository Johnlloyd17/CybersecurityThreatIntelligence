<?php
// =============================================================================
//  CTI — Grayhat Warfare Module
//  API Docs: https://buckets.grayhatwarfare.com/docs
//  Auth: access_token query param. Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GrayhatWarfareModule extends BaseApiModule
{
    private const API_ID   = 'grayhat-warfare';
    private const API_NAME = 'Grayhat Warfare';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://buckets.grayhatwarfare.com/api/v2/files?' . http_build_query([
            'keywords' => $queryValue,
            'access_token' => $apiKey,
        ]);

        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $files = $data['files'] ?? [];
        $count = count($files);

        if ($count === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $score = min(70, $count * 5);
        $severity = OsintResult::scoreToSeverity($score);

        $fileNames = array_map(fn($f) => $f['filename'] ?? '', array_slice($files, 0, 5));
        $preview = implode(', ', array_filter($fileNames));
        $summary = "Domain {$queryValue}: {$count} exposed files in cloud buckets. Files: {$preview}.";

        $tags = [self::API_ID, 'domain', 'exposed_data'];
        if ($count > 5) $tags[] = 'data_leak';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 75,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'https://buckets.grayhatwarfare.com/api/v2/files?' . http_build_query(['keywords' => 'test', 'access_token' => $apiKey]);
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
