<?php
// =============================================================================
//  CTI — Bitcoin Who's Who Module
//  Auth: key query param. Supports: bitcoin
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BitcoinWhosWhoModule extends BaseApiModule
{
    private const API_ID   = 'bitcoin-whos-who';
    private const API_NAME = "Bitcoin Who's Who";
    private const SUPPORTED = ['bitcoin'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://bitcoinwhoswho.com/api/address/' . urlencode($queryValue) . '?' . http_build_query(['key' => $apiKey]);
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

        $reports = $data['scam_reports'] ?? $data['reports'] ?? [];
        $owner = $data['owner'] ?? 'Unknown';
        $reportCount = is_array($reports) ? count($reports) : 0;

        $score = $reportCount > 0 ? min(90, 40 + $reportCount * 10) : 5;
        $severity = OsintResult::scoreToSeverity($score);

        $tags = [self::API_ID, 'bitcoin', 'blockchain'];
        if ($reportCount > 0) $tags[] = 'scam_reported';

        $summary = "Bitcoin {$queryValue}: Owner: {$owner}. Scam reports: {$reportCount}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $reportCount > 0 ? 85 : 60,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'https://bitcoinwhoswho.com/api/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?' . http_build_query(['key' => $apiKey]);
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
