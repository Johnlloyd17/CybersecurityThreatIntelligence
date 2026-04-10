<?php
// =============================================================================
//  CTI — TextMagic Module
//  API Docs: https://www.textmagic.com/docs/api/
//  Auth: Basic Auth. Supports: phone
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class TextMagicModule extends BaseApiModule
{
    private const API_ID   = 'textmagic';
    private const API_NAME = 'TextMagic';
    private const SUPPORTED = ['phone'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://rest.textmagic.com/api/v2/lookups/' . urlencode($queryValue);
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get($url, ['Authorization' => $authHeader], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $type = $data['type'] ?? 'unknown';
        $carrier = $data['carrier'] ?? 'Unknown';
        $country = $data['country'] ?? 'Unknown';

        $score = 5;
        $severity = OsintResult::scoreToSeverity($score);
        $summary = "Phone {$queryValue}: Type: {$type}. Carrier: {$carrier}. Country: {$country}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, 'phone', 'lookup'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get('https://rest.textmagic.com/api/v2/user', ['Authorization' => $authHeader], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
