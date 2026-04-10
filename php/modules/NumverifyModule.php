<?php
// =============================================================================
//  CTI — numverify Module
//  API Docs: https://numverify.com/documentation
//  Auth: access_key query param. Supports: phone
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class NumverifyModule extends BaseApiModule
{
    private const API_ID   = 'numverify';
    private const API_NAME = 'numverify';
    private const SUPPORTED = ['phone'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'http://apilayer.net/api/validate?' . http_build_query([
            'access_key' => $apiKey,
            'number' => $queryValue,
        ]);

        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        if (isset($data['error'])) {
            $errMsg = $data['error']['info'] ?? 'API error';
            return OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $resp['elapsed_ms']);
        }

        $valid = $data['valid'] ?? false;
        $country = $data['country_name'] ?? 'Unknown';
        $carrier = $data['carrier'] ?? 'Unknown';
        $lineType = $data['line_type'] ?? 'Unknown';

        $score = $valid ? 5 : 30;
        $severity = OsintResult::scoreToSeverity($score);

        $validStr = $valid ? 'yes' : 'no';
        $summary = "Phone {$queryValue}: Valid: {$validStr}. Country: {$country}. Carrier: {$carrier}. Type: {$lineType}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, 'phone', 'validation'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'http://apilayer.net/api/validate?' . http_build_query(['access_key' => $apiKey, 'number' => '14158586273']);
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200 && isset($resp['json']['error'])) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
