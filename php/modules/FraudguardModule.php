<?php
// =============================================================================
//  CTI — Fraudguard Module
//  Auth: Basic Auth. Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class FraudguardModule extends BaseApiModule
{
    private const API_ID   = 'fraudguard';
    private const API_NAME = 'Fraudguard';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.fraudguard.io/v2/ip/' . urlencode($queryValue);
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

        $riskLevel = $data['risk_level'] ?? 'unknown';
        $threat = $data['threat'] ?? 'unknown';
        $country = $data['country'] ?? 'Unknown';
        $isp = $data['isp'] ?? 'Unknown';

        $riskMap = ['1' => 10, '2' => 25, '3' => 50, '4' => 75, '5' => 95];
        $score = $riskMap[$riskLevel] ?? 10;
        $severity = OsintResult::scoreToSeverity($score);

        $tags = [self::API_ID, 'ip'];
        if ($score >= 70) $tags[] = 'malicious';
        elseif ($score >= 40) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        $summary = "IP {$queryValue}: Risk level: {$riskLevel}. Threat: {$threat}. Country: {$country}. ISP: {$isp}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get('https://api.fraudguard.io/v2/ip/8.8.8.8', ['Authorization' => $authHeader], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
