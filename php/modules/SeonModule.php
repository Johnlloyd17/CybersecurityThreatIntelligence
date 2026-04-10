<?php
// =============================================================================
//  CTI — Seon Module
//  API Docs: https://docs.seon.io/
//  Auth: X-API-KEY header. Supports: email, phone, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SeonModule extends BaseApiModule
{
    private const API_ID   = 'seon';
    private const API_NAME = 'Seon';
    private const SUPPORTED = ['email', 'phone', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        if ($queryType === 'email') {
            $url = 'https://api.seon.io/SeonRestService/email-api/v2.2/' . urlencode($queryValue);
        } elseif ($queryType === 'phone') {
            $url = 'https://api.seon.io/SeonRestService/phone-api/v1.4/' . urlencode($queryValue);
        } else {
            $url = 'https://api.seon.io/SeonRestService/ip-api/v1.1/' . urlencode($queryValue);
        }

        $resp = HttpClient::get($url, ['X-API-KEY' => $apiKey], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $innerData = $data['data'] ?? $data;
        $fraudScore = $innerData['score'] ?? $innerData['fraud_score'] ?? 0;
        $score = min(100, (int)$fraudScore);
        $severity = OsintResult::scoreToSeverity($score);

        $tags = [self::API_ID, $queryType];
        if ($score >= 70) $tags[] = 'high_risk';
        elseif ($score >= 40) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        $parts = ["{$queryValue}: Seon fraud score: {$score}"];

        if ($queryType === 'email') {
            $deliverable = isset($innerData['deliverable']) ? ($innerData['deliverable'] ? 'yes' : 'no') : 'unknown';
            $breach = isset($innerData['breach_details']) ? 'yes' : 'no';
            $parts[] = "Deliverable: {$deliverable}";
            $parts[] = "Breached: {$breach}";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.seon.io/SeonRestService/email-api/v2.2/test@example.com', ['X-API-KEY' => $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
