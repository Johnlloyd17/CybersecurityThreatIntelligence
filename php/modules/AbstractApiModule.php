<?php
// =============================================================================
//  CTI — AbstractAPI Email Validation Module
//  API Docs: https://www.abstractapi.com/api/email-verification-validation-api
//  Auth: api_key query param. Supports: email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class AbstractApiModule extends BaseApiModule
{
    private const API_ID   = 'abstractapi';
    private const API_NAME = 'AbstractAPI Email Validation';
    private const SUPPORTED = ['email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://emailvalidation.abstractapi.com/v1/?' . http_build_query([
            'api_key' => $apiKey,
            'email' => $queryValue,
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

        $deliverability = $data['deliverability'] ?? 'UNKNOWN';
        $isDisposable = $data['is_disposable_email'] ?? false;
        $isRole = $data['is_role_email'] ?? false;
        $isFree = $data['is_free_email'] ?? false;
        $qualityScore = isset($data['quality_score']) ? (float)$data['quality_score'] : 0.5;

        $score = 0;
        if ($isDisposable) $score += 40;
        if ($deliverability === 'UNDELIVERABLE') $score += 30;
        $score = max($score, (int)((1 - $qualityScore) * 50));

        $severity = OsintResult::scoreToSeverity($score);
        $tags = [self::API_ID, 'email'];
        if ($isDisposable) $tags[] = 'disposable';
        if ($isFree) $tags[] = 'free_email';

        $parts = ["Email {$queryValue}: Deliverability: {$deliverability}"];
        if ($isDisposable) $parts[] = "Disposable: yes";
        if ($isRole) $parts[] = "Role account: yes";
        if ($isFree) $parts[] = "Free provider: yes";
        $parts[] = "Quality: {$qualityScore}";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'https://emailvalidation.abstractapi.com/v1/?' . http_build_query(['api_key' => $apiKey, 'email' => 'test@example.com']);
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
