<?php
// =============================================================================
//  CTI — Leak-Lookup Module
//  API Docs: https://leak-lookup.com/api
//  Auth: key in POST JSON body. Supports: email, hash, username
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class LeakLookupModule extends BaseApiModule
{
    private const API_ID   = 'leak-lookup';
    private const API_NAME = 'Leak-Lookup';
    private const SUPPORTED = ['email', 'hash', 'username'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $typeMap = ['email' => 'email_address', 'hash' => 'hash', 'username' => 'username'];
        $lookupType = $typeMap[$queryType];

        $resp = HttpClient::post('https://leak-lookup.com/api/search', [], [
            'type' => $lookupType,
            'query' => $queryValue,
            'key' => $apiKey,
        ], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        if (isset($data['error']) && $data['error'] === true) {
            $msg = $data['message'] ?? 'API error';
            return OsintResult::error(self::API_ID, self::API_NAME, $msg, $resp['elapsed_ms']);
        }

        $results = $data['message'] ?? $data['results'] ?? [];
        if (!is_array($results) || empty($results)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $breachCount = count($results);
        $score = min(85, 30 + $breachCount * 8);
        $severity = OsintResult::scoreToSeverity($score);

        $breachNames = array_keys($results);
        $preview = implode(', ', array_slice($breachNames, 0, 8));
        $summary = "{$queryValue}: Found in {$breachCount} breach(es). Sources: {$preview}.";

        $tags = [self::API_ID, $queryType, 'breach', 'leak'];
        if ($breachCount > 5) $tags[] = 'high_exposure';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::post('https://leak-lookup.com/api/search', [], ['type' => 'email_address', 'query' => 'test@example.com', 'key' => $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
