<?php
// =============================================================================
//  CTI — StackOverflow Module
//  API Docs: https://api.stackexchange.com/docs
//  Free, no key required. Supports: username
//  Endpoint: https://api.stackexchange.com/2.3/users?inname={username}&site=stackoverflow
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class StackOverflowModule extends BaseApiModule
{
    private const API_ID   = 'stackoverflow';
    private const API_NAME = 'StackOverflow';
    private const SUPPORTED = ['username'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl  = rtrim($baseUrl ?: 'https://api.stackexchange.com/2.3', '/');
        $endpoint = "{$baseUrl}/users?inname=" . urlencode($queryValue) . "&site=stackoverflow&pagesize=5&order=desc&sort=reputation";

        $resp = HttpClient::get($endpoint, [], 15);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        return $this->parse($data, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $value, int $ms): OsintResult
    {
        $items   = isset($data['items']) ? $data['items'] : [];
        $hasMore = isset($data['has_more']) ? (bool)$data['has_more'] : false;

        if (count($items) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        $total = count($items);
        if ($hasMore) $total .= '+';

        // Informational score
        $score      = min(20, 5 + count($items) * 3);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 80;

        $parts = [];
        $parts[] = "Username '{$value}' — {$total} StackOverflow profile(s) found";

        // Detail top results
        foreach (array_slice($items, 0, 3) as $user) {
            $displayName = isset($user['display_name']) ? $user['display_name'] : 'unknown';
            $reputation  = isset($user['reputation']) ? (int)$user['reputation'] : 0;
            $location    = isset($user['location']) ? $user['location'] : '';
            $detail = "{$displayName} (rep: {$reputation})";
            if ($location) $detail .= " — {$location}";
            $parts[] = $detail;
        }

        // Check quota
        $quotaRemaining = isset($data['quota_remaining']) ? (int)$data['quota_remaining'] : -1;
        if ($quotaRemaining >= 0 && $quotaRemaining < 10) {
            $parts[] = "Warning: API quota low ({$quotaRemaining} remaining)";
        }

        $tags = [self::API_ID, 'username', 'osint', 'profile'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.stackexchange.com/2.3/users?inname=test&site=stackoverflow&pagesize=1', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
