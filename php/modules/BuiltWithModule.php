<?php
// =============================================================================
//  CTI — BuiltWith Module
//  API Docs: https://api.builtwith.com/
//  Auth: KEY param. Supports: domain
//  Endpoint: https://api.builtwith.com/free1/api.json?KEY={key}&LOOKUP={domain}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BuiltWithModule extends BaseApiModule
{
    private const API_ID   = 'builtwith';
    private const API_NAME = 'BuiltWith';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'domain') return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");

        $url = 'https://api.builtwith.com/free1/api.json?KEY=' . urlencode($apiKey) . '&LOOKUP=' . urlencode($queryValue);
        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $groups = $data['groups'] ?? $data['Results'][0]['Result']['Paths'][0]['Technologies'] ?? [];
        $techs = [];
        if (is_array($groups)) {
            foreach ($groups as $g) {
                if (isset($g['name'])) $techs[] = $g['name'];
                if (isset($g['Name'])) $techs[] = $g['Name'];
                if (isset($g['categories'])) {
                    foreach ($g['categories'] as $c) {
                        if (isset($c['name'])) $techs[] = $c['name'];
                    }
                }
            }
        }

        $techCount = count($techs);
        if ($techCount === 0) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);

        $parts = ["Domain {$queryValue}: {$techCount} technology/ies detected by BuiltWith"];
        $parts[] = "Technologies: " . implode(', ', array_slice(array_unique($techs), 0, 15));

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 5, severity: 'info', confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'technology', 'osint', 'clean'],
            rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.builtwith.com/free1/api.json?KEY=' . urlencode($apiKey) . '&LOOKUP=google.com', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
