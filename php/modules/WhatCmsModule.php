<?php
// =============================================================================
//  CTI — WhatCMS Module
//  API Docs: https://whatcms.org/Documentation
//  Auth: key param. Supports: domain, url
//  Endpoint: https://whatcms.org/API/Tech?key={key}&url={target}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WhatCmsModule extends BaseApiModule
{
    private const API_ID   = 'whatcms';
    private const API_NAME = 'WhatCMS';
    private const SUPPORTED = ['domain', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://whatcms.org/API/Tech?key=' . urlencode($apiKey) . '&url=' . urlencode($queryValue);
        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $resultCode = $data['result']['code'] ?? 0;
        if ($resultCode === 0) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);

        $results = $data['results'] ?? $data['result'] ?? [];
        $cms   = $results['name'] ?? $data['result']['name'] ?? 'Unknown';
        $ver   = $results['version'] ?? $data['result']['version'] ?? '';
        $techs = $data['technologies'] ?? [];

        $parts = ["Domain {$queryValue}: CMS detected — {$cms}"];
        if ($ver) $parts[] = "Version: {$ver}";
        if (!empty($techs)) {
            $techNames = array_map(fn($t) => $t['name'] ?? '', array_slice($techs, 0, 10));
            $parts[] = "Technologies: " . implode(', ', array_filter($techNames));
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 5, severity: 'info', confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, $queryType, 'cms', 'technology', 'clean'],
            rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://whatcms.org/API/Tech?key=' . urlencode($apiKey) . '&url=google.com', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
