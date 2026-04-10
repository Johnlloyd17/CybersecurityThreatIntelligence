<?php
// =============================================================================
//  CTI — FullHunt Module
//  API Docs: https://api-docs.fullhunt.io/
//  Auth: X-API-KEY header. Supports: domain
//  Endpoint: https://fullhunt.io/api/v1/domain/{domain}/subdomains
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class FullHuntModule extends BaseApiModule
{
    private const API_ID   = 'fullhunt';
    private const API_NAME = 'FullHunt';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'domain') return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");

        $url = 'https://fullhunt.io/api/v1/domain/' . urlencode($queryValue) . '/subdomains';
        $resp = HttpClient::get($url, ['X-API-KEY' => $apiKey], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $hosts = $data['hosts'] ?? [];
        $total = $data['metadata']['total_results'] ?? count($hosts);

        if (empty($hosts)) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);

        $parts = ["Domain {$queryValue}: {$total} subdomain(s)/host(s) discovered by FullHunt"];
        if (!empty($hosts)) $parts[] = "Hosts: " . implode(', ', array_slice($hosts, 0, 10));
        if ($total > 10) $parts[] = "... and " . ($total - 10) . " more";

        $score = min(25, (int)($total / 5));

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score), confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'dns', 'attack_surface', 'clean'],
            rawData: ['total' => $total, 'hosts' => array_slice($hosts, 0, 50)], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://fullhunt.io/api/v1/auth/status', ['X-API-KEY' => $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
