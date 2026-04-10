<?php
// =============================================================================
//  CTI — Host.io Module
//  API Docs: https://host.io/docs
//  Auth: token param. Supports: domain
//  Endpoint: https://host.io/api/full/{domain}?token={key}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class HostIoModule extends BaseApiModule
{
    private const API_ID   = 'host-io';
    private const API_NAME = 'Host.io';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'domain') return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");

        $url = 'https://host.io/api/full/' . urlencode($queryValue) . '?token=' . urlencode($apiKey);
        $resp = HttpClient::get($url, [], 15);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $web     = $data['web'] ?? [];
        $dns     = $data['dns'] ?? [];
        $related = $data['related'] ?? [];
        $ipInfo  = $data['ipinfo'] ?? [];

        $ip    = $dns['a'][0] ?? '';
        $mx    = $dns['mx'] ?? [];
        $ns    = $dns['ns'] ?? [];
        $rank  = $web['rank'] ?? null;
        $title = $web['title'] ?? '';
        $relCount = count($related['ip'] ?? []) + count($related['ns'] ?? []) + count($related['mx'] ?? []);

        $parts = ["Domain {$queryValue}"];
        if ($ip) $parts[] = "IP: {$ip}";
        if (!empty($ns)) $parts[] = "NS: " . implode(', ', array_slice($ns, 0, 3));
        if (!empty($mx)) $parts[] = "MX: " . implode(', ', array_slice($mx, 0, 3));
        if ($rank) $parts[] = "Rank: #{$rank}";
        if ($title) $parts[] = "Title: " . substr($title, 0, 80);
        if ($relCount > 0) $parts[] = "{$relCount} related domain(s)";

        $score = 5; // informational
        $tags = [self::API_ID, 'domain', 'dns', 'clean'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: 'info', confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://host.io/api/full/google.com?token=' . urlencode($apiKey), [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
