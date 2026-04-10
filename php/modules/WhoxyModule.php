<?php
// =============================================================================
//  CTI — Whoxy Module
//  API Docs: https://www.whoxy.com/documentation/
//  Auth: key query param. Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WhoxyModule extends BaseApiModule
{
    private const API_ID   = 'whoxy';
    private const API_NAME = 'Whoxy';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.whoxy.com/?' . http_build_query([
            'key' => $apiKey,
            'whois' => $queryValue,
        ]);

        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $statusCode = $data['status'] ?? 0;
        if ($statusCode === 0 || (isset($data['status_reason']) && stripos($data['status_reason'], 'not found') !== false)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $registrar = $data['registrar_name'] ?? 'Unknown';
        $created = $data['create_date'] ?? '';
        $expires = $data['expiry_date'] ?? '';
        $ns = $data['name_servers'] ?? [];

        $score = 10;
        $severity = OsintResult::scoreToSeverity($score);

        $parts = ["Domain {$queryValue}: Registrar: {$registrar}"];
        if ($created) $parts[] = "Created: {$created}";
        if ($expires) $parts[] = "Expires: {$expires}";
        if (!empty($ns)) {
            $nsList = implode(', ', array_slice($ns, 0, 4));
            $parts[] = "NS: {$nsList}";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'whois'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'https://api.whoxy.com/?' . http_build_query(['key' => $apiKey, 'whois' => 'example.com']);
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
