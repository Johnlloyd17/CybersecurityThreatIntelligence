<?php
// =============================================================================
//  CTI — JsonWHOIS Module
//  API Docs: https://jsonwhois.com/docs
//  Auth: Authorization: Token {key}. Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class JsonWhoisModule extends BaseApiModule
{
    private const API_ID   = 'jsonwhois';
    private const API_NAME = 'JsonWHOIS';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://jsonwhois.com/api/v1/whois?' . http_build_query(['domain' => $queryValue]);
        $resp = HttpClient::get($url, ['Authorization' => 'Token ' . $apiKey], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $registrar = $data['registrar'] ?? 'Unknown';
        $created = $data['created_on'] ?? '';
        $expires = $data['expires_on'] ?? '';
        $nameservers = $data['nameservers'] ?? [];

        $score = 10;
        $severity = OsintResult::scoreToSeverity($score);

        $parts = ["Domain {$queryValue}: Registrar: {$registrar}"];
        if ($created) $parts[] = "Created: {$created}";
        if ($expires) $parts[] = "Expires: {$expires}";
        if (!empty($nameservers)) {
            $nsList = implode(', ', array_slice($nameservers, 0, 4));
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
        $resp = HttpClient::get('https://jsonwhois.com/api/v1/whois?domain=example.com', ['Authorization' => 'Token ' . $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
