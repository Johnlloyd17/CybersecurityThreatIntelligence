<?php
// =============================================================================
//  CTI — C99 Module
//  API Docs: https://api.c99.nl/
//  Auth: key query param. Supports: domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class C99Module extends BaseApiModule
{
    private const API_ID   = 'c99';
    private const API_NAME = 'C99';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        if ($queryType === 'domain') {
            $url = 'https://api.c99.nl/subdomainfinder?' . http_build_query([
                'key' => $apiKey,
                'host' => $queryValue,
                'json' => 'true',
            ]);
        } else {
            $url = 'https://api.c99.nl/iplookup?' . http_build_query([
                'key' => $apiKey,
                'host' => $queryValue,
                'json' => 'true',
            ]);
        }

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

        if (isset($data['error'])) {
            return OsintResult::error(self::API_ID, self::API_NAME, $data['error'], $resp['elapsed_ms']);
        }

        $subdomains = $data['subdomains'] ?? [];
        $count = is_array($subdomains) ? count($subdomains) : 0;

        if ($queryType === 'domain') {
            if ($count === 0) {
                return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
            }
            $score = min(25, $count * 2);
            $severity = OsintResult::scoreToSeverity($score);
            $preview = implode(', ', array_slice(array_map(fn($s) => $s['subdomain'] ?? '', $subdomains), 0, 8));
            $summary = "Domain {$queryValue}: {$count} subdomains found. Preview: {$preview}.";
        } else {
            $score = 10;
            $severity = OsintResult::scoreToSeverity($score);
            $summary = "IP {$queryValue}: C99 lookup completed.";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 70,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, $queryType, 'recon'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'https://api.c99.nl/subdomainfinder?' . http_build_query(['key' => $apiKey, 'host' => 'example.com', 'json' => 'true']);
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
