<?php
// =============================================================================
//  CTI — Crobat (sonar.omnisint.io) Module
//  API Docs: https://sonar.omnisint.io
//  Free, no key. Supports: domain
//  Endpoint: GET https://sonar.omnisint.io/subdomains/{domain}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CrobatModule extends BaseApiModule
{
    private const API_ID   = 'crobat';
    private const API_NAME = 'Crobat (Omnisint)';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://sonar.omnisint.io/subdomains/' . urlencode($queryValue);
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ? $resp['error'] : 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!is_array($data) || count($data) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $subdomains = array_unique($data);
        $subCount = count($subdomains);

        $score = min(25, (int)($subCount / 5));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 70 + min(25, $subCount));

        $parts = ["Domain {$queryValue}: {$subCount} subdomain(s) found via Crobat"];

        $sample = array_slice($subdomains, 0, 15);
        if (!empty($sample)) {
            $parts[] = "Subdomains: " . implode(', ', $sample);
            if ($subCount > 15) {
                $remaining = $subCount - 15;
                $parts[] = "... and {$remaining} more";
            }
        }

        $tags = [self::API_ID, 'domain', 'dns', 'subdomains'];
        if ($subCount > 50) $tags[] = 'large_infrastructure';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['subdomain_count' => $subCount, 'subdomains' => array_slice($subdomains, 0, 100)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://sonar.omnisint.io/subdomains/google.com', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
