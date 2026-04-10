<?php
// =============================================================================
//  CTI — Recon.dev Module
//  API Docs: https://recon.dev/
//  Auth: API key as query param
//  Endpoint: GET https://recon.dev/api/search?key={key}&domain={domain}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ReconDevModule extends BaseApiModule
{
    private const API_ID   = 'recon-dev';
    private const API_NAME = 'Recon.dev';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. Recon.dev supports domain lookups only.");
        }

        $base = rtrim($baseUrl ?: 'https://recon.dev', '/');
        $url = "{$base}/api/search?key=" . urlencode($apiKey) . "&domain=" . urlencode($queryValue);

        $resp = HttpClient::get($url, [], 25);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!is_array($data)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);
        }

        if (empty($data)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Extract subdomains and related data
        $subdomains = [];
        $rawDomains = [];
        foreach ($data as $entry) {
            $rawDomain = $entry['rawDomain'] ?? '';
            if ($rawDomain) $rawDomains[] = $rawDomain;
            $subs = $entry['subdomains'] ?? [];
            foreach ($subs as $sub) {
                $subdomains[$sub] = true;
            }
        }

        $subdomainList = array_keys($subdomains);
        $subdomainCount = count($subdomainList);
        $rawDomainCount = count($rawDomains);

        // Score: more subdomains = more attack surface
        $score = min(40, $subdomainCount * 2);
        if ($subdomainCount > 50) $score = max($score, 50);

        $subSample = implode(', ', array_slice($subdomainList, 0, 15));
        $summary = "Recon.dev found {$subdomainCount} subdomain(s) and {$rawDomainCount} raw domain entry(ies) for {$queryValue}. " .
                   "Subdomains: {$subSample}";

        $tags = [self::API_ID, 'domain', 'dns', 'subdomain_enum'];
        if ($subdomainCount > 20) $tags[] = 'large_attack_surface';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(90, 55 + min(35, $subdomainCount)),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: ['subdomains' => $subdomainList, 'entries' => $data],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://recon.dev', '/');
        $url = "{$base}/api/search?key=" . urlencode($apiKey) . "&domain=example.com";
        $resp = HttpClient::get($url, [], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
