<?php
// =============================================================================
//  CTI — Bing Shared IPs Module
//  Uses Bing Web Search to find shared hosting on an IP address.
//  Auth: Ocp-Apim-Subscription-Key header
//  Endpoint: https://api.bing.microsoft.com/v7.0/search?q=ip:{ip}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BingSharedIpsModule extends BaseApiModule
{
    private const API_ID   = 'bing-shared-ips';
    private const API_NAME = 'Bing Shared IPs';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. Only IP lookups are supported.");
        }

        $base = rtrim($baseUrl ?: 'https://api.bing.microsoft.com', '/');
        $searchQuery = 'ip:' . $queryValue;
        $url = "{$base}/v7.0/search?q=" . urlencode($searchQuery) . "&count=50&responseFilter=Webpages";
        $headers = ['Ocp-Apim-Subscription-Key' => $apiKey];

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $webPages = $data['webPages']['value'] ?? [];
        $totalEstimated = $data['webPages']['totalEstimatedMatches'] ?? count($webPages);
        $resultCount = count($webPages);

        if ($resultCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Extract unique domains from results
        $domains = [];
        foreach ($webPages as $page) {
            $pageUrl = $page['url'] ?? '';
            if ($pageUrl) {
                $parsed = parse_url($pageUrl);
                $host = $parsed['host'] ?? '';
                if ($host) {
                    $domains[$host] = true;
                }
            }
        }
        $uniqueDomains = array_keys($domains);
        $domainCount = count($uniqueDomains);

        // Score based on shared hosting density
        $score = 0;
        if ($domainCount > 50) $score = 50;
        elseif ($domainCount > 20) $score = 35;
        elseif ($domainCount > 10) $score = 25;
        elseif ($domainCount > 5) $score = 15;
        else $score = 5;

        $domainSample = implode(', ', array_slice($uniqueDomains, 0, 10));
        $summary = "IP {$queryValue} shares hosting with ~{$domainCount} domain(s) " .
                   "(estimated {$totalEstimated} total results). " .
                   "Sample domains: {$domainSample}";

        $tags = [self::API_ID, 'ip', 'shared_hosting'];
        if ($domainCount > 20) $tags[] = 'high_density_hosting';
        if ($domainCount > 50) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(85, 50 + $domainCount),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: ['domains' => $uniqueDomains, 'total_estimated' => $totalEstimated, 'raw' => $data],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://api.bing.microsoft.com', '/');
        $url = "{$base}/v7.0/search?q=ip:8.8.8.8&count=1";
        $headers = ['Ocp-Apim-Subscription-Key' => $apiKey];
        $resp = HttpClient::get($url, $headers, 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
