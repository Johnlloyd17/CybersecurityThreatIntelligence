<?php
// =============================================================================
//  CTI — SpyOnWeb Module
//  API Docs: https://api.spyonweb.com/
//  Auth: access_token query param
//  Endpoint: GET https://api.spyonweb.com/v1/domain/{domain}?access_token={key}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SpyOnWebModule extends BaseApiModule
{
    private const API_ID   = 'spyonweb';
    private const API_NAME = 'SpyOnWeb';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. Supports domain and IP.");
        }

        $base = rtrim($baseUrl ?: 'https://api.spyonweb.com', '/');

        $endpoint = $queryType === 'ip' ? 'ip' : 'domain';
        $url = "{$base}/v1/{$endpoint}/" . urlencode($queryValue) . "?access_token=" . urlencode($apiKey);

        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $apiStatus = $data['status'] ?? 'error';
        if ($apiStatus !== 'found') {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $result = $data['result'] ?? [];

        // Extract analytics IDs and related domains
        $analyticsIds = [];
        $relatedDomains = [];

        // Check for Google Analytics, Adsense, etc.
        $summaryParts = [];

        $domainData = $result['domain'] ?? ($result['ip'] ?? []);
        $queryData = $domainData[$queryValue] ?? [];

        $items = $queryData['items'] ?? [];
        foreach ($items as $key => $val) {
            $analyticsIds[] = $key;
        }

        // Also look for DNS info
        $dnsNs = $result['dns_ns'] ?? [];
        $dnsA  = $result['dns_a'] ?? [];

        // Gather related domains from analytics
        $adsenseData = $result['adsense'] ?? [];
        $analyticsData = $result['analytics'] ?? [];

        foreach ($adsenseData as $adsId => $adsDomains) {
            $domainItems = $adsDomains['items'] ?? [];
            foreach ($domainItems as $d => $info) {
                $relatedDomains[$d] = true;
            }
            $analyticsIds[] = "adsense:{$adsId}";
        }

        foreach ($analyticsData as $gaId => $gaDomains) {
            $domainItems = $gaDomains['items'] ?? [];
            foreach ($domainItems as $d => $info) {
                $relatedDomains[$d] = true;
            }
            $analyticsIds[] = "ga:{$gaId}";
        }

        $relatedList = array_keys($relatedDomains);
        $relatedCount = count($relatedList);

        // Score: more related domains = more interconnection
        $score = min(35, $relatedCount * 3);
        if (count($analyticsIds) > 2) $score += 10;
        $score = min(60, $score);

        $relatedSample = implode(', ', array_slice($relatedList, 0, 10));
        $idSample = implode(', ', array_slice($analyticsIds, 0, 5));
        $summary = "SpyOnWeb: {$queryValue} linked to {$relatedCount} related domain(s). " .
                   "Analytics/tracking IDs: {$idSample}. " .
                   "Related domains: {$relatedSample}";

        $tags = [self::API_ID, $queryType, 'web_analytics', 'domain_correlation'];
        if ($relatedCount > 10) $tags[] = 'large_network';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(85, 50 + min(35, $relatedCount * 2)),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://api.spyonweb.com', '/');
        $url = "{$base}/v1/domain/example.com?access_token=" . urlencode($apiKey);
        $resp = HttpClient::get($url, [], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
