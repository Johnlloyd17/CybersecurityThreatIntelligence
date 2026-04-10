<?php
// =============================================================================
//  CTI — Onyphe Module
//  API Docs: https://www.onyphe.io/documentation/api
//  Auth: apikey param or Authorization header. Supports: ip, domain
//  Endpoint: https://www.onyphe.io/api/v2/simple/{category}/{value}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OnypheModule extends BaseApiModule
{
    private const API_ID   = 'onyphe';
    private const API_NAME = 'Onyphe';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://www.onyphe.io/api/v2', '/');
        $headers = ['Authorization' => 'apikey ' . $apiKey];

        // Use summary endpoint for comprehensive data
        $url = "{$base}/summary/" . urlencode($queryType) . "/" . urlencode($queryValue);

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $results = $data['results'] ?? [];
        $count   = $data['count'] ?? count($results);
        $total   = $data['total'] ?? $count;

        if ($count === 0) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);

        $ports     = [];
        $protocols = [];
        $countries = [];
        $asns      = [];
        $cves      = [];

        foreach ($results as $r) {
            if (isset($r['port'])) $ports[$r['port']] = true;
            if (isset($r['protocol'])) $protocols[$r['protocol']] = true;
            if (isset($r['country'])) $countries[$r['country']] = true;
            if (isset($r['asn'])) $asns[$r['asn']] = true;
            if (isset($r['cve']) && is_array($r['cve'])) {
                foreach ($r['cve'] as $c) $cves[$c] = true;
            }
        }

        $cveCount = count($cves);
        $score = min(100, count($ports) * 3 + $cveCount * 10);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 70 + min(25, $count));

        $label = $queryType === 'ip' ? "IP {$queryValue}" : "Domain {$queryValue}";
        $parts = ["{$label}: {$count} data point(s) on Onyphe"];
        if (!empty($ports)) $parts[] = "Ports: " . implode(', ', array_slice(array_keys($ports), 0, 10));
        if (!empty($countries)) $parts[] = "Countries: " . implode(', ', array_keys($countries));
        if ($cveCount > 0) $parts[] = "{$cveCount} CVE(s) associated";

        $tags = [self::API_ID, $queryType, 'scan'];
        if ($cveCount > 0) $tags[] = 'vulnerable';
        if ($score >= 70) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://www.onyphe.io/api/v2/user', ['Authorization' => 'apikey ' . $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
