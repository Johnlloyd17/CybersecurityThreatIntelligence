<?php
// =============================================================================
//  CTI — Censys Module
//  API Docs: https://search.censys.io/api
//  Auth: Basic Auth (API_ID:API_SECRET). Supports: ip, domain
//  Endpoint: https://search.censys.io/api/v2/hosts/{ip}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CensysModule extends BaseApiModule
{
    private const API_ID   = 'censys';
    private const API_NAME = 'Censys';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        // apiKey format: "API_ID:API_SECRET" (stored as combined in DB)
        $base = rtrim($baseUrl ?: 'https://search.censys.io/api/v2', '/');
        $headers = ['Authorization' => 'Basic ' . base64_encode($apiKey)];

        if ($queryType === 'ip') {
            $url = "{$base}/hosts/" . urlencode($queryValue);
        } else {
            // domain search via search endpoint
            $url = "{$base}/hosts/search?" . http_build_query(['q' => $queryValue, 'per_page' => 25]);
        }

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

        if ($queryType === 'ip') {
            return $this->parseHostResult($data, $queryValue, $resp['elapsed_ms']);
        }
        return $this->parseSearchResult($data, $queryValue, $resp['elapsed_ms']);
    }

    private function parseHostResult(array $data, string $ip, int $ms): OsintResult
    {
        $result = $data['result'] ?? $data;
        $services  = $result['services'] ?? [];
        $location  = $result['location'] ?? [];
        $asn       = $result['autonomous_system'] ?? [];
        $lastSeen  = $result['last_updated_at'] ?? '';

        $ports = [];
        $serviceNames = [];
        foreach ($services as $svc) {
            $port = $svc['port'] ?? 0;
            $name = $svc['service_name'] ?? $svc['extended_service_name'] ?? '';
            if ($port) $ports[] = $port;
            if ($name) $serviceNames[$name] = true;
        }

        $svcCount = count($services);
        $score = min(50, $svcCount * 5);
        // High-risk ports
        $riskyPorts = array_intersect($ports, [23, 445, 3389, 1433, 3306, 6379, 27017, 9200]);
        if (!empty($riskyPorts)) $score = max($score, 60);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 70 + min(25, $svcCount * 2));

        $parts = ["IP {$ip}: {$svcCount} service(s) detected by Censys"];
        if (!empty($ports)) $parts[] = "Open ports: " . implode(', ', array_slice($ports, 0, 15));
        if (!empty($serviceNames)) $parts[] = "Services: " . implode(', ', array_slice(array_keys($serviceNames), 0, 8));
        if (isset($asn['asn'])) {
            $asnName = $asn['name'] ?? '';
            $parts[] = "ASN: AS{$asn['asn']} ({$asnName})";
        }
        if (isset($location['country'])) $parts[] = "Country: " . $location['country'];

        $tags = [self::API_ID, 'ip', 'scan'];
        if (!empty($riskyPorts)) $tags[] = 'exposed_services';
        if ($svcCount > 10) $tags[] = 'high_exposure';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $result, success: true
        );
    }

    private function parseSearchResult(array $data, string $domain, int $ms): OsintResult
    {
        $hits = $data['result']['hits'] ?? [];
        $total = $data['result']['total'] ?? count($hits);

        if (empty($hits)) return OsintResult::notFound(self::API_ID, self::API_NAME, $domain, $ms);

        $ips = [];
        foreach ($hits as $h) { if (isset($h['ip'])) $ips[] = $h['ip']; }

        $parts = ["Domain {$domain}: {$total} host(s) found on Censys"];
        if (!empty($ips)) $parts[] = "IPs: " . implode(', ', array_slice($ips, 0, 10));

        $score = min(30, count($ips) * 2);

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score), confidence: 80,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'scan', 'clean'],
            rawData: ['total' => $total, 'ips' => $ips], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['Authorization' => 'Basic ' . base64_encode($apiKey)];
        $resp = HttpClient::get('https://search.censys.io/api/v2/metadata', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
