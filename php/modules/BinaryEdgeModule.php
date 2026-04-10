<?php
// =============================================================================
//  CTI — BinaryEdge Module
//  API Docs: https://docs.binaryedge.io/api-v2/
//  Auth: X-Key header. Supports: ip, domain
//  Endpoint: https://api.binaryedge.io/v2/query/ip/{ip}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BinaryEdgeModule extends BaseApiModule
{
    private const API_ID   = 'binaryedge';
    private const API_NAME = 'BinaryEdge';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://api.binaryedge.io/v2', '/');
        $headers = ['X-Key' => $apiKey];

        $url = $queryType === 'ip'
            ? "{$base}/query/ip/" . urlencode($queryValue)
            : "{$base}/query/domains/subdomain/" . urlencode($queryValue);

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
            $events = $data['events'] ?? [];
            $total  = $data['total'] ?? count($events);
            $ports  = [];
            $protocols = [];
            foreach ($events as $evt) {
                $port = $evt['port'] ?? null;
                if ($port) $ports[$port] = true;
                foreach ($evt['results'] ?? [] as $r) {
                    $proto = $r['origin']['module'] ?? '';
                    if ($proto) $protocols[$proto] = true;
                }
            }
            $portList = array_keys($ports);
            $score = min(50, count($portList) * 3);
            $riskyPorts = array_intersect($portList, [23, 445, 3389, 1433, 3306, 6379, 27017]);
            if (!empty($riskyPorts)) $score = max($score, 60);

            $parts = ["IP {$queryValue}: {$total} scan event(s) on BinaryEdge"];
            if (!empty($portList)) $parts[] = "Open ports: " . implode(', ', array_slice($portList, 0, 15));
            if (!empty($protocols)) $parts[] = "Modules: " . implode(', ', array_slice(array_keys($protocols), 0, 8));

            $tags = [self::API_ID, 'ip', 'scan'];
            if (!empty($riskyPorts)) $tags[] = 'exposed_services';
            $tags[] = $score >= 40 ? 'suspicious' : 'clean';
        } else {
            $subdomains = $data['events'] ?? [];
            $total = $data['total'] ?? count($subdomains);
            $score = min(20, count($subdomains));

            $parts = ["Domain {$queryValue}: {$total} subdomain(s) found on BinaryEdge"];
            if (!empty($subdomains)) $parts[] = "Subdomains: " . implode(', ', array_slice($subdomains, 0, 10));

            $tags = [self::API_ID, 'domain', 'dns', 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(95, 65 + min(30, $total ?? 0)),
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.binaryedge.io/v2/user/subscription', ['X-Key' => $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
