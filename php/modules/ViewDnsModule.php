<?php
// =============================================================================
//  CTI — ViewDNS.info Module
//  API Docs: https://viewdns.info/api/docs/
//  Auth: apikey param. Supports: ip, domain
//  Endpoint: https://api.viewdns.info/{tool}/?{params}&apikey={key}&output=json
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ViewDnsModule extends BaseApiModule
{
    private const API_ID   = 'viewdns';
    private const API_NAME = 'ViewDNS.info';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = 'https://api.viewdns.info';

        if ($queryType === 'ip') {
            $url = "{$base}/reversedns/?ip=" . urlencode($queryValue) . "&apikey=" . urlencode($apiKey) . "&output=json";
        } else {
            $url = "{$base}/dnsrecord/?domain=" . urlencode($queryValue) . "&recordtype=ANY&apikey=" . urlencode($apiKey) . "&output=json";
        }

        $resp = HttpClient::get($url, [], 15);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data || !isset($data['response'])) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid response', $resp['elapsed_ms']);

        $response = $data['response'];

        if ($queryType === 'ip') {
            $rdns = $response['rdns'] ?? [];
            $count = count($rdns);
            $names = array_map(fn($r) => $r['name'] ?? '', array_slice($rdns, 0, 10));

            $parts = ["IP {$queryValue}: {$count} reverse DNS record(s) via ViewDNS"];
            if (!empty($names)) $parts[] = "Hostnames: " . implode(', ', array_filter($names));

            $score = min(20, $count);
            $tags = [self::API_ID, 'ip', 'dns', 'clean'];
        } else {
            $records = $response['records'] ?? [];
            $count = count($records);

            $parts = ["Domain {$queryValue}: {$count} DNS record(s) via ViewDNS"];
            foreach (array_slice($records, 0, 5) as $r) {
                $parts[] = ($r['type'] ?? '?') . ": " . ($r['data'] ?? '');
            }

            $score = 5;
            $tags = [self::API_ID, 'domain', 'dns', 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score), confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: $tags, rawData: $response, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.viewdns.info/dnsrecord/?domain=google.com&recordtype=A&apikey=' . urlencode($apiKey) . '&output=json', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
