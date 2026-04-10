<?php
// =============================================================================
//  CTI — Spyse Module
//  API Docs: https://spyse-dev.readme.io/reference
//  Auth: Authorization: Bearer header
//  Endpoint: GET https://api.spyse.com/v4/data/domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SpyseModule extends BaseApiModule
{
    private const API_ID   = 'spyse';
    private const API_NAME = 'Spyse';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. Supports domain and IP.");
        }

        $base = rtrim($baseUrl ?: 'https://api.spyse.com', '/');
        $headers = ['Authorization' => 'Bearer ' . $apiKey];

        if ($queryType === 'domain') {
            $url = "{$base}/v4/data/domain?limit=10&domain=" . urlencode($queryValue);
        } else {
            $url = "{$base}/v4/data/ip?limit=10&ip=" . urlencode($queryValue);
        }

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $items = $data['data']['items'] ?? [];
        $totalCount = $data['data']['total_count'] ?? count($items);

        if (empty($items)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        if ($queryType === 'domain') {
            return $this->parseDomainResponse($items, $totalCount, $queryValue, $resp['elapsed_ms'], $data);
        }

        return $this->parseIpResponse($items, $totalCount, $queryValue, $resp['elapsed_ms'], $data);
    }

    private function parseDomainResponse(array $items, int $totalCount, string $query, int $elapsed, array $rawData): OsintResult
    {
        $first = $items[0] ?? [];
        $dnsA     = $first['dns_records']['A'] ?? [];
        $dnsMx    = $first['dns_records']['MX'] ?? [];
        $dnsNs    = $first['dns_records']['NS'] ?? [];
        $httpInfo = $first['http_extract'] ?? [];
        $certInfo = $first['cert_summary'] ?? [];
        $techList = $first['technologies'] ?? [];

        $ipAddresses = [];
        foreach ($dnsA as $a) {
            $ip = $a['ip'] ?? '';
            if ($ip) $ipAddresses[] = $ip;
        }

        $techNames = [];
        foreach ($techList as $tech) {
            $name = $tech['name'] ?? '';
            if ($name) $techNames[] = $name;
        }

        $score = min(25, count($ipAddresses) * 3);
        if (!empty($certInfo)) $score += 5;
        if (count($techNames) > 10) $score += 10;
        $score = min(50, $score);

        $ipSample  = implode(', ', array_slice($ipAddresses, 0, 5));
        $techSample = implode(', ', array_slice($techNames, 0, 8));
        $summary = "Spyse: Domain {$query} has {$totalCount} record(s). " .
                   "IPs: {$ipSample}. " .
                   "Technologies: {$techSample}. " .
                   "MX records: " . count($dnsMx) . ", NS records: " . count($dnsNs);

        $tags = [self::API_ID, 'domain', 'dns', 'technology'];
        if (!empty($techNames)) $tags[] = 'tech_detected';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(88, 60 + min(28, $totalCount * 3)),
            responseMs: $elapsed, summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $rawData, success: true
        );
    }

    private function parseIpResponse(array $items, int $totalCount, string $query, int $elapsed, array $rawData): OsintResult
    {
        $first = $items[0] ?? [];
        $ports   = $first['ports'] ?? [];
        $vulns   = $first['vulnerabilities'] ?? [];
        $geoInfo = $first['geo_info'] ?? [];

        $country = $geoInfo['country'] ?? 'Unknown';
        $city    = $geoInfo['city'] ?? '';
        $org     = $geoInfo['as_org'] ?? 'Unknown';

        $portNumbers = [];
        foreach ($ports as $p) {
            $num = $p['port'] ?? null;
            if ($num !== null) $portNumbers[] = $num;
        }

        $vulnIds = [];
        foreach ($vulns as $v) {
            $id = $v['id'] ?? '';
            if ($id) $vulnIds[] = $id;
        }

        $score = min(30, count($portNumbers) * 2);
        if (!empty($vulnIds)) $score += min(50, count($vulnIds) * 10);
        $score = min(100, $score);

        $portSample = implode(', ', array_slice($portNumbers, 0, 10));
        $vulnSample = implode(', ', array_slice($vulnIds, 0, 5));
        $summary = "Spyse: IP {$query} (Org: {$org}, {$country}). " .
                   "Open ports: {$portSample}. " .
                   "Vulnerabilities: " . count($vulnIds) . ($vulnSample ? " [{$vulnSample}]" : '');

        $tags = [self::API_ID, 'ip', 'scan'];
        if (!empty($vulnIds)) { $tags[] = 'vulnerable'; $tags[] = 'cve_found'; }
        if (count($portNumbers) > 10) $tags[] = 'many_open_ports';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(90, 60 + min(30, count($portNumbers) + count($vulnIds) * 3)),
            responseMs: $elapsed, summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $rawData, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://api.spyse.com', '/');
        $url = "{$base}/v4/data/account/quota";
        $headers = ['Authorization' => 'Bearer ' . $apiKey];
        $resp = HttpClient::get($url, $headers, 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
