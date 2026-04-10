<?php
// =============================================================================
//  CTI — ZoomEye Module
//  Queries ZoomEye cyberspace search engine for host/service information.
//  API Docs: https://www.zoomeye.org/doc
//  Supports: ip, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ZoomEyeModule extends BaseApiModule
{
    private const API_ID   = 'zoomeye';
    private const API_NAME = 'ZoomEye';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.zoomeye.org', '/');
        $headers = ['API-KEY' => $apiKey];

        // Build query based on type
        $query = ($queryType === 'ip') ? "ip:{$queryValue}" : "hostname:{$queryValue}";
        $url   = "{$baseUrl}/host/search?query=" . urlencode($query) . "&page=1";

        $resp = HttpClient::get($url, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json    = $resp['json'];
        $total   = $json['total'] ?? 0;
        $matches = $json['matches'] ?? [];

        if ($total === 0 || empty($matches)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $ports     = [];
        $services  = [];
        $os        = [];
        $countries = [];
        $vulns     = [];

        foreach ($matches as $m) {
            $port = $m['portinfo']['port'] ?? 0;
            if ($port) $ports[$port] = $m['portinfo']['service'] ?? 'unknown';

            $svc = $m['portinfo']['product'] ?? '';
            if ($svc) $services[$svc] = ($m['portinfo']['version'] ?? '');

            $osName = $m['portinfo']['os'] ?? '';
            if ($osName) $os[$osName] = true;

            $country = $m['geoinfo']['country']['names']['en'] ?? '';
            if ($country) $countries[$country] = true;

            foreach ($m['portinfo']['vulns'] ?? [] as $vuln) {
                $vulns[] = $vuln;
            }
        }

        $openPortCount = count($ports);
        $vulnCount     = count($vulns);

        $score = 0;
        if ($vulnCount > 0) $score = max($score, min(90, 50 + $vulnCount * 10));
        if ($openPortCount > 10) $score = max($score, 50);
        elseif ($openPortCount > 5) $score = max($score, 30);
        else $score = max($score, 10);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 70 + min(25, $openPortCount * 3));

        $summary = "ZoomEye: {$total} result(s) for {$queryValue}. {$openPortCount} port(s) detected.";
        if ($vulnCount > 0) $summary .= " {$vulnCount} vulnerability(ies) identified.";
        if (!empty($services)) {
            $svcList = [];
            foreach (array_slice($services, 0, 5, true) as $s => $v) {
                $svcList[] = $v ? "{$s}/{$v}" : $s;
            }
            $summary .= ' Services: ' . implode(', ', $svcList) . '.';
        }

        $resultTags = [self::API_ID, $queryType, 'infrastructure'];
        if ($vulnCount > 0) $resultTags[] = 'vulnerabilities';

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'total_results' => $total,
                'ports'         => $ports,
                'services'      => $services,
                'os'            => array_keys($os),
                'countries'     => array_keys($countries),
                'vulns'         => array_slice($vulns, 0, 20),
            ],
            success: true
        );

        // Discover IPs from results
        foreach ($matches as $m) {
            $ip = $m['ip'] ?? '';
            if ($ip && $ip !== $queryValue && filter_var($ip, FILTER_VALIDATE_IP)) {
                $result->addDiscovery('IP Address', $ip);
            }
        }

        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.zoomeye.org', '/');
        $headers = ['API-KEY' => $apiKey];
        $resp = HttpClient::get("{$baseUrl}/resources-info", $headers);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
