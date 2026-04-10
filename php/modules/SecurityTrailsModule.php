<?php
// =============================================================================
//  CTI — SECURITYTRAILS MODULE HANDLER
//  php/modules/SecurityTrailsModule.php
//
//  Domain and IP intelligence via SecurityTrails API.
//  API Docs: https://docs.securitytrails.com
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SecurityTrailsModule extends BaseApiModule
{
    private const API_ID   = 'securitytrails';
    private const API_NAME = 'SecurityTrails';

    /**
     * Execute a query against SecurityTrails.
     *
     * @param  string $queryType  "domain" or "ip"
     * @param  string $queryValue The domain or IP to look up
     * @param  string $apiKey     APIKEY for SecurityTrails
     * @param  string $baseUrl    Base URL (default: https://api.securitytrails.com/v1)
     * @return OsintResult
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        $headers = ['APIKEY' => $apiKey];

        switch ($queryType) {
            case 'domain':
                return $this->queryDomain($queryValue, $headers, $baseUrl);
            case 'ip':
                return $this->queryIP($queryValue, $headers, $baseUrl);
            default:
                return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }
    }

    /**
     * Query domain info and subdomains.
     */
    private function queryDomain(string $domain, array $headers, string $baseUrl): OsintResult
    {
        // Fetch domain info
        $infoUrl = rtrim($baseUrl, '/') . '/domain/' . urlencode($domain);
        $infoResponse = HttpClient::get($infoUrl, $headers);

        $statusCheck = $this->checkHttpErrors($infoResponse, $domain);
        if ($statusCheck !== null) {
            return $statusCheck;
        }

        $domainData = $infoResponse['json'] ?? [];

        // Fetch subdomains
        $subUrl = rtrim($baseUrl, '/') . '/domain/' . urlencode($domain) . '/subdomains';
        $subResponse = HttpClient::get($subUrl, $headers);

        $subdomains = [];
        $subdomainCount = 0;

        if ($subResponse['status'] === 200 && $subResponse['json'] !== null) {
            $subdomains = $subResponse['json']['subdomains'] ?? [];
            $subdomainCount = count($subdomains);
        }

        // Score based on subdomain count (larger attack surface = higher score, cap at 60)
        if ($subdomainCount === 0) {
            $score = 5;
        } elseif ($subdomainCount <= 10) {
            $score = 15;
        } elseif ($subdomainCount <= 50) {
            $score = 30;
        } elseif ($subdomainCount <= 200) {
            $score = 45;
        } else {
            $score = 60;
        }

        $severity = OsintResult::scoreToSeverity($score);

        // Build tags
        $tags = [self::API_ID, 'domain', 'dns'];
        if ($subdomainCount > 50) {
            $tags[] = 'large_attack_surface';
        }

        // Extract useful domain info
        $hostname = $domainData['hostname'] ?? $domain;
        $alexa    = $domainData['alexa_rank'] ?? null;
        $a_records = $domainData['current_dns']['a']['values'] ?? [];

        $ips = [];
        foreach (array_slice($a_records, 0, 3) as $record) {
            $ips[] = $record['ip'] ?? '';
        }
        $ipsStr = !empty($ips) ? implode(', ', array_filter($ips)) : 'N/A';

        $summary = "SecurityTrails: {$domain} has {$subdomainCount} subdomain(s). Resolves to: {$ipsStr}.";
        if ($alexa !== null) {
            $summary .= " Alexa rank: {$alexa}.";
        }

        $totalElapsed = $infoResponse['elapsed_ms'] + ($subResponse['elapsed_ms'] ?? 0);
        $confidence = 75;

        $rawData = [
            'domain_info' => $domainData,
            'subdomains'  => array_slice($subdomains, 0, 50),
            'subdomain_count' => $subdomainCount,
        ];

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $totalElapsed,
            summary:    $summary,
            tags:       $tags,
            rawData:    $rawData,
            success:    true,
            error:      null
        );
    }

    /**
     * Query domains associated with an IP.
     */
    private function queryIP(string $ip, array $headers, string $baseUrl): OsintResult
    {
        $url = rtrim($baseUrl, '/') . '/domains/list?include=current_dns.a.values.ip&filter=' . urlencode($ip);
        $response = HttpClient::get($url, $headers);

        $statusCheck = $this->checkHttpErrors($response, $ip);
        if ($statusCheck !== null) {
            return $statusCheck;
        }

        $data = $response['json'];
        if ($data === null) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $response['elapsed_ms']);
        }

        $records = $data['records'] ?? [];
        $domainCount = count($records);

        // Score based on number of associated domains
        if ($domainCount === 0) {
            $score = 5;
        } elseif ($domainCount <= 5) {
            $score = 10;
        } elseif ($domainCount <= 20) {
            $score = 25;
        } else {
            $score = 40;
        }

        $severity = OsintResult::scoreToSeverity($score);

        // Extract domain names
        $domainNames = [];
        foreach (array_slice($records, 0, 10) as $record) {
            $domainNames[] = $record['hostname'] ?? $record['name'] ?? '';
        }
        $domainsStr = !empty($domainNames) ? implode(', ', array_filter($domainNames)) : 'none';

        $summary = "SecurityTrails: {$ip} is associated with {$domainCount} domain(s). Top domains: {$domainsStr}.";

        $tags = [self::API_ID, 'ip', 'reverse_dns'];

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: 70,
            responseMs: $response['elapsed_ms'],
            summary:    $summary,
            tags:       $tags,
            rawData:    $data,
            success:    true,
            error:      null
        );
    }

    /**
     * Check for common HTTP error codes and return an appropriate OsintResult or null if OK.
     */
    private function checkHttpErrors(array $response, string $queryValue): ?OsintResult
    {
        if ($response['status'] === 0) {
            return OsintResult::error(self::API_ID, self::API_NAME, $response['error'] ?? 'Connection failed', $response['elapsed_ms']);
        }
        if ($response['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $response['elapsed_ms']);
        }
        if ($response['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$response['status']}", $response['elapsed_ms']);
        }
        return null;
    }

    /**
     * Health check: GET /ping endpoint.
     *
     * @param  string $apiKey
     * @param  string $baseUrl
     * @return array  ['status'=>'healthy'|'down', 'latency_ms'=>int, 'error'=>?string]
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['APIKEY' => $apiKey];
        $url = rtrim($baseUrl, '/') . '/ping';
        $response = HttpClient::get($url, $headers);

        if ($response['status'] === 200) {
            return [
                'status'     => 'healthy',
                'latency_ms' => $response['elapsed_ms'],
                'error'      => null,
            ];
        }

        return [
            'status'     => 'down',
            'latency_ms' => $response['elapsed_ms'],
            'error'      => $response['error'] ?? "HTTP {$response['status']}",
        ];
    }
}
