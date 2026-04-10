<?php
// =============================================================================
//  CTI — Shodan OSINT Module Handler
//  php/modules/ShodanModule.php
//
//  Queries the Shodan API for IP host information and DNS resolution.
//  API Docs: https://developer.shodan.io/api
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../EventTypes.php';
require_once __DIR__ . '/BaseApiModule.php';

class ShodanModule extends BaseApiModule
{
    private const API_ID   = 'shodan';
    private const API_NAME = 'Shodan';

    private const SUPPORTED_TYPES = ['ip', 'domain'];
    private const RISKY_PORTS = [21, 22, 23, 445, 3389, 5900, 8080, 8443];

    /**
     * Execute a threat intelligence query against Shodan.
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): array
    {
        if (!in_array($queryType, self::SUPPORTED_TYPES, true)) {
            return [OsintResult::error(
                self::API_ID,
                self::API_NAME,
                "Unsupported query type: {$queryType}. Shodan supports IP and domain lookups."
            )];
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.shodan.io', '/');

        if ($queryType === 'domain') {
            return $this->queryDomain($baseUrl, $queryValue, $apiKey);
        }

        return $this->queryIP($baseUrl, $queryValue, $apiKey);
    }

    /**
     * Run a health check against the Shodan API.
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.shodan.io', '/');
        $url = "{$baseUrl}/api-info?key=" . urlencode($apiKey);

        $response = HttpClient::get($url);

        if ($response['error'] || $response['status'] === 0) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => $response['error'] ?? 'Connection failed'];
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => 'Invalid API key'];
        }
        if ($response['status'] >= 200 && $response['status'] < 300) {
            return ['status' => 'healthy', 'latency_ms' => $response['elapsed_ms'], 'error' => null];
        }

        return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => "HTTP {$response['status']}"];
    }

    /**
     * Query Shodan for IP host information.
     */
    private function queryIP(string $baseUrl, string $ip, string $apiKey): array
    {
        $url = "{$baseUrl}/shodan/host/" . urlencode($ip) . "?key=" . urlencode($apiKey);
        $response = HttpClient::get($url);

        $responseError = $this->responseError($response, $ip);
        if ($responseError !== null) {
            return [$responseError];
        }

        $json = $response['json'];
        if (!is_array($json) || empty($json)) {
            return [OsintResult::error(self::API_ID, self::API_NAME, 'Unexpected response format', $response['elapsed_ms'])];
        }

        return $this->buildIpResults($json, $ip, $response['elapsed_ms']);
    }

    /**
     * Query Shodan DNS resolve for domain lookups.
     */
    private function queryDomain(string $baseUrl, string $domain, string $apiKey): array
    {
        $url = "{$baseUrl}/dns/resolve?hostnames=" . urlencode($domain) . "&key=" . urlencode($apiKey);
        $response = HttpClient::get($url);

        $responseError = $this->responseError($response, $domain);
        if ($responseError !== null) {
            return [$responseError];
        }

        $json = $response['json'];
        if (!is_array($json) || empty($json)) {
            return [OsintResult::error(self::API_ID, self::API_NAME, 'Unexpected response format', $response['elapsed_ms'])];
        }

        $resolvedIP = $json[$domain] ?? null;
        if (!$resolvedIP) {
            return [OsintResult::notFound(self::API_ID, self::API_NAME, $domain, $response['elapsed_ms'])];
        }

        // Resolve domain first, then produce the same event model as IP lookups.
        $elapsedDns = $response['elapsed_ms'];
        $ipResults = $this->queryIP($baseUrl, $resolvedIP, $apiKey);

        foreach ($ipResults as $result) {
            if (!$result instanceof OsintResult || !$result->success) {
                continue;
            }
            if ($result->dataType === EventTypes::IP_ADDRESS) {
                $result->summary = "Domain {$domain} resolves to {$resolvedIP}. " . $result->summary;
                $result->responseMs += $elapsedDns;
                $result->addDiscovery(EventTypes::INTERNET_NAME, $domain);
            }
            $result->tags[] = 'domain';
            $result->tags = array_values(array_unique($result->tags));
        }

        return $ipResults;
    }

    /**
     * Normalize a Shodan host payload into SpiderFoot-style data elements.
     *
     * @return OsintResult[]
     */
    private function buildIpResults(array $data, string $ip, int $elapsedMs): array
    {
        $ports     = $this->normalizePorts($data['ports'] ?? []);
        $vulns     = $this->extractVulnerabilityIds($data['vulns'] ?? []);
        $os        = $data['os'] ?? 'Unknown';
        $org       = $data['org'] ?? 'Unknown';
        $isp       = $data['isp'] ?? 'Unknown';
        $country   = $data['country_name'] ?? ($data['country_code'] ?? 'Unknown');
        $hostnames = $this->extractStringList($data['hostnames'] ?? []);
        $domains   = $this->extractStringList($data['domains'] ?? []);

        $portCount = count($ports);
        $vulnCount = count($vulns);

        // Keep risk behaviour stable: vulnerabilities dominate score; many ports add risk.
        $vulnScore = min(70, $vulnCount * 10);
        $portScore = min(30, max(0, $portCount - 3) * 2);
        $score = max(0, min(100, $vulnScore + $portScore));

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 60 + $portCount + ($vulnCount * 5));

        $portList = !empty($ports) ? implode(', ', array_slice($ports, 0, 10)) : 'none detected';
        $summary = "IP {$ip} (Org: {$org}, Country: {$country}): " .
                   "{$portCount} open port(s) [{$portList}]";

        if ($vulnCount > 0) {
            $vulnSample = implode(', ', array_slice($vulns, 0, 5));
            $summary .= ", {$vulnCount} known vulnerability(ies) [{$vulnSample}]";
        }
        if ($os && $os !== 'Unknown') {
            $summary .= ". OS: {$os}";
        }

        $tags = [self::API_ID, 'ip'];
        if ($vulnCount > 0) {
            $tags[] = 'vulnerable';
            $tags[] = 'cve_found';
        }
        if ($portCount > 10) {
            $tags[] = 'many_open_ports';
        }
        if ($score >= 70) {
            $tags[] = 'malicious';
        } elseif ($score >= 40) {
            $tags[] = 'suspicious';
        } else {
            $tags[] = 'clean';
        }
        foreach (self::RISKY_PORTS as $riskyPort) {
            if (in_array($riskyPort, $ports, true)) {
                $tags[] = "port_{$riskyPort}";
            }
        }
        if (!empty($hostnames)) {
            $tags[] = 'has_hostnames';
        }

        $results = [];

        $primary = new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $elapsedMs,
            summary:    $summary,
            tags:       array_values(array_unique($tags)),
            rawData:    $data,
            success:    true,
            dataType:   EventTypes::IP_ADDRESS
        );

        foreach ($hostnames as $hn) {
            $primary->addDiscovery(EventTypes::INTERNET_NAME, $hn);
        }
        foreach ($vulns as $cve) {
            $primary->addDiscovery(EventTypes::VULNERABILITY, $cve);
        }
        foreach ($domains as $domain) {
            $primary->addDiscovery(EventTypes::INTERNET_NAME, $domain);
        }
        $results[] = $primary;

        $asnMembership = $this->extractAsMembership($data['asn'] ?? null);
        if ($asnMembership !== null) {
            $results[] = new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      0,
                severity:   'info',
                confidence: 90,
                responseMs: 0,
                summary:    $asnMembership,
                tags:       [self::API_ID, 'asn', 'bgp'],
                rawData:    [
                    'asn' => $data['asn'] ?? null,
                    'isp' => $isp,
                    'org' => $org,
                ],
                success:    true,
                dataType:   'BGP AS Membership'
            );
        }

        foreach ($ports as $port) {
            $portTags = [self::API_ID, 'port', "port_{$port}"];
            $portScore = in_array($port, self::RISKY_PORTS, true) ? 25 : 0;
            if ($portScore > 0) {
                $portTags[] = 'risky_port';
            }

            $results[] = new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      $portScore,
                severity:   OsintResult::scoreToSeverity($portScore),
                confidence: 80,
                responseMs: 0,
                summary:    "{$ip}:{$port}",
                tags:       array_values(array_unique($portTags)),
                rawData:    $this->findPortPayload($data, $port) ?? ['ip' => $ip, 'port' => $port],
                success:    true,
                dataType:   EventTypes::OPEN_TCP_PORT
            );
        }

        $location = $this->buildLocationLabel($data);
        if ($location !== null) {
            $results[] = new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      0,
                severity:   'info',
                confidence: 85,
                responseMs: 0,
                summary:    $location,
                tags:       [self::API_ID, 'location'],
                rawData:    [
                    'city' => $data['city'] ?? null,
                    'region_code' => $data['region_code'] ?? null,
                    'country_name' => $data['country_name'] ?? null,
                    'country_code' => $data['country_code'] ?? null,
                    'latitude' => $data['latitude'] ?? null,
                    'longitude' => $data['longitude'] ?? null,
                ],
                success:    true,
                dataType:   'Physical Location'
            );
        }

        $rawSummary = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (!is_string($rawSummary) || $rawSummary === '') {
            $rawSummary = 'Raw Shodan host payload available.';
        }

        $results[] = new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      0,
            severity:   'info',
            confidence: 95,
            responseMs: 0,
            summary:    $rawSummary,
            tags:       [self::API_ID, 'raw_data'],
            rawData:    $data,
            success:    true,
            dataType:   EventTypes::RAW_RIR_DATA
        );

        return $results;
    }

    private function responseError(array $response, string $queryValue): ?OsintResult
    {
        if (($response['status'] ?? 0) === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, (int)($response['elapsed_ms'] ?? 0));
        }
        if (($response['status'] ?? 0) === 401 || ($response['status'] ?? 0) === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, (int)($response['elapsed_ms'] ?? 0));
        }
        if (($response['status'] ?? 0) === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, (int)($response['elapsed_ms'] ?? 0));
        }
        if (($response['status'] ?? 0) === 0 || !empty($response['error'])) {
            return OsintResult::error(
                self::API_ID,
                self::API_NAME,
                (string)($response['error'] ?? 'Connection failed'),
                (int)($response['elapsed_ms'] ?? 0)
            );
        }
        if (($response['status'] ?? 0) < 200 || ($response['status'] ?? 0) >= 300) {
            return OsintResult::error(
                self::API_ID,
                self::API_NAME,
                'HTTP ' . (int)($response['status'] ?? 0),
                (int)($response['elapsed_ms'] ?? 0)
            );
        }

        return null;
    }

    /**
     * @return int[]
     */
    private function normalizePorts(mixed $ports): array
    {
        if (!is_array($ports)) {
            return [];
        }

        $out = [];
        foreach ($ports as $port) {
            if (!is_numeric($port)) {
                continue;
            }
            $portInt = (int)$port;
            if ($portInt < 1 || $portInt > 65535) {
                continue;
            }
            $out[$portInt] = $portInt;
        }

        return array_values($out);
    }

    /**
     * @return string[]
     */
    private function extractVulnerabilityIds(mixed $vulns): array
    {
        if (!is_array($vulns)) {
            return [];
        }

        $ids = [];

        if ($this->isList($vulns)) {
            foreach ($vulns as $entry) {
                if (!is_string($entry)) {
                    continue;
                }
                $value = strtoupper(trim($entry));
                if ($value !== '') {
                    $ids[$value] = $value;
                }
            }
            return array_values($ids);
        }

        foreach ($vulns as $key => $value) {
            $k = strtoupper(trim((string)$key));
            if ($k !== '' && str_starts_with($k, 'CVE-')) {
                $ids[$k] = $k;
            }
            if (is_string($value)) {
                $v = strtoupper(trim($value));
                if ($v !== '' && str_starts_with($v, 'CVE-')) {
                    $ids[$v] = $v;
                }
            }
        }

        return array_values($ids);
    }

    /**
     * @return string[]
     */
    private function extractStringList(mixed $values): array
    {
        if (!is_array($values)) {
            return [];
        }

        $list = [];
        foreach ($values as $value) {
            if (!is_string($value)) {
                continue;
            }
            $normalized = trim($value);
            if ($normalized !== '') {
                $list[$normalized] = $normalized;
            }
        }
        return array_values($list);
    }

    private function extractAsMembership(mixed $asn): ?string
    {
        $raw = trim((string)$asn);
        if ($raw === '') {
            return null;
        }

        if (preg_match('/(\d{1,10})/', $raw, $m) === 1) {
            return ltrim($m[1], '0') !== '' ? ltrim($m[1], '0') : '0';
        }

        return $raw;
    }

    private function buildLocationLabel(array $data): ?string
    {
        $city = trim((string)($data['city'] ?? ''));
        $region = trim((string)($data['region_code'] ?? ''));
        $country = trim((string)($data['country_name'] ?? ($data['country_code'] ?? '')));

        if ($city !== '' && $country !== '') {
            return "{$city}, {$country}";
        }
        if ($city !== '' && $region !== '') {
            return "{$city}, {$region}";
        }
        if ($country !== '') {
            return $country;
        }
        if ($region !== '') {
            return $region;
        }

        return null;
    }

    private function findPortPayload(array $data, int $port): ?array
    {
        $entries = $data['data'] ?? null;
        if (!is_array($entries)) {
            return null;
        }

        foreach ($entries as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            if ((int)($entry['port'] ?? 0) === $port) {
                return $entry;
            }
        }

        return null;
    }

    private function isList(array $array): bool
    {
        if (function_exists('array_is_list')) {
            return array_is_list($array);
        }
        return array_keys($array) === range(0, count($array) - 1);
    }
}
