<?php
// =============================================================================
//  CTI — DomainTools Module
//  Queries DomainTools API for WHOIS, domain profile, and risk scoring.
//  API Docs: https://www.domaintools.com/resources/api-documentation/
//  Supports: domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DomainToolsModule extends BaseApiModule
{
    private const API_ID   = 'domaintools';
    private const API_NAME = 'DomainTools';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.domaintools.com/v1', '/');

        // API key format: "username:api_key"
        $parts = explode(':', $apiKey, 2);
        $username = $parts[0] ?? '';
        $key      = $parts[1] ?? $apiKey;

        $timestamp = gmdate('Y-m-d\TH:i:s\Z');
        $signature = hash_hmac('sha256', $username . $timestamp, $key);

        $authParams = http_build_query([
            'api_username' => $username,
            'signature'    => $signature,
            'timestamp'    => $timestamp,
        ]);

        if ($queryType === 'domain') {
            return $this->queryDomain($queryValue, $baseUrl, $authParams);
        }
        return $this->queryIp($queryValue, $baseUrl, $authParams);
    }

    private function queryDomain(string $domain, string $baseUrl, string $authParams): OsintResult
    {
        $url  = "{$baseUrl}/{$domain}/whois/parsed?{$authParams}";
        $resp = HttpClient::get($url, []);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $domain, $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json = $resp['json'];
        $whois = $json['response'] ?? $json['parsed_whois'] ?? [];

        $registrar  = $whois['registrar']['name'] ?? $whois['registrar'] ?? '';
        $created    = $whois['registration']['created'] ?? $whois['create_date'] ?? '';
        $expires    = $whois['registration']['expires'] ?? $whois['expiration_date'] ?? '';
        $nameservers = $whois['name_servers'] ?? [];
        $registrant = $whois['registrant'] ?? '';
        $contacts   = $whois['contacts'] ?? [];

        // Domain age scoring
        $score = 5;
        if ($created) {
            $ageDays = (int)((time() - strtotime($created)) / 86400);
            if ($ageDays < 30) $score = max($score, 60); // Very new domain
            elseif ($ageDays < 90) $score = max($score, 40);
            elseif ($ageDays < 365) $score = max($score, 20);
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 85;

        $summary = "Domain {$domain}: Registrar={$registrar}.";
        if ($created) $summary .= " Created: {$created}.";
        if ($expires) $summary .= " Expires: {$expires}.";
        if (is_array($nameservers) && !empty($nameservers)) {
            $summary .= ' NS: ' . implode(', ', array_slice($nameservers, 0, 3)) . '.';
        }

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: [self::API_ID, 'domain', 'whois'],
            rawData: [
                'domain'       => $domain,
                'registrar'    => $registrar,
                'created'      => $created,
                'expires'      => $expires,
                'name_servers' => $nameservers,
                'registrant'   => $registrant,
            ],
            success: true
        );

        if (is_array($nameservers)) {
            foreach ($nameservers as $ns) {
                if (is_string($ns) && preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $ns)) {
                    $result->addDiscovery('Internet Name', $ns);
                }
            }
        }

        return $result;
    }

    private function queryIp(string $ip, string $baseUrl, string $authParams): OsintResult
    {
        $url  = "{$baseUrl}/reverse-ip/?ip=" . urlencode($ip) . "&{$authParams}";
        $resp = HttpClient::get($url, []);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json    = $resp['json'];
        $domains = $json['response']['ip_addresses'][0]['domain_names'] ?? $json['ip_addresses'] ?? [];

        $count = is_array($domains) ? count($domains) : 0;
        $score = min(30, $count);

        $summary = "IP {$ip}: {$count} domain(s) hosted.";
        if ($count > 0 && is_array($domains)) {
            $sample = array_slice($domains, 0, 5);
            $summary .= ' Sample: ' . implode(', ', $sample) . '.';
        }

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score), confidence: 80,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: [self::API_ID, 'ip', 'reverse_dns'],
            rawData: ['ip' => $ip, 'domain_count' => $count, 'domains' => is_array($domains) ? array_slice($domains, 0, 50) : []],
            success: true
        );

        if (is_array($domains)) {
            foreach (array_slice($domains, 0, 10) as $d) {
                $result->addDiscovery('Internet Name', $d);
            }
        }

        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.domaintools.com/v1', '/');
        $parts = explode(':', $apiKey, 2);
        $ts = gmdate('Y-m-d\TH:i:s\Z');
        $sig = hash_hmac('sha256', ($parts[0] ?? '') . $ts, ($parts[1] ?? $apiKey));
        $auth = http_build_query(['api_username' => $parts[0] ?? '', 'signature' => $sig, 'timestamp' => $ts]);
        $resp = HttpClient::get("{$baseUrl}/account/?{$auth}", []);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
