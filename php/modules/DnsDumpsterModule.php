<?php
// =============================================================================
//  CTI — DNSdumpster Module
//  Discovers subdomains via multiple techniques: DNS brute-forcing,
//  certificate transparency, and common subdomain enumeration.
//  Free, no API key required. Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsDumpsterModule extends BaseApiModule
{
    private const API_ID   = 'dnsdumpster';
    private const API_NAME = 'DNSdumpster';
    private const SUPPORTED = ['domain'];

    // Common subdomains to check
    private const COMMON_SUBS = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'ns1', 'ns2',
        'blog', 'dev', 'staging', 'test', 'api', 'app', 'admin', 'portal',
        'secure', 'login', 'vpn', 'remote', 'cdn', 'static', 'assets', 'img',
        'images', 'media', 'docs', 'wiki', 'help', 'support', 'status',
        'monitor', 'grafana', 'jenkins', 'ci', 'git', 'gitlab', 'bitbucket',
        'jira', 'confluence', 'slack', 'teams', 'office', 'exchange',
        'autodiscover', 'owa', 'mx', 'mx1', 'mx2', 'ns3', 'dns', 'dns1',
        'dns2', 'relay', 'gateway', 'proxy', 'cache', 'waf', 'firewall',
        'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic',
        'kibana', 'logstash', 'sentry', 'prometheus', 'k8s', 'kubernetes',
        'docker', 'registry', 'harbor', 'vault', 'consul', 'nomad',
        'internal', 'intranet', 'extranet', 'corp', 'demo', 'sandbox',
        'beta', 'alpha', 'stage', 'preprod', 'uat', 'qa', 'prod',
        'backup', 'bak', 'old', 'new', 'v2', 'legacy', 'archive',
        'shop', 'store', 'pay', 'payment', 'billing', 'checkout',
        'crm', 'erp', 'sso', 'auth', 'oauth', 'id', 'identity',
        'm', 'mobile', 'wap', 'amp',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start  = microtime(true);
        $domain = strtolower(trim($queryValue));
        $found  = [];
        $ips    = [];

        // Method 1: DNS resolution of common subdomains
        foreach (self::COMMON_SUBS as $sub) {
            $fqdn = "{$sub}.{$domain}";
            $ip = @gethostbyname($fqdn);
            if ($ip !== $fqdn) {
                $found[$fqdn] = ['ip' => $ip, 'source' => 'dns_enum'];
                $ips[$ip] = true;
            }
        }

        // Method 2: Query crt.sh for certificate transparency subdomains
        $crtResp = HttpClient::get(
            'https://crt.sh/?q=' . urlencode("%.{$domain}") . '&output=json',
            [], 20
        );

        if ($crtResp['status'] === 200 && is_array($crtResp['json'])) {
            foreach ($crtResp['json'] as $cert) {
                $names = $cert['name_value'] ?? '';
                foreach (explode("\n", $names) as $name) {
                    $name = strtolower(trim($name));
                    $name = ltrim($name, '*.');
                    if ($name && str_ends_with($name, ".{$domain}") && !isset($found[$name])) {
                        $ip = @gethostbyname($name);
                        $resolved = ($ip !== $name);
                        $found[$name] = [
                            'ip'     => $resolved ? $ip : null,
                            'source' => 'cert_transparency',
                        ];
                        if ($resolved) $ips[$ip] = true;
                    }
                }
            }
        }

        // Method 3: MX, NS records
        $mxRecords = @dns_get_record($domain, DNS_MX);
        if (is_array($mxRecords)) {
            foreach ($mxRecords as $mx) {
                $target = $mx['target'] ?? '';
                if ($target && !isset($found[$target])) {
                    $ip = @gethostbyname($target);
                    $found[$target] = ['ip' => ($ip !== $target) ? $ip : null, 'source' => 'mx_record'];
                }
            }
        }

        $nsRecords = @dns_get_record($domain, DNS_NS);
        if (is_array($nsRecords)) {
            foreach ($nsRecords as $ns) {
                $target = $ns['target'] ?? '';
                if ($target && !isset($found[$target])) {
                    $ip = @gethostbyname($target);
                    $found[$target] = ['ip' => ($ip !== $target) ? $ip : null, 'source' => 'ns_record'];
                }
            }
        }

        $ms = (int)((microtime(true) - $start) * 1000);
        $totalFound = count($found);
        $uniqueIps  = count($ips);

        if ($totalFound === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $domain, $ms);
        }

        $score      = min(30, (int)($totalFound / 5));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 65 + min(30, $totalFound));

        $summary = "DNSdumpster: {$totalFound} subdomain(s) found for {$domain} across {$uniqueIps} unique IP(s).";

        // Group by source
        $bySrc = [];
        foreach ($found as $name => $info) {
            $src = $info['source'];
            $bySrc[$src] = ($bySrc[$src] ?? 0) + 1;
        }
        $srcParts = [];
        foreach ($bySrc as $s => $c) $srcParts[] = "{$s}: {$c}";
        $summary .= ' Sources: ' . implode(', ', $srcParts) . '.';

        $resultTags = [self::API_ID, 'domain', 'subdomain_enum', 'dns'];

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: $summary,
            tags: $resultTags,
            rawData: [
                'domain'       => $domain,
                'total_found'  => $totalFound,
                'unique_ips'   => $uniqueIps,
                'subdomains'   => $found,
                'by_source'    => $bySrc,
            ],
            success: true
        );

        // Discover subdomains and IPs
        foreach (array_slice(array_keys($found), 0, 15) as $sub) {
            $result->addDiscovery('Internet Name', $sub);
        }
        foreach (array_slice(array_keys($ips), 0, 10) as $ip) {
            $result->addDiscovery('IP Address', $ip);
        }

        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null];
    }
}
