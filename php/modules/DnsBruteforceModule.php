<?php
// =============================================================================
//  CTI — DNS Brute-forcer Module
//  Internal tool (no external API). Supports: domain
//  Uses dns_get_record() to check common subdomain prefixes
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsBruteforceModule extends BaseApiModule
{
    private const API_ID   = 'dns-bruteforce';
    private const API_NAME = 'DNS Brute-forcer';
    private const SUPPORTED = ['domain'];

    private const COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'admin',
        'blog', 'shop', 'cdn', 'ns1', 'ns2', 'mx', 'vpn', 'remote'
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $startTime = microtime(true);
        $resolved = [];
        $failed   = [];

        foreach (self::COMMON_SUBDOMAINS as $prefix) {
            $fqdn = $prefix . '.' . $queryValue;
            try {
                $records = @dns_get_record($fqdn, DNS_A | DNS_AAAA | DNS_CNAME);
                if ($records && count($records) > 0) {
                    $ips = [];
                    foreach ($records as $rec) {
                        $type = isset($rec['type']) ? $rec['type'] : '';
                        if ($type === 'A' && isset($rec['ip'])) {
                            $ips[] = $rec['ip'];
                        } elseif ($type === 'AAAA' && isset($rec['ipv6'])) {
                            $ips[] = $rec['ipv6'];
                        } elseif ($type === 'CNAME' && isset($rec['target'])) {
                            $ips[] = 'CNAME:' . $rec['target'];
                        }
                    }
                    $resolved[$fqdn] = $ips;
                } else {
                    $failed[] = $fqdn;
                }
            } catch (\Exception $e) {
                $failed[] = $fqdn;
            }
        }

        $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
        $resolvedCount = count($resolved);
        $checkedCount  = count(self::COMMON_SUBDOMAINS);

        if ($resolvedCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $elapsedMs);
        }

        $score = min(30, $resolvedCount * 2);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 60 + $resolvedCount * 3);

        $parts = ["{$resolvedCount} of {$checkedCount} common subdomains resolved for {$queryValue}"];

        $subList = array_keys($resolved);
        $parts[] = "Resolved: " . implode(', ', $subList);

        $tags = [self::API_ID, 'domain', 'dns', 'subdomains', 'bruteforce'];
        if ($resolvedCount > 10) $tags[] = 'large_infrastructure';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $elapsedMs, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['resolved_count' => $resolvedCount, 'checked_count' => $checkedCount, 'resolved' => $resolved],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $startTime = microtime(true);
        try {
            $records = @dns_get_record('www.google.com', DNS_A);
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            if ($records && count($records) > 0) {
                return ['status' => 'healthy', 'latency_ms' => $elapsedMs, 'error' => null];
            }
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => 'DNS resolution failed'];
        } catch (\Exception $e) {
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => $e->getMessage()];
        }
    }
}
