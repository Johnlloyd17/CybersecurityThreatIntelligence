<?php
// =============================================================================
//  CTI — DNS Resolver Module
//  Uses PHP's built-in dns_get_record() — no external API needed.
//  Supports: domain, ip (reverse DNS)
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../EventTypes.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsResolverModule extends BaseApiModule
{
    private const API_ID   = 'dns-resolver';
    private const API_NAME = 'DNS Resolver';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);

        if ($queryType === 'ip') {
            return $this->reverseLookup($queryValue, $start);
        }

        return $this->forwardLookup($queryValue, $start);
    }

    private function forwardLookup(string $domain, float $start): OsintResult
    {
        $records = [];
        $types = [DNS_A, DNS_AAAA, DNS_MX, DNS_NS, DNS_TXT, DNS_CNAME, DNS_SOA];

        foreach ($types as $type) {
            $result = @dns_get_record($domain, $type);
            if ($result) $records = array_merge($records, $result);
        }

        $ms = (int)((microtime(true) - $start) * 1000);

        if (empty($records)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $domain, $ms);
        }

        // Organize by type
        $byType = [];
        foreach ($records as $r) {
            $t = $r['type'] ?? 'UNKNOWN';
            $byType[$t][] = $r;
        }

        $parts = ["Domain {$domain}: " . count($records) . " DNS record(s) found"];
        // A records
        if (isset($byType['A'])) {
            $aIps = array_map(fn($r) => $r['ip'] ?? '', $byType['A']);
            $parts[] = "A: " . implode(', ', array_filter($aIps));
        }
        if (isset($byType['AAAA'])) {
            $parts[] = count($byType['AAAA']) . " AAAA record(s)";
        }
        if (isset($byType['MX'])) {
            $mx = array_map(fn($r) => ($r['target'] ?? '') . ' (pri:' . ($r['pri'] ?? '?') . ')', $byType['MX']);
            $parts[] = "MX: " . implode(', ', $mx);
        }
        if (isset($byType['NS'])) {
            $ns = array_map(fn($r) => $r['target'] ?? '', $byType['NS']);
            $parts[] = "NS: " . implode(', ', array_filter($ns));
        }
        if (isset($byType['TXT'])) {
            $txtCount = count($byType['TXT']);
            $parts[] = "{$txtCount} TXT record(s)";
            // Check for SPF, DMARC
            foreach ($byType['TXT'] as $txt) {
                $val = $txt['txt'] ?? '';
                if (stripos($val, 'v=spf') !== false) $parts[] = "SPF configured";
                if (stripos($val, 'v=DMARC') !== false) $parts[] = "DMARC configured";
            }
        }

        // DNS resolution is informational
        $score      = 5;
        $severity   = 'info';
        $confidence = 95;
        $tags       = [self::API_ID, 'domain', 'dns'];

        // Check for security misconfigs
        if (!isset($byType['TXT'])) $tags[] = 'no_txt';

        $tags[] = 'clean';

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['records' => $records, 'by_type' => array_map(fn($arr) => count($arr), $byType)],
            success: true
        );

        // Populate discoveries for enrichment chaining
        if (isset($byType['A'])) {
            foreach ($byType['A'] as $r) {
                $ip = $r['ip'] ?? '';
                if ($ip !== '') $result->addDiscovery(EventTypes::IP_ADDRESS, $ip);
            }
        }
        if (isset($byType['AAAA'])) {
            foreach ($byType['AAAA'] as $r) {
                $ip = $r['ipv6'] ?? '';
                if ($ip !== '') $result->addDiscovery(EventTypes::IPV6_ADDRESS, $ip);
            }
        }
        if (isset($byType['MX'])) {
            foreach ($byType['MX'] as $r) {
                $target = $r['target'] ?? '';
                if ($target !== '') $result->addDiscovery(EventTypes::INTERNET_NAME, $target);
            }
        }
        if (isset($byType['NS'])) {
            foreach ($byType['NS'] as $r) {
                $target = $r['target'] ?? '';
                if ($target !== '') $result->addDiscovery(EventTypes::INTERNET_NAME, $target);
            }
        }

        return $result;
    }

    private function reverseLookup(string $ip, float $start): OsintResult
    {
        $hostname = @gethostbyaddr($ip);
        $ms = (int)((microtime(true) - $start) * 1000);

        if (!$hostname || $hostname === $ip) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 80,
                responseMs: $ms,
                summary: "IP {$ip}: No reverse DNS (PTR) record found.",
                tags: [self::API_ID, 'ip', 'no_rdns'],
                rawData: ['hostname' => null], success: true
            );
        }

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 95,
            responseMs: $ms,
            summary: "IP {$ip}: Reverse DNS resolves to {$hostname}.",
            tags: [self::API_ID, 'ip', 'dns', 'clean'],
            rawData: ['hostname' => $hostname], success: true
        );
        $result->addDiscovery(EventTypes::INTERNET_NAME, $hostname);
        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $result = @dns_get_record('google.com', DNS_A);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($result) return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => 'DNS resolution failed'];
    }
}
