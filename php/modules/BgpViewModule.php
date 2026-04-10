<?php
// =============================================================================
//  CTI — BGPView Module
//  Queries BGPView API for BGP/ASN/prefix information.
//  API Docs: https://bgpview.docs.apiary.io/
//  Free, no key required. Supports: ip, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BgpViewModule extends BaseApiModule
{
    private const API_ID   = 'bgpview';
    private const API_NAME = 'BGPView';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.bgpview.io', '/');

        if ($queryType === 'ip') {
            return $this->queryIp($queryValue, $baseUrl);
        }
        return $this->queryDomain($queryValue, $baseUrl);
    }

    private function queryIp(string $ip, string $baseUrl): OsintResult
    {
        $resp = HttpClient::get("{$baseUrl}/ip/{$ip}", []);

        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data    = $resp['json']['data'] ?? [];
        $prefixes = $data['prefixes'] ?? [];
        $rir     = $data['rir_allocation']['rir_name'] ?? 'Unknown';

        if (empty($prefixes)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $ip, $resp['elapsed_ms']);
        }

        $asnList = [];
        $prefixList = [];
        $orgNames = [];
        foreach ($prefixes as $p) {
            $asn = $p['asn']['asn'] ?? 0;
            $asnName = $p['asn']['name'] ?? '';
            $asnDesc = $p['asn']['description'] ?? '';
            if ($asn) $asnList[$asn] = $asnName ?: $asnDesc;
            $prefix = $p['prefix'] ?? '';
            if ($prefix) $prefixList[] = $prefix;
            $org = $p['name'] ?? $p['description'] ?? '';
            if ($org) $orgNames[$org] = true;
        }

        $score = 10; // Informational
        $summary = "IP {$ip}: RIR={$rir}, " . count($asnList) . " ASN(s), " . count($prefixList) . " prefix(es).";
        if (!empty($asnList)) {
            $first = array_slice($asnList, 0, 3, true);
            $parts = [];
            foreach ($first as $asn => $name) {
                $parts[] = "AS{$asn}" . ($name ? " ({$name})" : '');
            }
            $summary .= ' ASNs: ' . implode(', ', $parts) . '.';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: 'info', confidence: 90,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: [self::API_ID, 'ip', 'bgp', 'network'],
            rawData: [
                'ip'       => $ip,
                'rir'      => $rir,
                'asns'     => $asnList,
                'prefixes' => $prefixList,
                'orgs'     => array_keys($orgNames),
            ],
            success: true
        );
    }

    private function queryDomain(string $domain, string $baseUrl): OsintResult
    {
        // Resolve domain to IP first, then look up
        $ip = gethostbyname($domain);
        if ($ip === $domain) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Could not resolve {$domain}", 0);
        }
        $result = $this->queryIp($ip, $baseUrl);
        if ($result->success) {
            $result->addDiscovery('IP Address', $ip);
        }
        return $result;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.bgpview.io', '/');
        $resp = HttpClient::get("{$baseUrl}/ip/8.8.8.8", []);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
