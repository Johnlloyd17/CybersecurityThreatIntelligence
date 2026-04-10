<?php
// =============================================================================
//  CTI — Passive DNS Module
//  Aggregates passive DNS data from multiple free sources:
//  Mnemonic PDNS, Open PDNS, and DNS resolution history.
//  Supports: domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PassiveDnsModule extends BaseApiModule
{
    private const API_ID   = 'passivedns';
    private const API_NAME = 'Passive DNS';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start   = microtime(true);
        $records = [];
        $errors  = [];

        // Source 1: PHP native DNS lookup
        $this->collectNativeDns($queryType, $queryValue, $records);

        // Source 2: Mnemonic PDNS (free, no key)
        $this->collectMnemonicPdns($queryType, $queryValue, $records, $errors);

        // Source 3: API-based PDNS if key provided
        if ($apiKey) {
            $this->collectApiPdns($queryType, $queryValue, $apiKey, $baseUrl, $records, $errors);
        }

        $ms = (int)((microtime(true) - $start) * 1000);

        if (empty($records)) {
            if (!empty($errors)) {
                return OsintResult::error(self::API_ID, self::API_NAME, implode('; ', $errors), $ms);
            }
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $ms);
        }

        // Deduplicate by value+type
        $unique = [];
        foreach ($records as $r) {
            $key = ($r['rrtype'] ?? '') . ':' . ($r['rrvalue'] ?? $r['value'] ?? '');
            if (!isset($unique[$key])) $unique[$key] = $r;
        }
        $records = array_values($unique);

        $totalRecords = count($records);
        $rrTypes = [];
        foreach ($records as $r) {
            $t = $r['rrtype'] ?? 'A';
            $rrTypes[$t] = ($rrTypes[$t] ?? 0) + 1;
        }

        $score      = min(25, (int)($totalRecords / 3));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 60 + min(35, $totalRecords * 2));

        $typeSummary = [];
        foreach ($rrTypes as $t => $c) $typeSummary[] = "{$t}:{$c}";
        $summary = "Passive DNS for {$queryValue}: {$totalRecords} record(s). Types: " . implode(', ', $typeSummary) . '.';

        $resultTags = [self::API_ID, $queryType, 'passive_dns'];

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: $summary,
            tags: $resultTags,
            rawData: [
                'query'    => $queryValue,
                'total'    => $totalRecords,
                'rr_types' => $rrTypes,
                'records'  => array_slice($records, 0, 100),
            ],
            success: true
        );

        // Discover IPs and domains from PDNS records
        foreach (array_slice($records, 0, 20) as $r) {
            $val = $r['rrvalue'] ?? $r['value'] ?? '';
            if (filter_var($val, FILTER_VALIDATE_IP)) {
                $result->addDiscovery('IP Address', $val);
            } elseif (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $val)) {
                $result->addDiscovery('Internet Name', $val);
            }
        }

        return $result;
    }

    private function collectNativeDns(string $queryType, string $value, array &$records): void
    {
        if ($queryType === 'domain') {
            foreach ([DNS_A, DNS_AAAA, DNS_MX, DNS_NS, DNS_TXT, DNS_CNAME] as $type) {
                $res = @dns_get_record($value, $type);
                if (!is_array($res)) continue;
                foreach ($res as $r) {
                    $rrtype = $r['type'] ?? 'A';
                    $val = $r['ip'] ?? $r['ipv6'] ?? $r['target'] ?? $r['txt'] ?? '';
                    if ($val) {
                        $records[] = ['rrtype' => $rrtype, 'rrvalue' => $val, 'source' => 'native_dns'];
                    }
                }
            }
        } elseif ($queryType === 'ip') {
            $host = gethostbyaddr($value);
            if ($host && $host !== $value) {
                $records[] = ['rrtype' => 'PTR', 'rrvalue' => $host, 'source' => 'native_dns'];
            }
        }
    }

    private function collectMnemonicPdns(string $queryType, string $value, array &$records, array &$errors): void
    {
        $url = "https://api.mnemonic.no/pdns/v3/{$value}";
        $resp = HttpClient::get($url, [], 15);

        if ($resp['status'] !== 200 || $resp['error']) {
            if ($resp['error']) $errors[] = "Mnemonic: {$resp['error']}";
            return;
        }

        $data = $resp['json']['data'] ?? [];
        foreach ($data as $entry) {
            $records[] = [
                'rrtype'     => $entry['rrtype'] ?? 'A',
                'rrvalue'    => $entry['answer'] ?? '',
                'first_seen' => $entry['first_seen'] ?? '',
                'last_seen'  => $entry['last_seen'] ?? '',
                'source'     => 'mnemonic',
            ];
        }
    }

    private function collectApiPdns(string $queryType, string $value, string $apiKey, string $baseUrl, array &$records, array &$errors): void
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.passivedns.com', '/');
        $headers = ['Authorization' => "Bearer {$apiKey}"];
        $url = "{$baseUrl}/lookup/" . urlencode($value);

        $resp = HttpClient::get($url, $headers, 15);
        if ($resp['status'] !== 200 || $resp['error']) {
            if ($resp['error']) $errors[] = "API PDNS: {$resp['error']}";
            return;
        }

        $data = $resp['json']['records'] ?? $resp['json']['data'] ?? [];
        foreach ($data as $entry) {
            $records[] = [
                'rrtype'     => $entry['rrtype'] ?? $entry['type'] ?? 'A',
                'rrvalue'    => $entry['rdata'] ?? $entry['value'] ?? '',
                'first_seen' => $entry['time_first'] ?? '',
                'last_seen'  => $entry['time_last'] ?? '',
                'source'     => 'api_pdns',
            ];
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get("https://api.mnemonic.no/pdns/v3/google.com", [], 10);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
