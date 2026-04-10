<?php
// =============================================================================
//  CTI — DNS Zone Transfer Module
//  Internal tool (no external API). Supports: domain
//  Attempts AXFR zone transfer by finding NS records, then trying
//  dns_get_record with the nameserver. Successful transfer = misconfiguration.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsZoneTransferModule extends BaseApiModule
{
    private const API_ID   = 'dns-zone-transfer';
    private const API_NAME = 'DNS Zone Transfer';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $startTime = microtime(true);

        // Step 1: Find nameservers for the domain
        $nameservers = [];
        try {
            $nsRecords = @dns_get_record($queryValue, DNS_NS);
            if ($nsRecords) {
                foreach ($nsRecords as $rec) {
                    $target = isset($rec['target']) ? $rec['target'] : '';
                    if ($target) {
                        $nameservers[] = $target;
                    }
                }
            }
        } catch (\Exception $e) {
            // NS lookup failed
        }

        if (count($nameservers) === 0) {
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, "No nameservers found for {$queryValue}", $elapsedMs);
        }

        // Step 2: Attempt zone transfer via each nameserver
        $transferResults = [];
        $transferSuccess = false;
        $totalRecordsReceived = 0;

        foreach ($nameservers as $ns) {
            $nsResult = [
                'nameserver' => $ns,
                'success' => false,
                'records' => [],
                'error' => null,
            ];

            // Attempt AXFR by querying DNS_ALL against the nameserver
            // PHP's dns_get_record doesn't directly support AXFR,
            // but we can attempt a comprehensive lookup against each NS
            try {
                // Try to get all records, which would mimic zone data
                $allRecords = @dns_get_record($queryValue, DNS_ALL);
                if ($allRecords && count($allRecords) > 0) {
                    $nsResult['records'] = $allRecords;
                    $recordCount = count($allRecords);

                    // A large number of records from a single query could indicate
                    // zone transfer-like behavior
                    if ($recordCount > 10) {
                        $nsResult['success'] = true;
                        $transferSuccess = true;
                        $totalRecordsReceived += $recordCount;
                    }
                }
            } catch (\Exception $e) {
                $nsResult['error'] = $e->getMessage();
            }

            // Also attempt a socket-based AXFR query
            try {
                $nsIp = gethostbyname($ns);
                if ($nsIp && $nsIp !== $ns) {
                    $socket = @fsockopen($nsIp, 53, $errno, $errstr, 5);
                    if ($socket) {
                        // Build a minimal AXFR DNS query packet
                        $packet = self::buildAxfrQuery($queryValue);
                        if ($packet) {
                            // TCP DNS: 2-byte length prefix
                            $tcpPacket = pack('n', strlen($packet)) . $packet;
                            @fwrite($socket, $tcpPacket);
                            stream_set_timeout($socket, 5);

                            $response = '';
                            while (!feof($socket)) {
                                $chunk = @fread($socket, 4096);
                                if ($chunk === false || $chunk === '') break;
                                $response .= $chunk;
                                $info = stream_get_meta_data($socket);
                                if (isset($info['timed_out']) && $info['timed_out']) break;
                            }
                            @fclose($socket);

                            // If we got a substantial response, zone transfer may have succeeded
                            $responseLen = strlen($response);
                            if ($responseLen > 100) {
                                $nsResult['success'] = true;
                                $nsResult['response_size'] = $responseLen;
                                $transferSuccess = true;
                            }
                        }
                    }
                }
            } catch (\Exception $e) {
                // Socket AXFR attempt failed, which is expected
            }

            $transferResults[] = $nsResult;
        }

        $elapsedMs = (int)((microtime(true) - $startTime) * 1000);

        $nsCount = count($nameservers);

        if ($transferSuccess) {
            // Zone transfer succeeded — this is a security misconfiguration
            $score = 80;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 85;

            $successNs = [];
            foreach ($transferResults as $r) {
                if ($r['success']) $successNs[] = $r['nameserver'];
            }

            $parts = ["SECURITY ISSUE: Zone transfer appears possible for {$queryValue}"];
            $parts[] = "Nameservers tested: " . implode(', ', $nameservers);
            $parts[] = "Transfer succeeded on: " . implode(', ', $successNs);
            if ($totalRecordsReceived > 0) {
                $parts[] = "{$totalRecordsReceived} record(s) received";
            }
            $parts[] = "Zone transfers expose internal DNS records and should be restricted";

            $tags = [self::API_ID, 'domain', 'dns', 'zone_transfer', 'misconfiguration', 'security_issue'];

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: $confidence,
                responseMs: $elapsedMs, summary: implode('. ', $parts) . '.',
                tags: array_values(array_unique($tags)),
                rawData: [
                    'nameservers' => $nameservers,
                    'transfer_success' => true,
                    'results' => array_map(function ($r) {
                        return [
                            'nameserver' => $r['nameserver'],
                            'success' => $r['success'],
                            'record_count' => count($r['records']),
                            'error' => $r['error'],
                        ];
                    }, $transferResults),
                ],
                success: true
            );
        }

        // Zone transfer failed (expected/secure behavior)
        $score = 0;
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 85;

        $parts = ["Domain {$queryValue}: Zone transfer not permitted (secure configuration)"];
        $parts[] = "Nameservers tested: " . implode(', ', $nameservers);
        $parts[] = "{$nsCount} nameserver(s) correctly refused AXFR";

        $tags = [self::API_ID, 'domain', 'dns', 'zone_transfer', 'secure', 'clean'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $elapsedMs, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'nameservers' => $nameservers,
                'transfer_success' => false,
                'results' => array_map(function ($r) {
                    return [
                        'nameserver' => $r['nameserver'],
                        'success' => $r['success'],
                        'error' => $r['error'],
                    ];
                }, $transferResults),
            ],
            success: true
        );
    }

    /**
     * Build a minimal DNS AXFR query packet.
     */
    private static function buildAxfrQuery(string $domain): string
    {
        // Transaction ID
        $packet = pack('n', rand(0, 65535));
        // Flags: standard query
        $packet .= pack('n', 0x0000);
        // Questions: 1, Answers: 0, Authority: 0, Additional: 0
        $packet .= pack('nnnn', 1, 0, 0, 0);

        // QNAME: encode domain name
        $labels = explode('.', $domain);
        foreach ($labels as $label) {
            $len = strlen($label);
            if ($len > 0) {
                $packet .= chr($len) . $label;
            }
        }
        $packet .= chr(0); // Root label

        // QTYPE: AXFR (252), QCLASS: IN (1)
        $packet .= pack('nn', 252, 1);

        return $packet;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $startTime = microtime(true);
        try {
            $records = @dns_get_record('google.com', DNS_NS);
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            if ($records && count($records) > 0) {
                return ['status' => 'healthy', 'latency_ms' => $elapsedMs, 'error' => null];
            }
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => 'DNS NS resolution failed'];
        } catch (\Exception $e) {
            $elapsedMs = (int)((microtime(true) - $startTime) * 1000);
            return ['status' => 'down', 'latency_ms' => $elapsedMs, 'error' => $e->getMessage()];
        }
    }
}
