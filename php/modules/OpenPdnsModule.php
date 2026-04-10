<?php
// =============================================================================
//  CTI — Open Passive DNS (CIRCL) Module
//  API Docs: https://www.circl.lu/services/passive-dns/
//  Free, no key. Supports: domain, ip
//  Endpoint: GET https://www.circl.lu/pdns/query/{value}
//  Returns NDJSON (newline-delimited JSON)
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OpenPdnsModule extends BaseApiModule
{
    private const API_ID   = 'open-pdns';
    private const API_NAME = 'Open Passive DNS (CIRCL)';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://www.circl.lu/pdns/query/' . urlencode($queryValue);
        $resp = HttpClient::get($url, ['Accept' => 'application/json'], 25);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ? $resp['error'] : 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403)
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        // Parse NDJSON response (one JSON object per line)
        $records = [];
        if ($resp['json'] && is_array($resp['json'])) {
            // Already parsed as a single JSON array
            $records = $resp['json'];
        } elseif ($resp['body']) {
            $lines = explode("\n", trim($resp['body']));
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '') continue;
                $decoded = json_decode($line, true);
                if ($decoded !== null) {
                    $records[] = $decoded;
                }
            }
        }

        if (count($records) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $totalRecords = count($records);

        // Extract unique rdata, rrnames, and rrtype
        $rnames  = [];
        $rdata   = [];
        $rrTypes = [];
        $firstSeen = null;
        $lastSeen  = null;

        foreach ($records as $rec) {
            $rn = isset($rec['rrname']) ? $rec['rrname'] : '';
            $rd = isset($rec['rdata']) ? $rec['rdata'] : '';
            $rt = isset($rec['rrtype']) ? $rec['rrtype'] : '';

            if ($rn) $rnames[$rn] = true;
            if ($rd) $rdata[$rd] = true;
            if ($rt) $rrTypes[$rt] = true;

            $fs = isset($rec['time_first']) ? $rec['time_first'] : '';
            $ls = isset($rec['time_last']) ? $rec['time_last'] : '';

            if ($fs && ($firstSeen === null || $fs < $firstSeen)) $firstSeen = $fs;
            if ($ls && ($lastSeen === null || $ls > $lastSeen)) $lastSeen = $ls;
        }

        $uniqueRdata = array_keys($rdata);
        $rdataCount  = count($uniqueRdata);

        $score = min(20, (int)($rdataCount / 3));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(90, 65 + min(20, $rdataCount));

        $parts = ["{$queryType} {$queryValue}: {$totalRecords} passive DNS record(s) via CIRCL"];

        $typeKeys = array_keys($rrTypes);
        if (!empty($typeKeys)) {
            $parts[] = "Record types: " . implode(', ', $typeKeys);
        }

        if ($rdataCount > 0) {
            $sample = array_slice($uniqueRdata, 0, 10);
            $parts[] = "Data: " . implode(', ', $sample);
            if ($rdataCount > 10) {
                $remaining = $rdataCount - 10;
                $parts[] = "... and {$remaining} more";
            }
        }

        if ($firstSeen && $lastSeen) {
            $parts[] = "Observed: {$firstSeen} to {$lastSeen}";
        }

        $tags = [self::API_ID, $queryType, 'dns', 'passive_dns'];
        if ($rdataCount > 20) $tags[] = 'large_infrastructure';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['total_records' => $totalRecords, 'unique_rdata' => array_slice($uniqueRdata, 0, 50), 'record_types' => $typeKeys],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://www.circl.lu/pdns/query/google.com', ['Accept' => 'application/json'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
