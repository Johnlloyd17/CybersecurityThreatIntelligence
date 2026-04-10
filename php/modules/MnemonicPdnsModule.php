<?php
// =============================================================================
//  CTI — Mnemonic PassiveDNS Module
//  API Docs: https://docs.mnemonic.no/display/public/API
//  Free, no key. Supports: domain, ip
//  Endpoint: GET https://api.mnemonic.no/pdns/v3/{value}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class MnemonicPdnsModule extends BaseApiModule
{
    private const API_ID   = 'mnemonic-pdns';
    private const API_NAME = 'Mnemonic PassiveDNS';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.mnemonic.no/pdns/v3/' . urlencode($queryValue);
        $resp = HttpClient::get($url, ['Accept' => 'application/json'], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ? $resp['error'] : 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!is_array($data)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Mnemonic returns { data: [...], count: N, ... }
        $records = isset($data['data']) ? $data['data'] : $data;
        $responseCount = isset($data['count']) ? (int)$data['count'] : 0;

        if (!is_array($records) || count($records) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $totalRecords = count($records);
        if ($responseCount > 0) {
            $totalRecords = max($totalRecords, $responseCount);
        }

        // Extract unique values and record types
        $queries = [];
        $answers = [];
        $rrTypes = [];
        $firstSeen = null;
        $lastSeen  = null;

        foreach ($records as $rec) {
            $q = isset($rec['query']) ? $rec['query'] : '';
            $a = isset($rec['answer']) ? $rec['answer'] : '';
            $t = isset($rec['rrtype']) ? $rec['rrtype'] : '';

            if ($q) $queries[$q] = true;
            if ($a) $answers[$a] = true;
            if ($t) $rrTypes[$t] = true;

            $fs = isset($rec['firstSeenTimestamp']) ? (int)$rec['firstSeenTimestamp'] : 0;
            $ls = isset($rec['lastSeenTimestamp']) ? (int)$rec['lastSeenTimestamp'] : 0;

            if ($fs > 0 && ($firstSeen === null || $fs < $firstSeen)) $firstSeen = $fs;
            if ($ls > 0 && ($lastSeen === null || $ls > $lastSeen)) $lastSeen = $ls;
        }

        $uniqueAnswers = array_keys($answers);
        $answerCount = count($uniqueAnswers);

        $score = min(25, (int)($answerCount / 3));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 70 + min(20, $answerCount));

        $parts = ["{$queryType} {$queryValue}: {$totalRecords} passive DNS record(s) via Mnemonic"];

        $typeKeys = array_keys($rrTypes);
        if (!empty($typeKeys)) {
            $parts[] = "Record types: " . implode(', ', $typeKeys);
        }

        if ($answerCount > 0) {
            $sample = array_slice($uniqueAnswers, 0, 10);
            $parts[] = "Resolved to: " . implode(', ', $sample);
            if ($answerCount > 10) {
                $remaining = $answerCount - 10;
                $parts[] = "... and {$remaining} more";
            }
        }

        if ($firstSeen && $lastSeen) {
            $firstDate = date('Y-m-d', (int)($firstSeen / 1000));
            $lastDate  = date('Y-m-d', (int)($lastSeen / 1000));
            $parts[] = "Seen: {$firstDate} to {$lastDate}";
        }

        $tags = [self::API_ID, $queryType, 'dns', 'passive_dns'];
        if ($answerCount > 20) $tags[] = 'large_infrastructure';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['total_records' => $totalRecords, 'unique_answers' => array_slice($uniqueAnswers, 0, 50), 'record_types' => $typeKeys],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.mnemonic.no/pdns/v3/google.com', ['Accept' => 'application/json'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
