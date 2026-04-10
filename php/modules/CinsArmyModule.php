<?php
// =============================================================================
//  CTI — CINS Army List Module
//  API: http://cinsscore.com/list/ci-badguys.txt (plaintext IP list)
//  Free, no key. Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CinsArmyModule extends BaseApiModule
{
    private const API_ID   = 'cins-army';
    private const API_NAME = 'CINS Army List';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'http://cinsscore.com/list/ci-badguys.txt';
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $ips = array_filter(array_map('trim', explode("\n", $resp['body'])), fn($l) => $l !== '' && $l[0] !== '#');
        $total = count($ips);
        $listed = in_array($queryValue, $ips, true);

        if ($listed) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 75, severity: 'high', confidence: 95,
                responseMs: $resp['elapsed_ms'],
                summary: "IP {$queryValue} IS listed in the CINS Army threat list ({$total} total entries). This IP has been observed performing malicious activity.",
                tags: [self::API_ID, 'ip', 'blocklisted', 'malicious', 'attacker'],
                rawData: ['listed' => true, 'total_entries' => $total], success: true
            );
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 90,
            responseMs: $resp['elapsed_ms'],
            summary: "IP {$queryValue} is NOT in the CINS Army threat list. Checked {$total} entries.",
            tags: [self::API_ID, 'ip', 'clean'],
            rawData: ['listed' => false, 'total_entries' => $total], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('http://cinsscore.com/list/ci-badguys.txt', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
