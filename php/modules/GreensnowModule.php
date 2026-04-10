<?php
// =============================================================================
//  CTI — Greensnow Blocklist Module
//  API: https://blocklist.greensnow.co/greensnow.txt (plaintext IP list)
//  Free, no key. Supports: ip
//  Checks if an IP appears in the Greensnow blocklist.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GreensnowModule extends BaseApiModule
{
    private const API_ID   = 'greensnow';
    private const API_NAME = 'Greensnow';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'https://blocklist.greensnow.co/greensnow.txt';
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $body = $resp['body'];
        $ips  = array_filter(array_map('trim', explode("\n", $body)), fn($l) => $l !== '' && $l[0] !== '#');
        $totalIps = count($ips);
        $isListed = in_array($queryValue, $ips, true);

        if ($isListed) {
            $score      = 70;
            $severity   = 'high';
            $confidence = 95;
            $summary    = "IP {$queryValue} IS listed in the Greensnow blocklist ({$totalIps} total entries).";
            $tags       = [self::API_ID, 'ip', 'blocklisted', 'malicious', 'attacker'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 90;
            $summary    = "IP {$queryValue} is NOT in the Greensnow blocklist. Checked against {$totalIps} entries.";
            $tags       = [self::API_ID, 'ip', 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['is_listed' => $isListed, 'total_entries' => $totalIps],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://blocklist.greensnow.co/greensnow.txt', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
