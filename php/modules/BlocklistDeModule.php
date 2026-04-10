<?php
// =============================================================================
//  CTI — blocklist.de Module
//  API Docs: https://www.blocklist.de/en/api.html
//  Free, no key. Supports: ip
//  Endpoint: http://api.blocklist.de/api.php?ip={ip}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BlocklistDeModule extends BaseApiModule
{
    private const API_ID   = 'blocklist-de';
    private const API_NAME = 'blocklist.de';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = ($baseUrl ?: 'https://api.blocklist.de/api.php') . '?ip=' . urlencode($queryValue);
        $resp = HttpClient::get($url, [], 15);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $body = trim($resp['body']);
        // Response format: "attacks: N" or "IP not found"
        // Can also be key-value pairs separated by <br>

        $attacks = 0;
        $reports = 0;
        $listed  = false;

        if (preg_match('/attacks:\s*(\d+)/i', $body, $m)) {
            $attacks = (int)$m[1];
            $listed  = $attacks > 0;
        }
        if (preg_match('/reports:\s*(\d+)/i', $body, $m)) {
            $reports = (int)$m[1];
        }

        // Some responses return just a number or "not found"
        if (stripos($body, 'not found') !== false || $body === '0') {
            $listed = false;
        }

        if ($listed) {
            $score = min(100, 50 + min(50, $attacks * 2));
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = min(99, 70 + min(25, $attacks));
            $summary = "IP {$queryValue} IS listed on blocklist.de. Attacks: {$attacks}, Reports: {$reports}.";
            $tags = [self::API_ID, 'ip', 'blocklisted', 'malicious', 'attacker'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 90;
            $summary    = "IP {$queryValue} is NOT listed on blocklist.de.";
            $tags       = [self::API_ID, 'ip', 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['attacks' => $attacks, 'reports' => $reports, 'listed' => $listed, 'raw' => $body],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.blocklist.de/api.php?ip=8.8.8.8', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
