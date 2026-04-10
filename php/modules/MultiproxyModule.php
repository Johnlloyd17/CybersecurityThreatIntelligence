<?php
// =============================================================================
//  CTI — Multiproxy.org Open Proxies Module
//  API: https://multiproxy.org/txt_all/proxy.txt (plaintext IP:port list)
//  Free, no key. Supports: ip
//  Checks if an IP appears as an open proxy in the multiproxy.org list.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class MultiproxyModule extends BaseApiModule
{
    private const API_ID   = 'multiproxy';
    private const API_NAME = 'multiproxy.org Open Proxies';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'https://multiproxy.org/txt_all/proxy.txt';
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $errMsg = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $resp['elapsed_ms']);
        }
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $body  = $resp['body'];
        $lines = array_filter(array_map('trim', explode("\n", $body)), fn($l) => $l !== '' && $l[0] !== '#');
        $totalEntries = count($lines);

        // Lines are in IP:port format; extract just the IP portion for matching
        $proxyIps = [];
        $matchedPort = null;
        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);
            $ip = trim($parts[0]);
            if ($ip === $queryValue) {
                $matchedPort = isset($parts[1]) ? trim($parts[1]) : 'unknown';
                $proxyIps[] = $ip;
            }
        }

        $isListed = !empty($proxyIps);

        if ($isListed) {
            $score      = 60;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 85;
            $portInfo = $matchedPort ? " (port {$matchedPort})" : '';
            $summary    = "IP {$queryValue} IS listed as an open proxy{$portInfo} in multiproxy.org ({$totalEntries} total entries).";
            $tags       = [self::API_ID, 'ip', 'proxy', 'open-proxy', 'suspicious'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 80;
            $summary    = "IP {$queryValue} is NOT in the multiproxy.org open proxy list. Checked against {$totalEntries} entries.";
            $tags       = [self::API_ID, 'ip', 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['is_listed' => $isListed, 'total_entries' => $totalEntries, 'matched_port' => $matchedPort],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://multiproxy.org/txt_all/proxy.txt', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
