<?php
// =============================================================================
//  CTI — TOR Exit Nodes Module
//  API: https://check.torproject.org/exit-addresses (plaintext list)
//  Free, no key. Supports: ip
//  Checks if an IP is a known TOR exit node.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class TorExitNodesModule extends BaseApiModule
{
    private const API_ID   = 'tor-exit-nodes';
    private const API_NAME = 'TOR Exit Nodes';
    private const SUPPORTED = ['ip'];

    private static ?array $cachedNodes = null;
    private static int $cacheTime = 0;

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'https://check.torproject.org/exit-addresses';
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $body = $resp['body'];
        // Parse: lines like "ExitAddress 1.2.3.4 2024-01-01 00:00:00"
        $exitIps = [];
        foreach (explode("\n", $body) as $line) {
            if (preg_match('/^ExitAddress\s+(\S+)/', $line, $m)) {
                $exitIps[$m[1]] = true;
            }
        }

        $totalNodes = count($exitIps);
        $isTorExit  = isset($exitIps[$queryValue]);

        if ($isTorExit) {
            $score      = 75;
            $severity   = 'high';
            $confidence = 99;
            $summary    = "IP {$queryValue} IS a known TOR exit node. Total TOR exit nodes in list: {$totalNodes}.";
            $tags       = [self::API_ID, 'ip', 'tor', 'exit_node', 'anonymization', 'suspicious'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 99;
            $summary    = "IP {$queryValue} is NOT a TOR exit node. Checked against {$totalNodes} known exit nodes.";
            $tags       = [self::API_ID, 'ip', 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['is_tor_exit' => $isTorExit, 'total_nodes' => $totalNodes],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://check.torproject.org/exit-addresses', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
