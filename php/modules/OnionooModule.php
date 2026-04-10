<?php
// =============================================================================
//  CTI — Onionoo Module
//  Queries Tor Project's Onionoo API for relay/bridge details.
//  API Docs: https://metrics.torproject.org/onionoo.html
//  Free, no key required. Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OnionooModule extends BaseApiModule
{
    private const API_ID   = 'onionoo';
    private const API_NAME = 'Onionoo (Tor Metrics)';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://onionoo.torproject.org', '/');
        $url = "{$baseUrl}/details?search=" . urlencode($queryValue);

        $resp = HttpClient::get($url, []);

        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json    = $resp['json'];
        $relays  = $json['relays'] ?? [];
        $bridges = $json['bridges'] ?? [];

        if (empty($relays) && empty($bridges)) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 90,
                responseMs: $resp['elapsed_ms'],
                summary: "IP {$queryValue}: Not a known Tor relay or bridge.",
                tags: [self::API_ID, 'ip', 'tor', 'clean'],
                rawData: ['ip' => $queryValue, 'is_tor' => false],
                success: true
            );
        }

        $totalRelays  = count($relays);
        $totalBridges = count($bridges);
        $flags     = [];
        $nicknames = [];
        $bandwidth = 0;
        $isExit    = false;
        $isGuard   = false;

        foreach ($relays as $r) {
            $nick = $r['nickname'] ?? '';
            if ($nick) $nicknames[] = $nick;
            foreach ($r['flags'] ?? [] as $f) {
                $flags[$f] = true;
                if ($f === 'Exit') $isExit = true;
                if ($f === 'Guard') $isGuard = true;
            }
            $bw = $r['observed_bandwidth'] ?? $r['advertised_bandwidth'] ?? 0;
            $bandwidth += $bw;
        }

        $score = 60;
        if ($isExit) $score = 80;
        if ($isGuard && $isExit) $score = 85;

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 95;

        $parts = ["IP {$queryValue}: Tor network node."];
        if ($totalRelays > 0) $parts[] = "{$totalRelays} relay(s).";
        if ($totalBridges > 0) $parts[] = "{$totalBridges} bridge(s).";
        if (!empty($flags)) $parts[] = 'Flags: ' . implode(', ', array_keys($flags)) . '.';
        if (!empty($nicknames)) $parts[] = 'Nickname(s): ' . implode(', ', array_slice($nicknames, 0, 3)) . '.';
        if ($bandwidth > 0) $parts[] = 'Bandwidth: ' . number_format($bandwidth / 1024) . ' KB/s.';

        $resultTags = [self::API_ID, 'ip', 'tor'];
        if ($isExit) $resultTags[] = 'tor_exit';
        if ($isGuard) $resultTags[] = 'tor_guard';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: implode(' ', $parts),
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'ip'            => $queryValue,
                'is_tor'        => true,
                'relay_count'   => $totalRelays,
                'bridge_count'  => $totalBridges,
                'flags'         => array_keys($flags),
                'nicknames'     => $nicknames,
                'bandwidth'     => $bandwidth,
                'is_exit'       => $isExit,
                'is_guard'      => $isGuard,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://onionoo.torproject.org', '/');
        $resp = HttpClient::get("{$baseUrl}/summary?limit=1", []);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
