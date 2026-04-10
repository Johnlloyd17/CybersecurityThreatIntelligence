<?php
// =============================================================================
//  CTI — BinaryEdge Torrents Module
//  Queries BinaryEdge API for torrent/DHT activity on IPs.
//  API Docs: https://docs.binaryedge.io/api-v2/
//  Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BinaryEdgeTorrentsModule extends BaseApiModule
{
    private const API_ID   = 'binaryedge-torrents';
    private const API_NAME = 'BinaryEdge Torrents';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.binaryedge.io/v2', '/');
        $headers = ['X-Key' => $apiKey];

        $url  = "{$baseUrl}/query/torrent/target/" . urlencode($queryValue);
        $resp = HttpClient::get($url, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json    = $resp['json'];
        $events  = $json['events'] ?? [];
        $total   = $json['total'] ?? count($events);

        if ($total === 0 || empty($events)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $torrents = [];
        foreach ($events as $ev) {
            $name = $ev['torrent']['name'] ?? $ev['name'] ?? 'unknown';
            $hash = $ev['torrent']['source'] ?? $ev['info_hash'] ?? '';
            $torrents[$hash ?: $name] = $name;
        }

        $uniqueTorrents = count($torrents);
        $score      = min(65, 20 + $uniqueTorrents * 5);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(90, 60 + $uniqueTorrents * 5);

        $sample = array_slice(array_values($torrents), 0, 5);
        $summary = "BinaryEdge: IP {$queryValue} seen in {$total} torrent DHT event(s) ({$uniqueTorrents} unique).";
        if (!empty($sample)) $summary .= ' Sample: ' . implode(', ', $sample) . '.';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: [self::API_ID, 'ip', 'torrent', 'p2p'],
            rawData: [
                'ip'              => $queryValue,
                'total_events'    => $total,
                'unique_torrents' => $uniqueTorrents,
                'torrents'        => array_slice($torrents, 0, 50, true),
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.binaryedge.io/v2', '/');
        $resp = HttpClient::get("{$baseUrl}/user/subscription", ['X-Key' => $apiKey]);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
