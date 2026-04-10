<?php
// =============================================================================
//  CTI — MetaDefender (OPSWAT) Module
//  API Docs: https://docs.opswat.com/mdcloud/
//  Auth: apikey header. Supports: hash, ip, domain, url
//  Endpoint: https://api.metadefender.com/v4/{type}/{value}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class MetaDefenderModule extends BaseApiModule
{
    private const API_ID   = 'metadefender';
    private const API_NAME = 'MetaDefender';
    private const SUPPORTED = ['hash', 'ip', 'domain', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://api.metadefender.com/v4', '/');
        $headers = ['apikey' => $apiKey];

        $url = match ($queryType) {
            'hash'   => "{$base}/hash/" . urlencode($queryValue),
            'ip'     => "{$base}/ip/" . urlencode($queryValue),
            'domain' => "{$base}/domain/" . urlencode($queryValue),
            'url'    => "{$base}/url/" . urlencode($queryValue),
            default  => "{$base}/ip/" . urlencode($queryValue),
        };

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        if ($queryType === 'hash') {
            $scanResults = $data['scan_results'] ?? $data['scan_result'] ?? [];
            $totalEngines = $scanResults['total_avs'] ?? 0;
            $detections   = $scanResults['total_detected_avs'] ?? 0;
            $scanAll      = $scanResults['scan_all_result_a'] ?? 'Unknown';

            $score = $totalEngines > 0 ? min(100, (int)($detections / $totalEngines * 100)) : 0;
            $parts = ["Hash {$queryValue}: {$detections}/{$totalEngines} engines detected. Verdict: {$scanAll}"];
            $tags = [self::API_ID, 'hash'];
            if ($detections > 5) $tags[] = 'malicious';
            elseif ($detections > 0) $tags[] = 'suspicious';
            else $tags[] = 'clean';
        } else {
            // IP/domain/URL lookups
            $geoInfo   = $data['geo_info'] ?? $data['lookup_results'] ?? [];
            $detected  = $data['detected_by'] ?? 0;
            $sources   = $data['lookup_results']['sources'] ?? [];

            $score = min(100, $detected * 15);
            $label = match ($queryType) {
                'ip' => "IP {$queryValue}", 'domain' => "Domain {$queryValue}", 'url' => "URL {$queryValue}", default => $queryValue,
            };
            $parts = ["{$label}: Detected by {$detected} source(s) on MetaDefender"];

            if (isset($geoInfo['country'])) $parts[] = "Country: " . ($geoInfo['country']['name'] ?? $geoInfo['country']);

            $tags = [self::API_ID, $queryType];
            if ($detected > 3) $tags[] = 'malicious';
            elseif ($detected > 0) $tags[] = 'suspicious';
            else $tags[] = 'clean';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(99, 60 + min(35, ($detections ?? $detected ?? 0) * 3)),
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.metadefender.com/v4/status', ['apikey' => $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
