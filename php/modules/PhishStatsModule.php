<?php
// =============================================================================
//  CTI — PhishStats Module
//  API Docs: https://phishstats.info/
//  Free, no key. Supports: url, domain, ip
//  Endpoint: https://phishstats.info:2096/api/phishing?_where=(url,like,~{query}~)
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PhishStatsModule extends BaseApiModule
{
    private const API_ID   = 'phishstats';
    private const API_NAME = 'PhishStats';
    private const SUPPORTED = ['url', 'domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = 'https://phishstats.info:2096/api/phishing';

        $where = match ($queryType) {
            'ip'     => "(ip,eq,{$queryValue})",
            'domain' => "(url,like,~{$queryValue}~)",
            'url'    => "(url,like,~{$queryValue}~)",
            default  => "(url,like,~{$queryValue}~)",
        };

        $url = "{$base}?_where={$where}&_sort=-date&_size=25";
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!is_array($data) || empty($data)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $count = count($data);
        $score = min(100, 50 + $count * 3);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 60 + min(30, $count * 2));

        // Extract unique IPs and dates
        $ips = [];
        $dates = [];
        $titles = [];
        foreach ($data as $entry) {
            if (isset($entry['ip'])) $ips[$entry['ip']] = true;
            if (isset($entry['date'])) $dates[] = $entry['date'];
            if (isset($entry['title']) && $entry['title']) $titles[] = $entry['title'];
        }

        $label = match ($queryType) {
            'ip'     => "IP {$queryValue}",
            'domain' => "Domain {$queryValue}",
            'url'    => "URL {$queryValue}",
            default  => $queryValue,
        };

        $parts = ["{$label}: Found in {$count} phishing record(s) on PhishStats"];
        if (!empty($dates)) {
            $parts[] = "Latest: " . $dates[0];
        }
        if (count($ips) > 1) {
            $parts[] = count($ips) . " unique IP(s)";
        }
        if (!empty($titles)) {
            $parts[] = "Title: " . substr($titles[0], 0, 80);
        }

        $tags = [self::API_ID, $queryType, 'phishing', 'malicious'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: array_slice($data, 0, 10), success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://phishstats.info:2096/api/phishing?_size=1', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
