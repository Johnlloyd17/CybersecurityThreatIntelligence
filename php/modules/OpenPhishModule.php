<?php
// =============================================================================
//  CTI — OpenPhish Module
//  API: https://openphish.com/feed.txt (plaintext URL list)
//  Free, no key. Supports: url, domain
//  Checks if a URL/domain appears in the OpenPhish phishing feed.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OpenPhishModule extends BaseApiModule
{
    private const API_ID   = 'openphish';
    private const API_NAME = 'OpenPhish';
    private const SUPPORTED = ['url', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'https://openphish.com/feed.txt';
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $lines = array_filter(array_map('trim', explode("\n", $resp['body'])), fn($l) => $l !== '');
        $total = count($lines);
        $searchVal = strtolower($queryValue);

        $matches = [];
        foreach ($lines as $line) {
            $lower = strtolower($line);
            if ($queryType === 'url') {
                if ($lower === $searchVal || strpos($lower, $searchVal) !== false) {
                    $matches[] = $line;
                }
            } else {
                // domain: check if domain appears in any URL
                $host = parse_url($line, PHP_URL_HOST);
                if ($host && (strtolower($host) === $searchVal || str_ends_with(strtolower($host), ".{$searchVal}"))) {
                    $matches[] = $line;
                }
            }
            if (count($matches) >= 20) break;
        }

        $matchCount = count($matches);

        if ($matchCount > 0) {
            $score      = min(100, 80 + $matchCount * 2);
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 95;
            $label = $queryType === 'url' ? "URL {$queryValue}" : "Domain {$queryValue}";
            $summary = "{$label}: Found {$matchCount} match(es) in OpenPhish feed ({$total} total entries).";
            $tags = [self::API_ID, $queryType, 'phishing', 'malicious'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 85;
            $label = $queryType === 'url' ? "URL {$queryValue}" : "Domain {$queryValue}";
            $summary = "{$label}: NOT found in OpenPhish feed. Checked {$total} entries.";
            $tags = [self::API_ID, $queryType, 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['matches' => array_slice($matches, 0, 10), 'total_feed' => $total],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://openphish.com/feed.txt', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
