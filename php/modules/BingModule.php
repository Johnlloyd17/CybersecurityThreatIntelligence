<?php
// =============================================================================
//  CTI — Bing Web Search Module
//  API Docs: https://docs.microsoft.com/en-us/bing/search-apis/bing-web-search/
//  Auth: Ocp-Apim-Subscription-Key header
//  Endpoint: https://api.bing.microsoft.com/v7.0/search
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BingModule extends BaseApiModule
{
    private const API_ID   = 'bing';
    private const API_NAME = 'Bing Web Search';
    private const SUPPORTED = ['ip', 'domain', 'email', 'url', 'hash', 'username', 'phone', 'keyword'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://api.bing.microsoft.com', '/');
        $url = "{$base}/v7.0/search?q=" . urlencode($queryValue) . "&count=20&responseFilter=Webpages";
        $headers = ['Ocp-Apim-Subscription-Key' => $apiKey];

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $webPages = $data['webPages']['value'] ?? [];
        $totalEstimated = $data['webPages']['totalEstimatedMatches'] ?? count($webPages);
        $resultCount = count($webPages);

        if ($resultCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Score: more results = more internet exposure
        $score = 0;
        if ($totalEstimated > 1000) $score = 30;
        elseif ($totalEstimated > 100) $score = 20;
        elseif ($totalEstimated > 10) $score = 10;
        else $score = 5;

        // Check for threat-related keywords in snippets
        $threatKeywords = ['malware', 'phishing', 'scam', 'exploit', 'vulnerability', 'hack', 'breach', 'threat', 'abuse', 'malicious'];
        $threatMatches = 0;
        $snippets = [];
        foreach ($webPages as $page) {
            $snippet = $page['snippet'] ?? '';
            $snippets[] = $snippet;
            foreach ($threatKeywords as $kw) {
                if (stripos($snippet, $kw) !== false) {
                    $threatMatches++;
                    break;
                }
            }
        }

        if ($threatMatches > 5) $score += 40;
        elseif ($threatMatches > 2) $score += 25;
        elseif ($threatMatches > 0) $score += 10;

        $score = min(100, $score);

        $topResults = [];
        foreach (array_slice($webPages, 0, 5) as $page) {
            $name = $page['name'] ?? 'Untitled';
            $pageUrl = $page['url'] ?? '';
            $topResults[] = "{$name} ({$pageUrl})";
        }

        $summary = "Bing found ~{$totalEstimated} result(s) for \"{$queryValue}\". " .
                   "Threat keyword matches in snippets: {$threatMatches}/{$resultCount}. " .
                   "Top results: " . implode('; ', array_slice($topResults, 0, 3));

        $tags = [self::API_ID, $queryType, 'search'];
        if ($threatMatches > 2) $tags[] = 'threat_mentions';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(90, 50 + $resultCount * 2),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://api.bing.microsoft.com', '/');
        $url = "{$base}/v7.0/search?q=test&count=1";
        $headers = ['Ocp-Apim-Subscription-Key' => $apiKey];
        $resp = HttpClient::get($url, $headers, 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
