<?php
// =============================================================================
//  CTI — Google Custom Search Module
//  API Docs: https://developers.google.com/custom-search/v1/reference/rest
//  Auth: API key as query param. cx from apiKey "key|cx" format or baseUrl.
//  Endpoint: https://www.googleapis.com/customsearch/v1
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GoogleSearchModule extends BaseApiModule
{
    private const API_ID   = 'google';
    private const API_NAME = 'Google Custom Search';
    private const SUPPORTED = ['ip', 'domain', 'email', 'url', 'hash', 'username', 'phone', 'keyword'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        // Parse apiKey: may be "key|cx" format
        $key = $apiKey;
        $cx  = $baseUrl;
        if (strpos($apiKey, '|') !== false) {
            $parts = explode('|', $apiKey, 2);
            $key = $parts[0];
            $cx  = $parts[1];
        }

        if (!$cx) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Missing Custom Search Engine ID (cx). Provide as "apiKey|cx" or set baseUrl to cx.');
        }

        $url = 'https://www.googleapis.com/customsearch/v1?key=' . urlencode($key) .
               '&cx=' . urlencode($cx) .
               '&q=' . urlencode($queryValue) .
               '&num=10';

        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $items = $data['items'] ?? [];
        $searchInfo = $data['searchInformation'] ?? [];
        $totalResults = $searchInfo['totalResults'] ?? '0';
        $totalResultsInt = intval($totalResults);
        $resultCount = count($items);

        if ($resultCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Score based on exposure and threat mentions
        $score = 0;
        if ($totalResultsInt > 10000) $score = 30;
        elseif ($totalResultsInt > 1000) $score = 20;
        elseif ($totalResultsInt > 100) $score = 10;
        else $score = 5;

        $threatKeywords = ['malware', 'phishing', 'scam', 'exploit', 'vulnerability', 'hack', 'breach', 'threat', 'abuse', 'malicious'];
        $threatMatches = 0;
        foreach ($items as $item) {
            $snippet = $item['snippet'] ?? '';
            $title   = $item['title'] ?? '';
            $combined = strtolower($snippet . ' ' . $title);
            foreach ($threatKeywords as $kw) {
                if (strpos($combined, $kw) !== false) {
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
        foreach (array_slice($items, 0, 5) as $item) {
            $title = $item['title'] ?? 'Untitled';
            $link  = $item['link'] ?? '';
            $topResults[] = "{$title} ({$link})";
        }

        $formattedTime = $searchInfo['formattedSearchTime'] ?? 'N/A';
        $summary = "Google found ~{$totalResults} result(s) for \"{$queryValue}\" in {$formattedTime}s. " .
                   "Threat keyword matches: {$threatMatches}/{$resultCount}. " .
                   "Top: " . implode('; ', array_slice($topResults, 0, 3));

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
        $key = $apiKey;
        $cx  = $baseUrl;
        if (strpos($apiKey, '|') !== false) {
            $parts = explode('|', $apiKey, 2);
            $key = $parts[0];
            $cx  = $parts[1];
        }

        if (!$cx) return ['status' => 'down', 'latency_ms' => 0, 'error' => 'Missing cx (Custom Search Engine ID)'];

        $url = 'https://www.googleapis.com/customsearch/v1?key=' . urlencode($key) .
               '&cx=' . urlencode($cx) . '&q=test&num=1';
        $resp = HttpClient::get($url, [], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key or cx'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
