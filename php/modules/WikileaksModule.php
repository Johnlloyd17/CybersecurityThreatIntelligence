<?php
// =============================================================================
//  CTI — WikiLeaks Module
//  Searches WikiLeaks archive for mentions of the query value.
//  Uses WikiLeaks search API with fallback to DuckDuckGo site search.
//  Supports: domain, email, ip, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WikileaksModule extends BaseApiModule
{
    private const API_ID   = 'wikileaks';
    private const API_NAME = 'WikiLeaks Search';
    private const SUPPORTED = ['domain', 'email', 'ip', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);

        try {
            // Try WikiLeaks search first
            $result = $this->searchWikileaks($value);
            $ms = (int)((microtime(true) - $start) * 1000);

            if ($result === null) {
                // Fallback to DuckDuckGo site search
                $result = $this->searchDuckDuckGo($value);
                $ms = (int)((microtime(true) - $start) * 1000);
            }

            if ($result === null) {
                return OsintResult::error(
                    self::API_ID, self::API_NAME,
                    'Could not query WikiLeaks search or fallback search',
                    $ms
                );
            }

            $found = $result['found'];
            $resultCount = $result['count'];
            $source = $result['source'];
            $details = $result['details'];

            if (!$found || $resultCount === 0) {
                return new OsintResult(
                    api: self::API_ID, apiName: self::API_NAME,
                    score: 0, severity: 'info', confidence: 50,
                    responseMs: $ms,
                    summary: "No WikiLeaks references found for '{$value}' (via {$source}).",
                    tags: [self::API_ID, $queryType, 'clean'],
                    rawData: ['query' => $value, 'source' => $source, 'results' => []],
                    success: true
                );
            }

            // Having references in WikiLeaks is notable
            $score = min(40 + ($resultCount * 5), 75);
            $severity = OsintResult::scoreToSeverity($score);

            $summaryParts = [];
            $summaryParts[] = "{$resultCount} WikiLeaks reference(s) found for '{$value}'";
            $summaryParts[] = "Search source: {$source}";

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: 55,
                responseMs: $ms,
                summary: implode('. ', $summaryParts) . '.',
                tags: array_values(array_unique([self::API_ID, $queryType, 'wikileaks', 'leak', 'mentioned'])),
                rawData: [
                    'query' => $value,
                    'source' => $source,
                    'result_count' => $resultCount,
                    'results' => array_slice($details, 0, 20),
                ],
                success: true
            );
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    private function searchWikileaks(string $query): ?array
    {
        $encodedQuery = urlencode($query);
        $url = "https://search.wikileaks.org/?q={$encodedQuery}&exact_phrase=on";

        $resp = HttpClient::get($url, [], 15, 0);

        if ($resp['error'] || $resp['status'] >= 400) {
            return null;
        }

        $body = $resp['body'];
        $results = [];
        $count = 0;

        // Try to extract result count from page
        if (preg_match('/(\d+)\s+result/i', $body, $countMatch)) {
            $count = (int)$countMatch[1];
        }

        // Extract result entries (titles and snippets)
        if (preg_match_all('/<div[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)<\/div>/si', $body, $resultMatches)) {
            foreach ($resultMatches[1] as $resultHtml) {
                $title = '';
                $snippet = '';
                if (preg_match('/<a[^>]*>([^<]+)<\/a>/i', $resultHtml, $titleMatch)) {
                    $title = trim(strip_tags($titleMatch[1]));
                }
                if (preg_match('/<p[^>]*>([^<]+)<\/p>/i', $resultHtml, $snippetMatch)) {
                    $snippet = trim(strip_tags($snippetMatch[1]));
                }
                if ($title || $snippet) {
                    $results[] = ['title' => $title, 'snippet' => mb_substr($snippet, 0, 200)];
                }
            }
        }

        // Also check for simple text matches if structured parsing fails
        if ($count === 0 && stripos($body, $query) !== false) {
            // The query appears on the page, likely there are results
            $count = max(1, count($results));
        }

        if ($count === 0 && empty($results)) {
            // Check if page loaded but no results
            if (stripos($body, 'no results') !== false || stripos($body, '0 result') !== false) {
                return ['found' => false, 'count' => 0, 'source' => 'wikileaks_search', 'details' => []];
            }
            // Page might have loaded but we couldn't parse it
            if (strlen($body) < 100) {
                return null; // Fallback to DuckDuckGo
            }
        }

        return [
            'found'   => $count > 0 || !empty($results),
            'count'   => max($count, count($results)),
            'source'  => 'wikileaks_search',
            'details' => $results,
        ];
    }

    private function searchDuckDuckGo(string $query): ?array
    {
        $encodedQuery = urlencode("site:wikileaks.org {$query}");
        $url = "https://html.duckduckgo.com/html/?q={$encodedQuery}";

        $resp = HttpClient::get($url, [
            'User-Agent' => 'Mozilla/5.0 (compatible; CTI-Platform/1.0)',
        ], 15, 0);

        if ($resp['error'] || $resp['status'] >= 400) {
            return null;
        }

        $body = $resp['body'];
        $results = [];

        // Parse DuckDuckGo HTML results
        if (preg_match_all('/<a[^>]+class="result__a"[^>]*>([^<]+)<\/a>/i', $body, $titleMatches)) {
            foreach ($titleMatches[1] as $title) {
                $results[] = ['title' => trim(strip_tags($title)), 'snippet' => ''];
            }
        }

        // Also try simpler link extraction for wikileaks.org results
        if (empty($results) && preg_match_all('/href="[^"]*wikileaks\.org[^"]*"[^>]*>([^<]*)</i', $body, $linkMatches)) {
            foreach ($linkMatches[1] as $linkText) {
                $text = trim(strip_tags($linkText));
                if ($text) {
                    $results[] = ['title' => $text, 'snippet' => ''];
                }
            }
        }

        // Check for "no results" indicator
        if (empty($results)) {
            if (stripos($body, 'No results') !== false || stripos($body, 'no more results') !== false) {
                return ['found' => false, 'count' => 0, 'source' => 'duckduckgo_site_search', 'details' => []];
            }
        }

        return [
            'found'   => !empty($results),
            'count'   => count($results),
            'source'  => 'duckduckgo_site_search',
            'details' => $results,
        ];
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $resp = HttpClient::get('https://search.wikileaks.org/', [], 10, 0);
        $latency = (int)((microtime(true) - $start) * 1000);

        if ($resp['error']) {
            return ['status' => 'down', 'latency_ms' => $latency, 'error' => $resp['error']];
        }
        if ($resp['status'] >= 400) {
            $status = $resp['status'];
            return ['status' => 'degraded', 'latency_ms' => $latency, 'error' => "HTTP {$status}"];
        }

        return ['status' => 'up', 'latency_ms' => $latency, 'error' => null];
    }
}
