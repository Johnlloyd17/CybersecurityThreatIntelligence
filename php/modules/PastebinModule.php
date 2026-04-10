<?php
// =============================================================================
//  CTI — Pastebin Scraping Module
//  API Docs: https://pastebin.com/doc_scraping_api
//  Auth: Free public endpoint (PRO account IP must be whitelisted)
//  Endpoint: GET https://scrape.pastebin.com/api_scraping.php
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PastebinModule extends BaseApiModule
{
    private const API_ID   = 'pastebin';
    private const API_NAME = 'Pastebin Scraping';
    private const SUPPORTED = ['ip', 'domain', 'email', 'url', 'hash', 'username', 'keyword'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://scrape.pastebin.com', '/');

        // Step 1: Get recent paste metadata
        $listUrl = "{$base}/api_scraping.php?limit=100";
        $resp = HttpClient::get($listUrl, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 403)
            return OsintResult::error(self::API_ID, self::API_NAME, 'IP not whitelisted for Pastebin scraping API', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $pastes = $resp['json'];
        if (!is_array($pastes)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid response format', $resp['elapsed_ms']);
        }

        $totalElapsed = $resp['elapsed_ms'];
        $matchingPastes = [];
        $searchLower = strtolower($queryValue);

        // Step 2: Check each paste title/user for matches, then fetch content for top candidates
        foreach ($pastes as $paste) {
            $title = $paste['title'] ?? '';
            $user  = $paste['user'] ?? '';
            $key   = $paste['key'] ?? '';

            // Quick match on metadata
            if (stripos($title, $queryValue) !== false || stripos($user, $queryValue) !== false) {
                $matchingPastes[] = [
                    'key'   => $key,
                    'title' => $title,
                    'user'  => $user,
                    'date'  => $paste['date'] ?? '',
                    'size'  => $paste['size'] ?? 0,
                    'match' => 'metadata',
                ];
                continue;
            }

            // Fetch paste content for deeper search (limit to first 20 pastes to avoid rate limits)
            if (count($matchingPastes) < 10 && count($matchingPastes) + count($pastes) <= 120) {
                $contentUrl = "{$base}/api_scrape_item.php?i=" . urlencode($key);
                $contentResp = HttpClient::get($contentUrl, [], 10);
                $totalElapsed += $contentResp['elapsed_ms'];

                if ($contentResp['status'] === 200 && $contentResp['body']) {
                    if (stripos($contentResp['body'], $queryValue) !== false) {
                        $matchingPastes[] = [
                            'key'   => $key,
                            'title' => $title,
                            'user'  => $user,
                            'date'  => $paste['date'] ?? '',
                            'size'  => $paste['size'] ?? 0,
                            'match' => 'content',
                        ];
                    }
                }

                // Only check content of first 20 pastes
                static $contentChecks = 0;
                $contentChecks++;
                if ($contentChecks >= 20) break;
            }
        }

        $matchCount = count($matchingPastes);

        if ($matchCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $totalElapsed);
        }

        // Score based on number of paste matches
        $score = min(80, $matchCount * 12);

        $pasteSummaries = [];
        foreach (array_slice($matchingPastes, 0, 5) as $p) {
            $title = $p['title'] ?: '(untitled)';
            $pasteSummaries[] = "{$title} [key:{$p['key']}, match:{$p['match']}]";
        }

        $summary = "Pastebin: Found {$matchCount} paste(s) matching \"{$queryValue}\" in recent scrapes. " .
                   "Matches: " . implode('; ', $pasteSummaries);

        $tags = [self::API_ID, $queryType, 'paste', 'leak_detection'];
        if ($matchCount > 3) $tags[] = 'data_leak';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(80, 40 + $matchCount * 5),
            responseMs: $totalElapsed, summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: ['matches' => $matchingPastes, 'total_scanned' => count($pastes)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://scrape.pastebin.com', '/');
        $url = "{$base}/api_scraping.php?limit=1";
        $resp = HttpClient::get($url, [], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'IP not whitelisted'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
