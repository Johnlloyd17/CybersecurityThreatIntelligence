<?php
// =============================================================================
//  CTI — Wikipedia Edits Module
//  API Docs: https://en.wikipedia.org/w/api.php
//  Free, no key. Supports: username
//  Checks if a username has Wikipedia edit history.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WikipediaEditsModule extends BaseApiModule
{
    private const API_ID   = 'wikipedia-edits';
    private const API_NAME = 'Wikipedia Edits';
    private const SUPPORTED = ['username'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://en.wikipedia.org/w/api.php?' . http_build_query([
            'action'  => 'query',
            'list'    => 'usercontribs',
            'ucuser'  => $queryValue,
            'uclimit' => 50,
            'ucprop'  => 'title|timestamp|comment|sizediff',
            'format'  => 'json',
        ]);

        $resp = HttpClient::get($url, [], 15);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        // Check for error (e.g., invalid username)
        if (isset($data['error'])) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $contribs = $data['query']['usercontribs'] ?? [];
        $count = count($contribs);

        if ($count === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Extract articles edited
        $articles = [];
        $latestEdit = '';
        foreach ($contribs as $c) {
            $articles[$c['title'] ?? ''] = true;
            if (!$latestEdit && isset($c['timestamp'])) $latestEdit = $c['timestamp'];
        }

        $parts = ["Username '{$queryValue}': {$count} recent Wikipedia edit(s) across " . count($articles) . " article(s)"];
        if ($latestEdit) $parts[] = "Latest: {$latestEdit}";

        $sampleArticles = array_slice(array_keys($articles), 0, 5);
        if (!empty($sampleArticles)) $parts[] = "Articles: " . implode(', ', $sampleArticles);

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 5, severity: 'info', confidence: 90,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'username', 'osint', 'clean'],
            rawData: ['edit_count' => $count, 'articles' => array_keys($articles), 'latest' => $latestEdit],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://en.wikipedia.org/w/api.php?action=query&meta=siteinfo&format=json', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
