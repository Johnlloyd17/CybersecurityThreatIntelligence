<?php
// =============================================================================
//  CTI — OnionSearchEngine Module
//  Free, no key required. Supports: domain
//  Endpoint: https://onionsearchengine.com/search.php?search={domain}&submit=Search&api=true
//  Returns dark web search results
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OnionSearchEngineModule extends BaseApiModule
{
    private const API_ID   = 'onionsearchengine';
    private const API_NAME = 'OnionSearchEngine';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl  = rtrim($baseUrl ?: 'https://onionsearchengine.com', '/');
        $endpoint = "{$baseUrl}/search.php?search=" . urlencode($queryValue) . "&submit=Search&api=true";

        $resp = HttpClient::get($endpoint, [], 25);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        // Response may be JSON or HTML depending on the API mode
        $data = $resp['json'];
        if ($data) {
            return $this->parseJson($data, $queryValue, $resp['elapsed_ms']);
        }

        // Fallback: parse HTML/text response
        return $this->parseHtml($resp['body'], $queryValue, $resp['elapsed_ms']);
    }

    private function parseJson(array $data, string $value, int $ms): OsintResult
    {
        $results = isset($data['results']) ? $data['results'] : (isset($data['data']) ? $data['data'] : []);
        $total   = isset($data['total']) ? (int)$data['total'] : count($results);

        if ($total === 0 && count($results) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        return $this->buildResult($total, $results, $value, $ms);
    }

    private function parseHtml(string $body, string $value, int $ms): OsintResult
    {
        $body = trim($body);
        if (empty($body)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        // Extract .onion URLs from HTML
        $onionUrls = [];
        if (preg_match_all('/https?:\/\/[a-z2-7]{16,56}\.onion[^\s"<]*/i', $body, $matches)) {
            $onionUrls = array_unique($matches[0]);
        }

        // Extract titles from anchor tags
        $titles = [];
        if (preg_match_all('/<a[^>]*>([^<]+)<\/a>/i', $body, $titleMatches)) {
            foreach (array_slice($titleMatches[1], 0, 10) as $t) {
                $t = trim(strip_tags($t));
                if (strlen($t) > 5) $titles[] = $t;
            }
        }

        $total = max(count($onionUrls), count($titles));
        if ($total === 0) {
            // Check if body contains the search term at all
            if (stripos($body, $value) === false) {
                return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
            }
            $total = 1; // At least mentioned
        }

        $results = [];
        foreach ($onionUrls as $i => $url) {
            $title = isset($titles[$i]) ? $titles[$i] : '';
            $results[] = ['url' => $url, 'title' => $title];
        }

        return $this->buildResult($total, $results, $value, $ms);
    }

    private function buildResult(int $total, array $results, string $value, int $ms): OsintResult
    {
        // Score based on dark web exposure
        if ($total >= 20) {
            $score = 80;
        } elseif ($total >= 10) {
            $score = 65;
        } elseif ($total >= 5) {
            $score = 50;
        } elseif ($total >= 1) {
            $score = 30;
        } else {
            $score = 0;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 35 + min(50, $total * 5));

        $parts = [];
        $parts[] = "Domain {$value} — {$total} dark web result(s) found via OnionSearchEngine";

        // Extract unique onion domains
        $onionDomains = [];
        foreach (array_slice($results, 0, 10) as $r) {
            $url = isset($r['url']) ? $r['url'] : '';
            if (preg_match('/([a-z2-7]{16,56}\.onion)/i', $url, $m)) {
                $onionDomains[$m[1]] = true;
            }
        }
        if (count($onionDomains) > 0) {
            $parts[] = count($onionDomains) . " unique .onion domain(s)";
        }

        // Show sample titles
        $sampleTitles = [];
        foreach (array_slice($results, 0, 3) as $r) {
            $title = isset($r['title']) ? $r['title'] : '';
            if ($title) $sampleTitles[] = $title;
        }
        if (count($sampleTitles) > 0) {
            $parts[] = "Sample: " . implode('; ', $sampleTitles);
        }

        $tags = [self::API_ID, 'domain', 'darkweb'];
        if ($total >= 10) $tags[] = 'high_exposure';
        if ($total >= 5) $tags[] = 'suspicious';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['total' => $total, 'results' => array_slice($results, 0, 20)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://onionsearchengine.com/search.php?search=test&submit=Search&api=true', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
