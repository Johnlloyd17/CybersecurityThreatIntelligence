<?php
require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';

class TorchModule extends BaseApiModule
{
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        $query = urlencode($queryValue);
        $url = "https://ahmia.fi/search/?q={$query}";

        $resp = HttpClient::get($url, ['User-Agent: Mozilla/5.0 (CTI Platform)'], 15);

        if ($resp['error'] || $resp['status'] !== 200) {
            return OsintResult::error('torch', 'Torch (via Ahmia)', 'Search failed: ' . ($resp['error'] ?: "HTTP {$resp['status']}"));
        }

        $body = $resp['body'];
        $results = [];

        if (preg_match_all('/<li[^>]*class="[^"]*result[^"]*"[^>]*>(.*?)<\/li>/si', $body, $matches)) {
            foreach ($matches[1] as $item) {
                $title = '';
                $link = '';
                $snippet = '';
                if (preg_match('/<a[^>]+href="([^"]*)"[^>]*>(.*?)<\/a>/si', $item, $a)) {
                    $link = html_entity_decode(strip_tags($a[1]));
                    $title = html_entity_decode(strip_tags($a[2]));
                }
                if (preg_match('/<p[^>]*>(.*?)<\/p>/si', $item, $p)) {
                    $snippet = html_entity_decode(strip_tags($p[1]));
                }
                if ($title || $link) {
                    $results[] = ['title' => $title, 'url' => $link, 'snippet' => substr($snippet, 0, 200)];
                }
                if (count($results) >= 15) break;
            }
        }

        $count = count($results);
        $score = $count > 0 ? min(20 + $count * 4, 65) : 0;

        return new OsintResult(
            api:        'torch',
            apiName:    'Torch (via Ahmia)',
            score:      $score,
            severity:   OsintResult::scoreToSeverity($score),
            confidence: $count > 0 ? 60 : 80,
            responseMs: $resp['elapsed_ms'],
            summary:    $count > 0
                ? "Found {$count} dark web result(s) for {$queryValue} via Ahmia search engine."
                : "No dark web results found for {$queryValue} via Ahmia.",
            tags:       $count > 0 ? ['darknet', 'tor', 'onion'] : ['darknet', 'clean'],
            rawData:    ['results' => $results, 'query' => $queryValue],
            success:    true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $resp = HttpClient::get('https://ahmia.fi/', [], 10);
        $ms = round((microtime(true) - $start) * 1000);
        return [
            'status' => $resp['status'] === 200 ? 'up' : 'down',
            'latency_ms' => $ms,
            'error' => $resp['error'],
        ];
    }
}

require_once __DIR__ . '/BaseApiModule.php';