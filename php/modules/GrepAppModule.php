<?php
// =============================================================================
//  CTI — grep.app Module (Code Search)
//  API Docs: https://grep.app/
//  Free, no key required. Supports: domain, hash
//  Endpoint: https://grep.app/api/search?q={value}&regexp=false
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GrepAppModule extends BaseApiModule
{
    private const API_ID   = 'grep-app';
    private const API_NAME = 'grep.app';
    private const SUPPORTED = ['domain', 'hash'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl  = rtrim($baseUrl ?: 'https://grep.app/api', '/');
        $endpoint = "{$baseUrl}/search?q=" . urlencode($queryValue) . "&regexp=false";

        $resp = HttpClient::get($endpoint, [], 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        return $this->parse($data, $queryType, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $type, string $value, int $ms): OsintResult
    {
        $hits   = isset($data['hits']) ? $data['hits'] : [];
        $facets = isset($data['facets']) ? $data['facets'] : [];
        $count  = isset($hits['total']) ? (int)$hits['total'] : 0;
        $results = isset($hits['hits']) ? $hits['hits'] : [];

        if ($count === 0 && count($results) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        // Score based on code exposure
        if ($type === 'hash') {
            // Hash found in code repos is more concerning
            $score = ($count >= 5) ? 60 : (($count >= 1) ? 45 : 0);
        } else {
            // Domain references in code
            if ($count >= 50) {
                $score = 30;
            } elseif ($count >= 10) {
                $score = 20;
            } else {
                $score = 10;
            }
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 50 + min(40, $count * 2));

        $label = ($type === 'hash') ? "Hash {$value}" : "Domain {$value}";
        $parts = [];
        $parts[] = "{$label} — {$count} code match(es) found on grep.app";

        // Extract unique repos
        $repos = [];
        foreach (array_slice($results, 0, 10) as $hit) {
            $source = isset($hit['_source']) ? $hit['_source'] : [];
            $repo = isset($source['repo']) ? $source['repo'] : [];
            $repoName = isset($repo['raw']) ? $repo['raw'] : '';
            if ($repoName) $repos[$repoName] = true;
        }
        if (count($repos) > 0) {
            $parts[] = count($repos) . " unique repository(ies)";
            $repoList = array_slice(array_keys($repos), 0, 3);
            $parts[] = "Repos: " . implode(', ', $repoList);
        }

        $tags = [self::API_ID, $type, 'code_search'];
        if ($type === 'hash' && $count > 0) $tags[] = 'leaked';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://grep.app/api/search?q=test&regexp=false', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
