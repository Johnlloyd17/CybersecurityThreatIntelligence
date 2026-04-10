<?php
// =============================================================================
//  CTI — Searchcode Module
//  API Docs: https://searchcode.com/api/
//  Free, no key required. Supports: domain
//  Endpoint: https://searchcode.com/api/codesearch_I/?q={domain}&per_page=20
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SearchcodeModule extends BaseApiModule
{
    private const API_ID   = 'searchcode';
    private const API_NAME = 'Searchcode';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl  = rtrim($baseUrl ?: 'https://searchcode.com/api', '/');
        $endpoint = "{$baseUrl}/codesearch_I/?q=" . urlencode($queryValue) . "&per_page=20";

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

        return $this->parse($data, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $value, int $ms): OsintResult
    {
        $total   = isset($data['total']) ? (int)$data['total'] : 0;
        $results = isset($data['results']) ? $data['results'] : [];

        if ($total === 0 && count($results) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        // Informational score for code exposure
        if ($total >= 100) {
            $score = 25;
        } elseif ($total >= 20) {
            $score = 15;
        } else {
            $score = 10;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 50 + min(40, $total));

        $parts = [];
        $parts[] = "Domain {$value} — {$total} code result(s) found on Searchcode";

        // Extract unique repos and languages
        $repos = [];
        $languages = [];
        foreach (array_slice($results, 0, 20) as $r) {
            $repo = isset($r['repo']) ? $r['repo'] : '';
            if ($repo) $repos[$repo] = true;
            $lang = isset($r['language']) ? $r['language'] : '';
            if ($lang) $languages[$lang] = true;
        }

        if (count($repos) > 0) {
            $parts[] = count($repos) . " unique repository(ies)";
        }
        if (count($languages) > 0) {
            $parts[] = "Languages: " . implode(', ', array_slice(array_keys($languages), 0, 5));
        }

        $tags = [self::API_ID, 'domain', 'code_search'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://searchcode.com/api/codesearch_I/?q=test&per_page=1', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
