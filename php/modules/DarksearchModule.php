<?php
// =============================================================================
//  CTI — Darksearch Module
//  API Docs: https://darksearch.io/apidoc
//  Free, no key required. Supports: domain
//  Endpoint: https://darksearch.io/api/search?query={domain}&page=1
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DarksearchModule extends BaseApiModule
{
    private const API_ID   = 'darksearch';
    private const API_NAME = 'Darksearch';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl  = rtrim($baseUrl ?: 'https://darksearch.io/api', '/');
        $endpoint = "{$baseUrl}/search?query=" . urlencode($queryValue) . "&page=1";

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
        $results = isset($data['data']) ? $data['data'] : [];

        if ($total === 0 && count($results) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        // Score based on dark web exposure
        if ($total >= 50) {
            $score = 85;
        } elseif ($total >= 20) {
            $score = 70;
        } elseif ($total >= 10) {
            $score = 55;
        } elseif ($total >= 5) {
            $score = 40;
        } elseif ($total >= 1) {
            $score = 25;
        } else {
            $score = 0;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 40 + min(50, $total * 3));

        $parts = [];
        $parts[] = "Domain {$value} — {$total} dark web result(s) found via Darksearch";

        $lastPage = isset($data['last_page']) ? (int)$data['last_page'] : 1;
        if ($lastPage > 1) {
            $parts[] = "{$lastPage} page(s) of results available";
        }

        // Extract sample titles
        $titles = [];
        foreach (array_slice($results, 0, 3) as $r) {
            $title = isset($r['title']) ? $r['title'] : '';
            if ($title) $titles[] = $title;
        }
        if (count($titles) > 0) {
            $parts[] = "Sample titles: " . implode('; ', $titles);
        }

        $tags = [self::API_ID, 'domain', 'darkweb'];
        if ($total >= 20) $tags[] = 'high_exposure';
        if ($total >= 10) $tags[] = 'suspicious';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://darksearch.io/api/search?query=test&page=1', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
