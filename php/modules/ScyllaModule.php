<?php
// =============================================================================
//  CTI — Scylla Module (Leak Database)
//  Queries scylla.sh for breach data.
//  Supports: email, username
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ScyllaModule extends BaseApiModule
{
    private const API_ID   = 'scylla';
    private const API_NAME = 'Scylla';
    private const SUPPORTED = ['email', 'username'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $value = urlencode($queryValue);
        $field = $queryType === 'email' ? 'email' : 'username';
        $url = "https://scylla.sh/search?q={$field}:{$value}";

        $r = HttpClient::get($url, [
            'Accept' => 'application/json',
        ], 15);

        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
        }

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        $data = $r['json'];
        if ($data === null) {
            // Might be down or returning non-JSON
            if ($r['status'] >= 400) {
                return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$r['status']}", $ms);
            }
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $ms);
        }

        if (empty($data)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $ms);
        }

        $leakCount = is_array($data) ? count($data) : 0;

        if ($leakCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $ms);
        }

        // Extract breach sources
        $sources = [];
        foreach ($data as $entry) {
            if (is_array($entry)) {
                $src = isset($entry['_source']) ? $entry['_source'] : $entry;
                $source = isset($src['domain']) ? $src['domain'] : 'unknown';
                if (!in_array($source, $sources, true)) {
                    $sources[] = $source;
                }
            }
        }

        $parts = ["{$queryType} '{$queryValue}': Found in {$leakCount} breach record(s)"];
        if (!empty($sources)) {
            $showSources = array_slice($sources, 0, 10);
            $parts[] = "Sources: " . implode(', ', $showSources);
        }

        $score = min(90, 50 + $leakCount * 3);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 75;
        $tags = [self::API_ID, $queryType, 'breach', 'leaked'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'leak_count' => $leakCount,
                'sources' => $sources,
                'sample' => array_slice($data, 0, 5),
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://scylla.sh', [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] >= 200 && $r['status'] < 500) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
