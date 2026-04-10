<?php
// =============================================================================
//  CTI — CommonCrawl Module
//  API Docs: https://index.commoncrawl.org/
//  Free, no key required. Supports: domain, url
//  Endpoint: https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{domain}&output=json&limit=50
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CommonCrawlModule extends BaseApiModule
{
    private const API_ID   = 'commoncrawl';
    private const API_NAME = 'CommonCrawl';
    private const SUPPORTED = ['domain', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://index.commoncrawl.org', '/');

        $urlParam = ($queryType === 'domain')
            ? '*.' . urlencode($queryValue)
            : urlencode($queryValue);

        $endpoint = "{$baseUrl}/CC-MAIN-2024-10-index?url={$urlParam}&output=json&limit=50";

        $resp = HttpClient::get($endpoint, [], 30);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        // CommonCrawl returns NDJSON (one JSON object per line)
        $body = trim($resp['body']);
        if (empty($body)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $lines = explode("\n", $body);
        $records = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            $decoded = json_decode($line, true);
            if ($decoded) $records[] = $decoded;
        }

        if (count($records) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        return $this->parse($records, $queryType, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $records, string $type, string $value, int $ms): OsintResult
    {
        $total = count($records);

        // Gather unique URLs and status codes
        $uniqueUrls = [];
        $statusCodes = [];
        $mimeTypes = [];
        foreach ($records as $r) {
            $url = isset($r['url']) ? $r['url'] : '';
            if ($url) $uniqueUrls[$url] = true;
            $status = isset($r['status']) ? $r['status'] : '';
            if ($status) $statusCodes[$status] = (isset($statusCodes[$status]) ? $statusCodes[$status] : 0) + 1;
            $mime = isset($r['mime']) ? $r['mime'] : '';
            if ($mime) $mimeTypes[$mime] = true;
        }

        // Score: more crawl records = more internet presence (informational, not necessarily malicious)
        if ($total >= 40) {
            $score = 20;
        } elseif ($total >= 20) {
            $score = 15;
        } elseif ($total >= 5) {
            $score = 10;
        } else {
            $score = 5;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 60 + min(30, $total));

        $label = ($type === 'url') ? "URL {$value}" : "Domain {$value}";
        $parts = [];
        $parts[] = "{$label} — {$total} crawl record(s) found in CommonCrawl";
        $parts[] = count($uniqueUrls) . " unique URL(s)";
        if (count($mimeTypes) > 0) {
            $parts[] = "MIME types: " . implode(', ', array_keys($mimeTypes));
        }

        $tags = [self::API_ID, $type, 'crawl_data'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: ['records' => $records, 'total' => $total], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=example.com&output=json&limit=1', [], 15);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
