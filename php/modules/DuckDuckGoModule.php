<?php
// =============================================================================
//  CTI — DuckDuckGo Instant Answers Module
//  API Docs: https://api.duckduckgo.com/api
//  Free, no key. Supports: domain
//  Endpoint: https://api.duckduckgo.com/?q={query}&format=json
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DuckDuckGoModule extends BaseApiModule
{
    private const API_ID   = 'duckduckgo';
    private const API_NAME = 'DuckDuckGo';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.duckduckgo.com/?q=' . urlencode($queryValue) . '&format=json&no_html=1';
        $resp = HttpClient::get($url, [], 15);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $abstract    = $data['Abstract'] ?? '';
        $abstractUrl = $data['AbstractURL'] ?? '';
        $heading     = $data['Heading'] ?? '';
        $related     = $data['RelatedTopics'] ?? [];
        $infobox     = $data['Infobox'] ?? null;

        if (!$abstract && empty($related) && !$heading) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $parts = ["Domain {$queryValue}"];
        if ($heading) $parts[] = "Topic: {$heading}";
        if ($abstract) $parts[] = substr($abstract, 0, 200);
        if (!empty($related)) $parts[] = count($related) . " related topic(s)";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 5, severity: 'info', confidence: 70,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'osint', 'clean'],
            rawData: ['heading' => $heading, 'abstract' => substr($abstract, 0, 500), 'url' => $abstractUrl, 'related_count' => count($related)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.duckduckgo.com/?q=test&format=json', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
