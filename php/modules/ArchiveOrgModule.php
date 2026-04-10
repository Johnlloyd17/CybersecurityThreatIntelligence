<?php
// =============================================================================
//  CTI — Archive.org (Wayback Machine) Module
//  API Docs: https://archive.org/help/wayback_api.php
//  Free, no key. Supports: domain, url
//  Endpoint: https://archive.org/wayback/available?url={target}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ArchiveOrgModule extends BaseApiModule
{
    private const API_ID   = 'archive-org';
    private const API_NAME = 'Archive.org';
    private const SUPPORTED = ['domain', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://archive.org/wayback/available?url=' . urlencode($queryValue);
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $snapshot = $data['archived_snapshots']['closest'] ?? null;

        if (!$snapshot || !($snapshot['available'] ?? false)) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 5, severity: 'info', confidence: 70,
                responseMs: $resp['elapsed_ms'],
                summary: "{$queryValue}: No archived snapshots found on Archive.org.",
                tags: [self::API_ID, $queryType, 'no_archive'],
                rawData: $data, success: true
            );
        }

        $archiveUrl = $snapshot['url'] ?? '';
        $timestamp  = $snapshot['timestamp'] ?? '';
        $status     = $snapshot['status'] ?? '';

        // Format timestamp: 20240101120000 → 2024-01-01
        $dateStr = '';
        if (strlen($timestamp) >= 8) {
            $dateStr = substr($timestamp, 0, 4) . '-' . substr($timestamp, 4, 2) . '-' . substr($timestamp, 6, 2);
        }

        // Having archive data is informational, not a threat indicator
        $score      = 5;
        $severity   = 'info';
        $confidence = 85;

        $label = $queryType === 'domain' ? "Domain {$queryValue}" : "URL {$queryValue}";
        $summary = "{$label}: Found in Archive.org. Latest snapshot: {$dateStr}. Status: {$status}.";

        $tags = [self::API_ID, $queryType, 'archived', 'clean'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://archive.org/wayback/available?url=google.com', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
