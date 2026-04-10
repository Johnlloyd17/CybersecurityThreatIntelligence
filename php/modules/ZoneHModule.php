<?php
// =============================================================================
//  CTI — Zone-H Defacement Check Module
//  URL: https://zone-h.org/?hz={domain}
//  Free, no key. Supports: domain
//  Checks if a domain has defacement records on Zone-H by scraping the page.
//  Note: No public API available; results are informational only.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ZoneHModule extends BaseApiModule
{
    private const API_ID   = 'zone-h';
    private const API_NAME = 'Zone-H Defacement Check';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $encodedDomain = urlencode($queryValue);
        $base = $baseUrl ?: 'https://zone-h.org';
        $url = "{$base}/?hz={$encodedDomain}";
        $resp = HttpClient::get($url, ['Accept' => 'text/html'], 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $errMsg = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $resp['elapsed_ms']);
        }

        if ($resp['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        }

        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $html = $resp['body'];

        // Look for indicators of defacement records in the HTML
        // Zone-H typically shows defacement entries in table rows with domain references
        $hasDefacements = false;
        $defacementCount = 0;

        // Check for common patterns indicating defacement records
        // Zone-H shows "Total defacements" or table rows with defacement data
        if (preg_match('/Total\s+defacements?\s*:\s*(\d+)/i', $html, $matches)) {
            $defacementCount = (int)$matches[1];
            $hasDefacements = $defacementCount > 0;
        } elseif (preg_match_all('/defacement|defaced/i', $html, $matches)) {
            // Fallback: count references to defacement in the page
            $mentionCount = count($matches[0]);
            // Filter out generic page chrome mentions (nav, footer, etc.)
            if ($mentionCount > 3) {
                $hasDefacements = true;
                $defacementCount = $mentionCount;
            }
        }

        // Also look for the domain appearing in table data cells as a record
        $domainEscaped = preg_quote($queryValue, '/');
        $domainInTable = preg_match_all('/<td[^>]*>.*?' . $domainEscaped . '.*?<\/td>/is', $html, $tableMatches);

        if ($domainInTable > 0 && !$hasDefacements) {
            $hasDefacements = true;
            $defacementCount = $domainInTable;
        }

        // Check for "no records" or empty results
        $noRecords = preg_match('/no\s+records?\s+found|nothing\s+found|0\s+results?/i', $html);
        if ($noRecords) {
            $hasDefacements = false;
            $defacementCount = 0;
        }

        if ($hasDefacements) {
            $score      = 55;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 60;
            $countStr = $defacementCount > 0 ? " ({$defacementCount} record(s))" : '';
            $summary    = "Domain {$queryValue} has defacement records on Zone-H{$countStr}. This may indicate past security compromises.";
            $tags       = [self::API_ID, 'domain', 'defaced', 'compromised', 'web-security'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 50;
            $summary    = "No defacement records found for {$queryValue} on Zone-H. Note: Zone-H may require CAPTCHA for some queries, so results are informational.";
            $tags       = [self::API_ID, 'domain', 'clean', 'no-defacement'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['has_defacements' => $hasDefacements, 'defacement_count' => $defacementCount, 'domain' => $queryValue],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://zone-h.org', ['Accept' => 'text/html'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
