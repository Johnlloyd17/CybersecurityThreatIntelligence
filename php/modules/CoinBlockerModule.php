<?php
// =============================================================================
//  CTI — CoinBlocker Lists Module
//  API: https://zerodot1.gitlab.io/CoinBlockerLists/ (plaintext domain/IP lists)
//  Free, no key. Supports: domain, ip
//  Checks if a domain or IP appears in the CoinBlocker cryptojacking blocklist.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CoinBlockerModule extends BaseApiModule
{
    private const API_ID   = 'coinblocker';
    private const API_NAME = 'CoinBlocker Lists';
    private const SUPPORTED = ['domain', 'ip'];

    private const LIST_URL        = 'https://zerodot1.gitlab.io/CoinBlockerLists/list.txt';
    private const BROWSER_LIST_URL = 'https://zerodot1.gitlab.io/CoinBlockerLists/list_browser.txt';

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        // Fetch the main list
        $mainUrl = $baseUrl ?: self::LIST_URL;
        $resp = HttpClient::get($mainUrl, [], 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $errMsg = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $resp['elapsed_ms']);
        }
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $lines = array_filter(array_map('trim', explode("\n", $resp['body'])), fn($l) => $l !== '' && $l[0] !== '#');
        $totalEntries = count($lines);
        $isListed = in_array($queryValue, $lines, true);

        // Also check the browser list for additional coverage
        $inBrowserList = false;
        $resp2 = HttpClient::get(self::BROWSER_LIST_URL, [], 15);
        if (!$resp2['error'] && $resp2['status'] === 200) {
            $browserLines = array_filter(array_map('trim', explode("\n", $resp2['body'])), fn($l) => $l !== '' && $l[0] !== '#');
            $inBrowserList = in_array($queryValue, $browserLines, true);
            $totalEntries += count($browserLines);
        }

        $foundAnywhere = $isListed || $inBrowserList;
        $totalMs = $resp['elapsed_ms'] + ($resp2['elapsed_ms'] ?? 0);

        if ($foundAnywhere) {
            $listNames = [];
            if ($isListed) $listNames[] = 'main list';
            if ($inBrowserList) $listNames[] = 'browser list';
            $listStr = implode(' and ', $listNames);

            $score      = 70;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 90;
            $summary    = "{$queryType} {$queryValue} IS listed in the CoinBlocker {$listStr} (cryptojacking blocklist, {$totalEntries} total entries).";
            $tags       = [self::API_ID, $queryType, 'blocklisted', 'cryptojacking', 'mining'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 85;
            $summary    = "{$queryType} {$queryValue} is NOT in the CoinBlocker lists. Checked against {$totalEntries} entries.";
            $tags       = [self::API_ID, $queryType, 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $totalMs, summary: $summary,
            tags: $tags, rawData: ['is_listed' => $foundAnywhere, 'in_main_list' => $isListed, 'in_browser_list' => $inBrowserList, 'total_entries' => $totalEntries],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get(self::LIST_URL, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
