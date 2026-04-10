<?php
// =============================================================================
//  CTI — Custom Threat Feed Module
//  Uses user-configured custom threat feed URL from baseUrl.
//  Fetches feed, parses as CSV/JSON/text lines, searches for query matches.
//  Supports: ip, domain, url, hash, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CustomThreatFeedModule extends BaseApiModule
{
    private const API_ID   = 'custom-threat-feed';
    private const API_NAME = 'Custom Threat Feed';
    private const SUPPORTED = ['ip', 'domain', 'url', 'hash', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);
        $feedUrl = trim($baseUrl);

        if (empty($feedUrl)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'No feed URL configured. Set the base URL to your threat feed endpoint.');
        }

        try {
            $headers = [];
            if (!empty($apiKey)) {
                $headers['Authorization'] = 'Bearer ' . $apiKey;
            }

            $resp = HttpClient::get($feedUrl, $headers, 30, 1);
            $ms = (int)((microtime(true) - $start) * 1000);

            if ($resp['error']) {
                return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'], $ms);
            }
            if ($resp['status'] === 401 || $resp['status'] === 403) {
                return OsintResult::unauthorized(self::API_ID, self::API_NAME, $ms);
            }
            if ($resp['status'] === 429) {
                return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
            }
            if ($resp['status'] >= 400) {
                $status = $resp['status'];
                return OsintResult::error(self::API_ID, self::API_NAME, "Feed returned HTTP {$status}", $ms);
            }

            $body = $resp['body'];
            $matches = [];
            $totalEntries = 0;

            // Try JSON format first
            if ($resp['json'] !== null) {
                $matches = $this->searchJson($resp['json'], $value, $totalEntries);
            } else {
                // Try CSV or plain text lines
                $matches = $this->searchTextLines($body, $value, $totalEntries);
            }

            $ms = (int)((microtime(true) - $start) * 1000);
            $matchCount = count($matches);

            if ($matchCount === 0) {
                return new OsintResult(
                    api: self::API_ID, apiName: self::API_NAME,
                    score: 0, severity: 'info', confidence: 70,
                    responseMs: $ms,
                    summary: "No matches for '{$value}' in custom threat feed ({$totalEntries} entries checked).",
                    tags: [self::API_ID, $queryType, 'clean'],
                    rawData: ['total_entries' => $totalEntries, 'matches' => []],
                    success: true
                );
            }

            $score = min(40 + ($matchCount * 15), 90);
            $severity = OsintResult::scoreToSeverity($score);

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: 65,
                responseMs: $ms,
                summary: "{$matchCount} match(es) found for '{$value}' in custom threat feed ({$totalEntries} entries).",
                tags: array_values(array_unique([self::API_ID, $queryType, 'threat_feed', 'listed'])),
                rawData: [
                    'total_entries' => $totalEntries,
                    'match_count' => $matchCount,
                    'matches' => array_slice($matches, 0, 20),
                ],
                success: true
            );
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    private function searchJson($json, string $needle, int &$totalEntries): array
    {
        $matches = [];

        // Handle array of objects or flat array
        if (is_array($json)) {
            $items = isset($json['data']) ? $json['data'] : (isset($json['results']) ? $json['results'] : $json);

            if (!is_array($items)) {
                return $matches;
            }

            $totalEntries = count($items);
            $lowerNeedle = strtolower($needle);

            foreach ($items as $item) {
                $serialized = is_array($item) ? json_encode($item) : (string)$item;
                if (stripos($serialized, $lowerNeedle) !== false) {
                    $matches[] = is_array($item) ? $item : ['value' => $item];
                }
            }
        }

        return $matches;
    }

    private function searchTextLines(string $body, string $needle, int &$totalEntries): array
    {
        $matches = [];
        $lines = preg_split('/\r?\n/', $body);
        $totalEntries = 0;
        $lowerNeedle = strtolower($needle);

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $totalEntries++;

            if (stripos($line, $lowerNeedle) !== false) {
                // Try CSV parsing
                $fields = str_getcsv($line);
                if (count($fields) > 1) {
                    $matches[] = ['raw_line' => $line, 'fields' => $fields];
                } else {
                    $matches[] = ['value' => $line];
                }
            }
        }

        return $matches;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        if (empty(trim($baseUrl))) {
            return ['status' => 'unconfigured', 'latency_ms' => 0, 'error' => 'No feed URL configured'];
        }

        $headers = [];
        if (!empty($apiKey)) {
            $headers['Authorization'] = 'Bearer ' . $apiKey;
        }

        $start = microtime(true);
        $resp = HttpClient::get(trim($baseUrl), $headers, 10, 0);
        $latency = (int)((microtime(true) - $start) * 1000);

        if ($resp['error']) {
            return ['status' => 'down', 'latency_ms' => $latency, 'error' => $resp['error']];
        }
        if ($resp['status'] >= 400) {
            $status = $resp['status'];
            return ['status' => 'down', 'latency_ms' => $latency, 'error' => "HTTP {$status}"];
        }

        return ['status' => 'up', 'latency_ms' => $latency, 'error' => null];
    }
}
