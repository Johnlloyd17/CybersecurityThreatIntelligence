<?php
// =============================================================================
//  CTI — CyberCrime-Tracker Module
//  Free, no key required. Supports: domain, ip, url
//  Endpoint: http://cybercrime-tracker.net/all.php (plaintext C2 list)
//  Checks if target appears in the C2 tracker list
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CybercrimeTrackerModule extends BaseApiModule
{
    private const API_ID   = 'cybercrime-tracker';
    private const API_NAME = 'CyberCrime-Tracker';
    private const SUPPORTED = ['domain', 'ip', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $feedUrl = $baseUrl ? rtrim($baseUrl, '/') . '/all.php' : 'http://cybercrime-tracker.net/all.php';

        $resp = HttpClient::get($feedUrl, [], 30);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $body = trim($resp['body']);
        if (empty($body)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Empty response from C2 feed', $resp['elapsed_ms']);
        }

        return $this->parse($body, $queryType, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(string $body, string $type, string $value, int $ms): OsintResult
    {
        $lines = explode("\n", $body);
        $matches = [];
        $searchValue = strtolower(trim($value));

        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line) || $line[0] === '#') continue;

            $lineLower = strtolower($line);
            if (strpos($lineLower, $searchValue) !== false) {
                $matches[] = $line;
            }
        }

        $totalEntries = count($lines);
        $matchCount   = count($matches);

        if ($matchCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        // Found in C2 tracker = high threat
        if ($matchCount >= 5) {
            $score = 95;
        } elseif ($matchCount >= 3) {
            $score = 90;
        } elseif ($matchCount >= 1) {
            $score = 85;
        } else {
            $score = 0;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 80 + $matchCount * 5);

        $label = match ($type) {
            'ip'     => "IP {$value}",
            'domain' => "Domain {$value}",
            'url'    => "URL {$value}",
            default  => $value,
        };

        $parts = [];
        $parts[] = "{$label} — FOUND in CyberCrime-Tracker C2 feed ({$matchCount} match(es))";
        $parts[] = "C2 feed contains {$totalEntries} total entries";

        // Show up to 3 matching entries
        foreach (array_slice($matches, 0, 3) as $m) {
            $parts[] = "Match: {$m}";
        }

        $tags = [self::API_ID, $type, 'c2', 'malicious', 'botnet'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: ['matches' => $matches, 'total_entries' => $totalEntries], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('http://cybercrime-tracker.net/all.php', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
