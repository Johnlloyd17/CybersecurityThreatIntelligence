<?php
// =============================================================================
//  CTI — VXVault Module
//  API: http://vxvault.net/URL_List.php (plaintext malware URL list)
//  Free, no key. Supports: url, domain
//  Checks if URL/domain appears in VXVault's malware URL feed.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class VxVaultModule extends BaseApiModule
{
    private const API_ID   = 'vxvault';
    private const API_NAME = 'VXVault';
    private const SUPPORTED = ['url', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'http://vxvault.net/URL_List.php';
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $lines = array_filter(array_map('trim', explode("\n", $resp['body'])), fn($l) => $l !== '' && $l[0] !== '#' && strpos($l, 'http') !== false);
        $total = count($lines);
        $searchVal = strtolower($queryValue);

        $matches = [];
        foreach ($lines as $line) {
            $lower = strtolower(trim($line));
            if ($queryType === 'url' && strpos($lower, $searchVal) !== false) {
                $matches[] = $line;
            } elseif ($queryType === 'domain') {
                $host = parse_url($line, PHP_URL_HOST);
                if ($host && strtolower($host) === $searchVal) {
                    $matches[] = $line;
                }
            }
            if (count($matches) >= 20) break;
        }

        $matchCount = count($matches);

        if ($matchCount > 0) {
            $score = min(100, 85 + $matchCount);
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: OsintResult::scoreToSeverity($score), confidence: 95,
                responseMs: $resp['elapsed_ms'],
                summary: "{$queryValue}: Found {$matchCount} match(es) in VXVault malware URL feed ({$total} total).",
                tags: [self::API_ID, $queryType, 'malware', 'malicious'],
                rawData: ['matches' => array_slice($matches, 0, 10), 'total' => $total], success: true
            );
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 80,
            responseMs: $resp['elapsed_ms'],
            summary: "{$queryValue}: NOT in VXVault malware URL feed. Checked {$total} entries.",
            tags: [self::API_ID, $queryType, 'clean'],
            rawData: ['total' => $total], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('http://vxvault.net/URL_List.php', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
