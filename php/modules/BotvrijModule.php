<?php
// =============================================================================
//  CTI — Botvrij.eu IOC Module
//  API: https://www.botvrij.eu/data/ (plaintext IOC lists)
//  Free, no key. Supports: domain, ip, hash
//  Downloads the relevant IOC list and checks if the value appears in it.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BotvrijModule extends BaseApiModule
{
    private const API_ID   = 'botvrij';
    private const API_NAME = 'botvrij.eu';
    private const SUPPORTED = ['domain', 'ip', 'hash'];

    private const LIST_URLS = [
        'domain' => 'https://www.botvrij.eu/data/ioclist.domain',
        'ip'     => 'https://www.botvrij.eu/data/ioclist.ip-dst',
        'hash'   => 'https://www.botvrij.eu/data/ioclist.md5',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: self::LIST_URLS[$queryType];
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $errMsg = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $resp['elapsed_ms']);
        }
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $body  = $resp['body'];
        $lines = array_filter(array_map('trim', explode("\n", $body)), fn($l) => $l !== '' && $l[0] !== '#');
        $totalEntries = count($lines);
        $isListed = in_array($queryValue, $lines, true);

        if ($isListed) {
            $score      = 75;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 90;
            $summary    = "{$queryType} {$queryValue} IS listed in the botvrij.eu IOC list ({$totalEntries} total entries).";
            $tags       = [self::API_ID, $queryType, 'blocklisted', 'malicious', 'ioc'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 85;
            $summary    = "{$queryType} {$queryValue} is NOT in the botvrij.eu IOC list. Checked against {$totalEntries} entries.";
            $tags       = [self::API_ID, $queryType, 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['is_listed' => $isListed, 'total_entries' => $totalEntries, 'list_type' => $queryType],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://www.botvrij.eu/data/ioclist.domain', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
