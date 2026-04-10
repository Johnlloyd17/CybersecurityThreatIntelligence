<?php
// =============================================================================
//  CTI — Steven Black Hosts Module
//  API: https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
//  Free, no key. Supports: domain
//  Checks if a domain appears in the Steven Black unified hosts blocklist.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class StevenBlackHostsModule extends BaseApiModule
{
    private const API_ID   = 'steven-black-hosts';
    private const API_NAME = 'Steven Black Hosts';
    private const SUPPORTED = ['domain'];

    private const HOSTS_URL = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts';

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: self::HOSTS_URL;
        $resp = HttpClient::get($url, [], 30);

        if ($resp['error'] || $resp['status'] === 0) {
            $errMsg = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $resp['elapsed_ms']);
        }
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $body  = $resp['body'];
        $lines = explode("\n", $body);
        $totalEntries = 0;
        $isListed = false;

        // Parse hosts file lines: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;

            $parts = preg_split('/\s+/', $line, 3);
            if (count($parts) < 2) continue;

            $prefix = $parts[0];
            $domain = $parts[1];

            // Only count actual blocklist entries (0.0.0.0 or 127.0.0.1 sinkhole lines)
            if ($prefix !== '0.0.0.0' && $prefix !== '127.0.0.1') continue;
            // Skip localhost entries
            if ($domain === 'localhost' || $domain === 'localhost.localdomain') continue;

            $totalEntries++;
            if (strcasecmp($domain, $queryValue) === 0) {
                $isListed = true;
            }
        }

        if ($isListed) {
            $score      = 65;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 90;
            $summary    = "Domain {$queryValue} IS listed in the Steven Black hosts blocklist ({$totalEntries} total entries). This domain is associated with ads, malware, or tracking.";
            $tags       = [self::API_ID, 'domain', 'blocklisted', 'adware', 'tracking', 'malware'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 85;
            $summary    = "Domain {$queryValue} is NOT in the Steven Black hosts blocklist. Checked against {$totalEntries} entries.";
            $tags       = [self::API_ID, 'domain', 'clean'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['is_listed' => $isListed, 'total_entries' => $totalEntries],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get(self::HOSTS_URL, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
