<?php
// =============================================================================
//  CTI — Internet Storm Center (ISC SANS) Module
//  API Docs: https://isc.sans.edu/api/
//  Free, no key. Supports: ip
//  Endpoint: https://isc.sans.edu/api/ip/{ip}?json
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class IscSansModule extends BaseApiModule
{
    private const API_ID   = 'isc-sans';
    private const API_NAME = 'Internet Storm Center';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://isc.sans.edu/api', '/');
        $url  = "{$base}/ip/" . urlencode($queryValue) . "?json";

        $resp = HttpClient::get($url, ['User-Agent' => 'CTI-Platform/1.0'], 15);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        // ISC wraps in an "ip" key
        if (isset($data['ip'])) $data = $data['ip'];
        if (!$data) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);

        $count    = (int)($data['count'] ?? 0);       // Number of reports
        $attacks  = (int)($data['attacks'] ?? 0);      // Number of attacks
        $maxdate  = $data['maxdate'] ?? '';
        $mindate  = $data['mindate'] ?? '';
        $asn      = $data['as'] ?? '';
        $asname   = $data['asname'] ?? '';
        $country  = $data['ascountry'] ?? '';
        $network  = $data['network'] ?? '';
        $threatfeeds = $data['threatfeeds'] ?? [];

        // Score: based on reports and attacks
        if ($count === 0 && $attacks === 0) {
            $score = 0;
        } elseif ($attacks > 1000) {
            $score = 90;
        } elseif ($attacks > 100) {
            $score = 70;
        } elseif ($attacks > 10) {
            $score = 50;
        } elseif ($count > 10) {
            $score = 35;
        } else {
            $score = max(10, $count * 3);
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = $count > 0 ? min(99, 55 + min(40, $count)) : 40;

        $parts = ["IP {$queryValue}: {$count} report(s), {$attacks} attack(s) recorded by ISC"];
        if ($asn) $parts[] = "ASN: {$asn} ({$asname})";
        if ($country) $parts[] = "Country: {$country}";
        if ($network) $parts[] = "Network: {$network}";
        if ($maxdate) $parts[] = "Last seen: {$maxdate}";

        if (!empty($threatfeeds) && is_array($threatfeeds)) {
            $feedNames = array_keys($threatfeeds);
            $parts[] = "Threat feeds: " . implode(', ', array_slice($feedNames, 0, 5));
        }

        $tags = [self::API_ID, 'ip'];
        if ($attacks > 100) $tags[] = 'malicious';
        elseif ($count > 5) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        if ($attacks > 0) $tags[] = 'attacker';
        if (!empty($threatfeeds)) $tags[] = 'threat_feed';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://isc.sans.edu/api/ip/8.8.8.8?json', ['User-Agent' => 'CTI-Platform/1.0'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
