<?php
// =============================================================================
//  CTI — HackerTarget Module
//  API Docs: https://hackertarget.com/api/
//  Free tier: no key, 100 req/day. Supports: domain, ip
//  Endpoints: /api/{tool}/?q={target}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class HackerTargetModule extends BaseApiModule
{
    private const API_ID   = 'hackertarget';
    private const API_NAME = 'HackerTarget';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = 'https://api.hackertarget.com';

        // For domains: hostsearch (subdomains), dnslookup, reversedns
        // For IPs: reverseiplookup, aslookup
        if ($queryType === 'domain') {
            $url = "{$base}/hostsearch/?q=" . urlencode($queryValue);
        } else {
            $url = "{$base}/reverseiplookup/?q=" . urlencode($queryValue);
        }

        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $body = trim($resp['body']);

        // Error responses are plain text starting with "error"
        if (stripos($body, 'error') === 0 || stripos($body, 'API count exceeded') !== false) {
            if (stripos($body, 'API count exceeded') !== false) {
                return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
            }
            return OsintResult::error(self::API_ID, self::API_NAME, $body, $resp['elapsed_ms']);
        }

        if ($body === '' || $body === 'No records found' || stripos($body, 'no results') !== false) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Parse CSV-like response (each line: hostname,ip)
        $lines = array_filter(explode("\n", $body), fn($l) => trim($l) !== '');
        $count = count($lines);

        // Also get AS info for IPs
        $asnInfo = '';
        if ($queryType === 'ip') {
            $asnResp = HttpClient::get("{$base}/aslookup/?q=" . urlencode($queryValue), [], 10);
            if ($asnResp['status'] === 200 && $asnResp['body']) {
                $asnInfo = trim($asnResp['body']);
            }
        }

        // Score based on number of results (more hosted domains/subdomains = more interesting)
        if ($queryType === 'domain') {
            $score = min(30, $count * 2); // subdomains aren't necessarily threats
        } else {
            $score = min(40, $count); // many domains on one IP can indicate shared hosting
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 60 + min(30, $count));

        $label = $queryType === 'domain' ? "Domain {$queryValue}" : "IP {$queryValue}";
        $parts = [];
        if ($queryType === 'domain') {
            $parts[] = "{$label}: {$count} subdomain(s)/host(s) found";
            // Show first 5 entries
            $sample = array_slice($lines, 0, 5);
            foreach ($sample as $line) {
                $cols = explode(',', $line);
                if (isset($cols[0])) $parts[] = trim($cols[0]);
            }
            if ($count > 5) $parts[] = "... and " . ($count - 5) . " more";
        } else {
            $parts[] = "{$label}: {$count} domain(s) hosted on this IP";
            if ($asnInfo) $parts[] = "ASN: " . substr($asnInfo, 0, 100);
        }

        $tags = [self::API_ID, $queryType, 'dns'];
        if ($count > 50) $tags[] = 'shared_hosting';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: ['lines' => $lines, 'count' => $count, 'asn' => $asnInfo],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.hackertarget.com/hostsearch/?q=google.com', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200 && stripos($resp['body'], 'error') !== 0) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
