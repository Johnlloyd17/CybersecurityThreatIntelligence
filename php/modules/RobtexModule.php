<?php
// =============================================================================
//  CTI — Robtex Module
//  API Docs: https://www.robtex.com/api/
//  Free, no key. Supports: ip, domain
//  Endpoints: /freeapi/ipquery/{ip}, /freeapi/pdns/forward/{domain}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class RobtexModule extends BaseApiModule
{
    private const API_ID   = 'robtex';
    private const API_NAME = 'Robtex';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://freeapi.robtex.com', '/');

        if ($queryType === 'ip') {
            $url = "{$base}/ipquery/{$queryValue}";
        } else {
            $url = "{$base}/pdns/forward/{$queryValue}";
        }

        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        if ($queryType === 'ip') {
            return $this->parseIpResponse($resp, $queryValue);
        }
        return $this->parseDomainResponse($resp, $queryValue);
    }

    private function parseIpResponse(array $resp, string $ip): OsintResult
    {
        $data = $resp['json'];
        if (!$data || ($data['status'] ?? '') === 'error') {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $ip, $resp['elapsed_ms']);
        }

        $status   = $data['status'] ?? 'ok';
        $city     = $data['city'] ?? '';
        $country  = $data['country'] ?? '';
        $asn      = $data['as'] ?? '';
        $asname   = $data['asname'] ?? '';
        $whois    = $data['whoisdesc'] ?? '';
        $act      = $data['act'] ?? [];   // Active DNS (A records pointing here)
        $acth     = $data['acth'] ?? [];  // Active DNS (history)
        $pas      = $data['pas'] ?? [];   // Passive DNS

        $actCount = count($act);
        $pasCount = count($pas);

        $score = min(30, $actCount + $pasCount);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 60 + min(30, $actCount + $pasCount));

        $parts = ["IP {$ip}"];
        if ($asn) $parts[] = "ASN: {$asn} ({$asname})";
        if ($country) $parts[] = "Country: {$country}";
        if ($city) $parts[] = "City: {$city}";
        $parts[] = "{$actCount} active DNS record(s), {$pasCount} passive DNS record(s)";

        $tags = [self::API_ID, 'ip', 'dns'];
        if ($actCount > 20) $tags[] = 'shared_hosting';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    private function parseDomainResponse(array $resp, string $domain): OsintResult
    {
        // PDNS forward returns NDJSON (one JSON per line)
        $body = trim($resp['body']);
        $lines = array_filter(explode("\n", $body), fn($l) => trim($l) !== '');
        $records = [];
        foreach ($lines as $line) {
            $rec = json_decode($line, true);
            if ($rec) $records[] = $rec;
        }

        if (empty($records)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $domain, $resp['elapsed_ms']);
        }

        $ips = [];
        $firstSeen = null;
        $lastSeen = null;
        foreach ($records as $r) {
            if (isset($r['rrdata'])) $ips[$r['rrdata']] = true;
            $fs = $r['time_first'] ?? null;
            $ls = $r['time_last'] ?? null;
            if ($fs && (!$firstSeen || $fs < $firstSeen)) $firstSeen = $fs;
            if ($ls && (!$lastSeen || $ls > $lastSeen)) $lastSeen = $ls;
        }

        $ipCount = count($ips);
        $score = min(20, $ipCount * 2);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 65 + min(25, count($records)));

        $parts = ["Domain {$domain}: {$ipCount} unique IP(s) in passive DNS, " . count($records) . " record(s)"];
        $sampleIps = array_slice(array_keys($ips), 0, 5);
        if (!empty($sampleIps)) $parts[] = "IPs: " . implode(', ', $sampleIps);

        $tags = [self::API_ID, 'domain', 'dns', 'passive_dns'];
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['records' => array_slice($records, 0, 50), 'ip_count' => $ipCount],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://freeapi.robtex.com/ipquery/8.8.8.8', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
