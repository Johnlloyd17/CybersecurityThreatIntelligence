<?php
// =============================================================================
//  CTI — ThreatFox Module (abuse.ch)
//  API Docs: https://threatfox.abuse.ch/api/
//  Free, no key. Supports: ip, domain, hash, url
//  POST JSON to: https://threatfox-api.abuse.ch/api/v1/
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ThreatFoxModule extends BaseApiModule
{
    private const API_ID   = 'threatfox';
    private const API_NAME = 'ThreatFox';
    private const SUPPORTED = ['ip', 'domain', 'hash', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'https://threatfox-api.abuse.ch/api/v1/';

        // ThreatFox uses "search_ioc" for searching indicators
        $postBody = json_encode([
            'query'      => 'search_ioc',
            'search_term' => $queryValue,
        ]);

        $resp = HttpClient::post($url, ['Content-Type' => 'application/json'], $postBody, 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $queryStatus = $data['query_status'] ?? '';
        if ($queryStatus === 'no_result') {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }
        if ($queryStatus !== 'ok') {
            return OsintResult::error(self::API_ID, self::API_NAME, "API error: {$queryStatus}", $resp['elapsed_ms']);
        }

        $iocs = $data['data'] ?? [];
        $iocCount = count($iocs);

        if ($iocCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Analyze IOCs
        $malwareNames = [];
        $threatTypes  = [];
        $confidences  = [];
        foreach ($iocs as $ioc) {
            $mw = $ioc['malware'] ?? '';
            if ($mw) $malwareNames[$mw] = true;
            $tt = $ioc['threat_type'] ?? '';
            if ($tt) $threatTypes[$tt] = true;
            $cl = (int)($ioc['confidence_level'] ?? 0);
            if ($cl) $confidences[] = $cl;
        }

        $score = min(100, 60 + $iocCount * 5);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = !empty($confidences) ? (int)(array_sum($confidences) / count($confidences)) : 75;

        $label = match ($queryType) {
            'ip'     => "IP {$queryValue}",
            'domain' => "Domain {$queryValue}",
            'hash'   => "Hash {$queryValue}",
            'url'    => "URL {$queryValue}",
            default  => $queryValue,
        };

        $parts = ["{$label}: Found in {$iocCount} ThreatFox IOC(s)"];
        if (!empty($malwareNames)) $parts[] = "Malware: " . implode(', ', array_slice(array_keys($malwareNames), 0, 5));
        if (!empty($threatTypes)) $parts[] = "Threat types: " . implode(', ', array_keys($threatTypes));

        $tags = [self::API_ID, $queryType, 'malicious'];
        foreach (array_keys($malwareNames) as $mw) $tags[] = strtolower($mw);
        foreach (array_keys($threatTypes) as $tt) $tags[] = strtolower(str_replace(' ', '_', $tt));
        $tags[] = 'ioc';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique(array_slice($tags, 0, 15))), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $postBody = json_encode(['query' => 'get_ioc_types']);
        $resp = HttpClient::post('https://threatfox-api.abuse.ch/api/v1/', ['Content-Type' => 'application/json'], $postBody, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
