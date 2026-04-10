<?php
// =============================================================================
//  CTI — Pulsedive Module
//  API Docs: https://pulsedive.com/api/
//  Auth: key param. Supports: ip, domain, url, hash
//  Endpoint: https://pulsedive.com/api/info.php?indicator={val}&key={key}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PulsediveModule extends BaseApiModule
{
    private const API_ID   = 'pulsedive';
    private const API_NAME = 'Pulsedive';
    private const SUPPORTED = ['ip', 'domain', 'url', 'hash'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://pulsedive.com/api/info.php?' . http_build_query([
            'indicator' => $queryValue,
            'key'       => $apiKey,
        ]);

        $resp = HttpClient::get($url, [], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);
        if (isset($data['error'])) {
            if (stripos($data['error'], 'not found') !== false)
                return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
            return OsintResult::error(self::API_ID, self::API_NAME, $data['error'], $resp['elapsed_ms']);
        }

        $risk     = $data['risk'] ?? 'unknown';
        $riskRec  = $data['risk_recommended'] ?? $risk;
        $threats  = $data['threats'] ?? [];
        $feeds    = $data['feeds'] ?? [];
        $props    = $data['properties'] ?? [];
        $stamp    = $data['stamp_seen'] ?? '';

        $riskMap = ['critical' => 95, 'high' => 75, 'medium' => 50, 'low' => 20, 'none' => 0, 'unknown' => 5];
        $score = $riskMap[strtolower($risk)] ?? 5;
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = in_array($risk, ['critical','high','medium'], true) ? 85 : 60;

        $label = match ($queryType) {
            'ip' => "IP {$queryValue}", 'domain' => "Domain {$queryValue}",
            'url' => "URL {$queryValue}", 'hash' => "Hash {$queryValue}",
            default => $queryValue,
        };

        $parts = ["{$label}: Pulsedive risk: {$risk}"];
        if (!empty($threats)) {
            $threatNames = array_map(fn($t) => $t['name'] ?? '', $threats);
            $parts[] = "Threats: " . implode(', ', array_filter($threatNames));
        }
        if (!empty($feeds)) {
            $feedNames = array_map(fn($f) => $f['name'] ?? '', $feeds);
            $parts[] = "Feeds: " . implode(', ', array_slice(array_filter($feedNames), 0, 5));
        }
        if ($stamp) $parts[] = "Last seen: {$stamp}";

        $tags = [self::API_ID, $queryType];
        if ($score >= 70) $tags[] = 'malicious';
        elseif ($score >= 40) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        foreach ($threats as $t) {
            $tn = $t['name'] ?? '';
            if ($tn) $tags[] = strtolower(str_replace(' ', '_', $tn));
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique(array_slice($tags, 0, 12))), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://pulsedive.com/api/info.php?indicator=8.8.8.8&key=' . urlencode($apiKey), [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
