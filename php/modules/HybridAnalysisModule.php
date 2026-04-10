<?php
// =============================================================================
//  CTI — Hybrid Analysis Module
//  API Docs: https://www.hybrid-analysis.com/docs/api/v2
//  Auth: api-key header. Supports: hash, domain, ip
//  Endpoint: https://www.hybrid-analysis.com/api/v2/search/{type}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class HybridAnalysisModule extends BaseApiModule
{
    private const API_ID   = 'hybrid-analysis';
    private const API_NAME = 'Hybrid Analysis';
    private const SUPPORTED = ['hash', 'domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://www.hybrid-analysis.com/api/v2', '/');
        $headers = [
            'api-key'    => $apiKey,
            'User-Agent' => 'Falcon Sandbox',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ];

        if ($queryType === 'hash') {
            $url  = "{$base}/search/hash";
            $body = http_build_query(['hash' => $queryValue]);
        } elseif ($queryType === 'domain') {
            $url  = "{$base}/search/terms";
            $body = http_build_query(['domain' => $queryValue]);
        } else {
            $url  = "{$base}/search/terms";
            $body = http_build_query(['host' => $queryValue]);
        }

        $resp = HttpClient::post($url, $headers, $body, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!is_array($data)) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $results = $data;
        // For search/terms the result is in 'result' key
        if (isset($data['result'])) $results = $data['result'];
        if (isset($data['count']) && $data['count'] === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        if (empty($results) || (isset($results[0]) && empty($results))) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Analyze sandbox results
        $sampleCount = is_array($results) ? count($results) : 0;
        $verdicts    = [];
        $families    = [];
        $maxThreat   = 0;

        $items = is_array($results) && isset($results[0]) ? $results : [$results];
        foreach ($items as $item) {
            if (!is_array($item)) continue;
            $verdict = $item['verdict'] ?? '';
            if ($verdict) $verdicts[$verdict] = ($verdicts[$verdict] ?? 0) + 1;
            $family = $item['vx_family'] ?? '';
            if ($family) $families[$family] = true;
            $ts = (int)($item['threat_score'] ?? 0);
            if ($ts > $maxThreat) $maxThreat = $ts;
        }

        $score = $maxThreat > 0 ? $maxThreat : ($sampleCount > 0 ? min(60, $sampleCount * 10) : 0);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 65 + min(30, $sampleCount * 3));

        $label = match ($queryType) {
            'hash'   => "Hash {$queryValue}",
            'domain' => "Domain {$queryValue}",
            'ip'     => "IP {$queryValue}",
            default  => $queryValue,
        };

        $parts = ["{$label}: {$sampleCount} sandbox analysis result(s) on Hybrid Analysis"];
        if (!empty($verdicts)) $parts[] = "Verdicts: " . implode(', ', array_map(fn($v, $c) => "{$v}({$c})", array_keys($verdicts), $verdicts));
        if (!empty($families)) $parts[] = "Families: " . implode(', ', array_slice(array_keys($families), 0, 5));
        if ($maxThreat > 0) $parts[] = "Max threat score: {$maxThreat}/100";

        $tags = [self::API_ID, $queryType, 'sandbox'];
        if ($maxThreat >= 70) $tags[] = 'malicious';
        elseif ($maxThreat >= 40 || $sampleCount > 3) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        if (!empty($families)) $tags[] = 'malware';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: array_slice($items, 0, 5), success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://www.hybrid-analysis.com/api/v2/system/heartbeat', ['api-key' => $apiKey, 'User-Agent' => 'Falcon Sandbox'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
