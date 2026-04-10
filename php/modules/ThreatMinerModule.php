<?php
// =============================================================================
//  CTI — ThreatMiner Module
//  API Docs: https://www.threatminer.org/api.php
//  Free, no key. Supports: ip, domain, hash
//  Endpoints: /v2/{type}.php?q={value}&rt={report_type}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ThreatMinerModule extends BaseApiModule
{
    private const API_ID   = 'threatminer';
    private const API_NAME = 'ThreatMiner';
    private const SUPPORTED = ['ip', 'domain', 'hash'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://api.threatminer.org/v2', '/');

        // rt=1 = WHOIS/Passive DNS, rt=2 = related samples, etc.
        $endpoint = match ($queryType) {
            'ip'     => "{$base}/host.php?q=" . urlencode($queryValue) . "&rt=1",
            'domain' => "{$base}/domain.php?q=" . urlencode($queryValue) . "&rt=1",
            'hash'   => "{$base}/sample.php?q=" . urlencode($queryValue) . "&rt=1",
            default  => "{$base}/host.php?q=" . urlencode($queryValue) . "&rt=1",
        };

        $resp = HttpClient::get($endpoint, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        // status_code: 200=found, 404=not found, 408=rate limit
        $sc = (int)($data['status_code'] ?? 0);
        if ($sc === 404 || $sc === 0) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($sc === 408) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);

        $results = $data['results'] ?? [];
        $count   = count($results);

        // Also fetch related samples (rt=2)
        $samplesEndpoint = match ($queryType) {
            'ip'     => "{$base}/host.php?q=" . urlencode($queryValue) . "&rt=2",
            'domain' => "{$base}/domain.php?q=" . urlencode($queryValue) . "&rt=2",
            'hash'   => "{$base}/sample.php?q=" . urlencode($queryValue) . "&rt=6",
            default  => null,
        };

        $sampleCount = 0;
        if ($samplesEndpoint) {
            $r2 = HttpClient::get($samplesEndpoint, [], 15);
            if ($r2['json'] && ($r2['json']['status_code'] ?? 0) === 200) {
                $sampleCount = count($r2['json']['results'] ?? []);
            }
        }

        $totalPoints = $count + $sampleCount;

        if ($sampleCount > 10)      $score = min(100, 70 + $sampleCount);
        elseif ($sampleCount > 3)    $score = 50 + $sampleCount;
        elseif ($totalPoints > 10)   $score = 35;
        elseif ($totalPoints > 3)    $score = 20;
        else                         $score = max(0, $totalPoints * 5);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 50 + min(40, $totalPoints * 2));

        $label = match ($queryType) {
            'ip'     => "IP {$queryValue}",
            'domain' => "Domain {$queryValue}",
            'hash'   => "Hash {$queryValue}",
            default  => $queryValue,
        };

        $parts = ["{$label}: {$count} passive DNS record(s)"];
        if ($sampleCount > 0) $parts[] = "{$sampleCount} related malware sample(s)";

        $tags = [self::API_ID, $queryType];
        if ($sampleCount > 5) $tags[] = 'malicious';
        elseif ($sampleCount > 0) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        if ($sampleCount > 0) $tags[] = 'malware';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.threatminer.org/v2/host.php?q=8.8.8.8&rt=1', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
