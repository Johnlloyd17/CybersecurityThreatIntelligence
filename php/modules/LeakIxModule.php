<?php
// =============================================================================
//  CTI — LeakIX Module
//  API Docs: https://leakix.net/api-documentation
//  Auth: api-key header. Supports: ip, domain
//  Endpoint: https://leakix.net/host/{ip} or /search?scope=leak&q={domain}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class LeakIxModule extends BaseApiModule
{
    private const API_ID   = 'leakix';
    private const API_NAME = 'LeakIX';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $headers = ['Accept' => 'application/json'];
        if ($apiKey) $headers['api-key'] = $apiKey;

        if ($queryType === 'ip') {
            $url = 'https://leakix.net/host/' . urlencode($queryValue);
        } else {
            $url = 'https://leakix.net/search?scope=leak&q=' . urlencode($queryValue);
        }

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);

        if ($queryType === 'ip') {
            $services = $data['Services'] ?? [];
            $leaks    = $data['Leaks'] ?? [];
            $events   = $data['Events'] ?? [];

            $leakCount = count($leaks);
            $svcCount  = count($services);

            $score = min(100, $leakCount * 20 + $svcCount * 3);
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = min(99, 60 + min(35, $leakCount * 5 + $svcCount));

            $parts = ["IP {$queryValue}: {$svcCount} service(s), {$leakCount} leak(s) on LeakIX"];

            $ports = [];
            foreach ($services as $s) { if (isset($s['port'])) $ports[] = $s['port']; }
            if (!empty($ports)) $parts[] = "Ports: " . implode(', ', array_slice($ports, 0, 10));

            $tags = [self::API_ID, 'ip'];
            if ($leakCount > 0) $tags[] = 'data_leak';
            if ($leakCount > 0) $tags[] = 'malicious';
            else $tags[] = 'clean';
        } else {
            $results = is_array($data) ? $data : [];
            $count = count($results);

            $score = min(100, $count * 15);
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = min(99, 55 + min(40, $count * 5));

            $parts = ["Domain {$queryValue}: {$count} leak(s) found on LeakIX"];

            $tags = [self::API_ID, 'domain'];
            if ($count > 0) { $tags[] = 'data_leak'; $tags[] = 'suspicious'; }
            else $tags[] = 'clean';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['Accept' => 'application/json'];
        if ($apiKey) $headers['api-key'] = $apiKey;
        $resp = HttpClient::get('https://leakix.net/host/8.8.8.8', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
