<?php
// =============================================================================
//  CTI — IBM X-Force Exchange Module
//  API Docs: https://api.xforce.ibmcloud.com/doc/
//  Auth: Basic Auth (key:password). Supports: ip, domain, hash, url
//  Endpoint: https://api.xforce.ibmcloud.com/{type}/{value}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class XForceModule extends BaseApiModule
{
    private const API_ID   = 'xforce-exchange';
    private const API_NAME = 'IBM X-Force Exchange';
    private const SUPPORTED = ['ip', 'domain', 'hash', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $base = rtrim($baseUrl ?: 'https://api.xforce.ibmcloud.com', '/');
        $headers = [
            'Authorization' => 'Basic ' . base64_encode($apiKey),
            'Accept'        => 'application/json',
        ];

        $url = match ($queryType) {
            'ip'     => "{$base}/ipr/" . urlencode($queryValue),
            'domain' => "{$base}/resolve/" . urlencode($queryValue),
            'hash'   => "{$base}/malware/" . urlencode($queryValue),
            'url'    => "{$base}/url/" . urlencode($queryValue),
            default  => "{$base}/ipr/" . urlencode($queryValue),
        };

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        return match ($queryType) {
            'ip'     => $this->parseIp($data, $queryValue, $resp['elapsed_ms']),
            'domain' => $this->parseDomain($data, $queryValue, $resp['elapsed_ms']),
            'hash'   => $this->parseHash($data, $queryValue, $resp['elapsed_ms']),
            'url'    => $this->parseUrl($data, $queryValue, $resp['elapsed_ms']),
            default  => $this->parseIp($data, $queryValue, $resp['elapsed_ms']),
        };
    }

    private function parseIp(array $data, string $ip, int $ms): OsintResult
    {
        $xfScore  = (float)($data['score'] ?? 0);     // X-Force risk score (1-10)
        $cats     = $data['cats'] ?? [];               // Categories
        $country  = $data['geo']['country'] ?? '';
        $reason   = $data['reasonDescription'] ?? '';
        $subnets  = $data['subnets'] ?? [];

        $score = min(100, (int)($xfScore * 10));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = $xfScore > 0 ? min(99, 60 + (int)($xfScore * 4)) : 50;

        $parts = ["IP {$ip}: X-Force risk score {$xfScore}/10"];
        if ($country) $parts[] = "Country: {$country}";
        if (!empty($cats)) $parts[] = "Categories: " . implode(', ', array_keys($cats));
        if ($reason) $parts[] = "Reason: {$reason}";

        $tags = [self::API_ID, 'ip'];
        if ($xfScore >= 7) $tags[] = 'malicious';
        elseif ($xfScore >= 4) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        foreach (array_keys($cats) as $c) $tags[] = strtolower(str_replace(' ', '_', $c));

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique(array_slice($tags, 0, 12))), rawData: $data, success: true
        );
    }

    private function parseDomain(array $data, string $domain, int $ms): OsintResult
    {
        $aRecords = $data['A'] ?? [];
        $aaaa     = $data['AAAA'] ?? [];
        $mx       = $data['MX'] ?? [];

        $count = count($aRecords) + count($aaaa) + count($mx);
        $parts = ["Domain {$domain}: {$count} DNS record(s) via X-Force"];
        if (!empty($aRecords)) $parts[] = "A records: " . implode(', ', array_slice($aRecords, 0, 5));

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 5, severity: 'info', confidence: 80,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'dns', 'clean'], rawData: $data, success: true
        );
    }

    private function parseHash(array $data, string $hash, int $ms): OsintResult
    {
        $malware = $data['malware'] ?? $data;
        $family  = $malware['family'] ?? [];
        $risk    = $malware['risk'] ?? 'unknown';
        $type    = $malware['type'] ?? '';
        $origins = $malware['origins'] ?? [];

        $riskMap = ['high' => 85, 'medium' => 50, 'low' => 20, 'unknown' => 10];
        $score = $riskMap[strtolower($risk)] ?? 10;
        $severity   = OsintResult::scoreToSeverity($score);

        $parts = ["Hash {$hash}: Risk level '{$risk}' on X-Force"];
        if ($type) $parts[] = "Type: {$type}";
        if (!empty($family)) $parts[] = "Family: " . implode(', ', array_slice($family, 0, 5));

        $tags = [self::API_ID, 'hash'];
        if ($score >= 70) $tags[] = 'malicious';
        elseif ($score >= 40) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        if ($type) $tags[] = 'malware';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    private function parseUrl(array $data, string $urlVal, int $ms): OsintResult
    {
        $result = $data['result'] ?? $data;
        $xfScore = (float)($result['score'] ?? 0);
        $cats    = $result['cats'] ?? $result['categoryDescriptions'] ?? [];

        $score = min(100, (int)($xfScore * 10));
        $severity   = OsintResult::scoreToSeverity($score);

        $parts = ["URL {$urlVal}: X-Force score {$xfScore}/10"];
        if (!empty($cats)) $parts[] = "Categories: " . implode(', ', is_array($cats) ? (array_keys($cats) ?: array_values($cats)) : [$cats]);

        $tags = [self::API_ID, 'url'];
        if ($xfScore >= 7) $tags[] = 'malicious';
        elseif ($xfScore >= 4) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 75,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.xforce.ibmcloud.com/ipr/8.8.8.8', ['Authorization' => 'Basic ' . base64_encode($apiKey), 'Accept' => 'application/json'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
