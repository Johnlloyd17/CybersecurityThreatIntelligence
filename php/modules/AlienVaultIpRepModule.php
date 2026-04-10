<?php
// =============================================================================
//  CTI — AlienVault IP Reputation Module
//  API Docs: https://otx.alienvault.com/api
//  Free, no key required. Supports: ip
//  Endpoint: https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class AlienVaultIpRepModule extends BaseApiModule
{
    private const API_ID   = 'alienvault-ip-rep';
    private const API_NAME = 'AlienVault IP Reputation';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl  = rtrim($baseUrl ?: 'https://otx.alienvault.com/api/v1', '/');
        $endpoint = "{$baseUrl}/indicators/IPv4/" . urlencode($queryValue) . "/reputation";

        $headers = ['Accept' => 'application/json'];
        if ($apiKey) {
            $headers['X-OTX-API-KEY'] = $apiKey;
        }

        $resp = HttpClient::get($endpoint, $headers, 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        return $this->parse($data, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $value, int $ms): OsintResult
    {
        $reputation = isset($data['reputation']) ? $data['reputation'] : null;
        $activities = isset($data['reputation_details']) ? $data['reputation_details'] : [];

        // Check for different response structures
        if ($reputation === null && isset($data['data'])) {
            $reputation = $data['data'];
        }

        // If reputation data is empty, it means the IP has no reputation data
        if ($reputation === null && count($activities) === 0) {
            // Try to determine if it's clean or just unknown
            $score      = 5;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 60;

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $score, severity: $severity, confidence: $confidence,
                responseMs: $ms, summary: "IP {$value} — No reputation data found in AlienVault OTX. Likely clean.",
                tags: [self::API_ID, 'ip', 'clean'], rawData: $data, success: true
            );
        }

        // Parse reputation score if available
        $repScore = 0;
        if (is_numeric($reputation)) {
            $repScore = (int)$reputation;
        }

        $activityCount = count($activities);

        // Score based on reputation and activities
        if ($repScore > 0 || $activityCount > 5) {
            $score = min(100, 50 + $repScore * 5 + $activityCount * 3);
        } elseif ($activityCount > 0) {
            $score = 30 + $activityCount * 5;
        } else {
            $score = max(0, $repScore * 10);
        }
        $score = min(100, $score);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 50 + min(40, $activityCount * 5));

        $parts = [];
        $parts[] = "IP {$value} — AlienVault reputation score: {$repScore}";
        if ($activityCount > 0) {
            $parts[] = "{$activityCount} reputation activit(y/ies) recorded";

            // Extract activity types
            $actTypes = [];
            foreach (array_slice($activities, 0, 5) as $act) {
                $actType = isset($act['activity']) ? $act['activity'] : (isset($act['type']) ? $act['type'] : '');
                if ($actType) $actTypes[] = $actType;
            }
            if (count($actTypes) > 0) {
                $parts[] = "Activities: " . implode(', ', array_unique($actTypes));
            }
        }

        $tags = [self::API_ID, 'ip', 'reputation'];
        if ($score >= 70) $tags[] = 'malicious';
        elseif ($score >= 40) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['Accept' => 'application/json'];
        if ($apiKey) {
            $headers['X-OTX-API-KEY'] = $apiKey;
        }
        $resp = HttpClient::get('https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/reputation', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
