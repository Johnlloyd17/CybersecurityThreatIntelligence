<?php
// =============================================================================
//  CTI — EmailRep Module
//  API Docs: https://emailrep.io/docs/
//  Auth: Key header (optional for limited queries). Supports: email
//  Endpoint: https://emailrep.io/{email}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class EmailRepModule extends BaseApiModule
{
    private const API_ID   = 'emailrep';
    private const API_NAME = 'EmailRep';
    private const SUPPORTED = ['email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'email') return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");

        $url = 'https://emailrep.io/' . urlencode($queryValue);
        $headers = ['User-Agent' => 'CTI-Platform/1.0'];
        if ($apiKey) $headers['Key'] = $apiKey;

        $resp = HttpClient::get($url, $headers, 15);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $reputation   = $data['reputation'] ?? 'none';
        $suspicious   = (bool)($data['suspicious'] ?? false);
        $malicious    = (bool)($data['details']['malicious_activity'] ?? false);
        $breached     = (bool)($data['details']['credentials_leaked'] ?? false);
        $dataBreached = (bool)($data['details']['data_breach'] ?? false);
        $profiles     = $data['details']['profiles'] ?? [];
        $domain       = $data['details']['domain_reputation'] ?? 'n/a';
        $firstSeen    = $data['details']['first_seen'] ?? '';
        $lastSeen     = $data['details']['last_seen'] ?? '';
        $daysSince    = $data['details']['days_since_domain_creation'] ?? null;

        $repMap = ['high' => 0, 'medium' => 20, 'low' => 50, 'none' => 30];
        $score = $repMap[$reputation] ?? 30;
        if ($malicious) $score = max($score, 80);
        if ($suspicious) $score = max($score, 60);
        if ($breached) $score = max($score, 45);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 65 + ($malicious ? 25 : 0) + ($suspicious ? 15 : 0));

        $parts = ["Email {$queryValue}: Reputation: {$reputation}"];
        if ($malicious) $parts[] = "Malicious activity detected";
        if ($suspicious) $parts[] = "Suspicious";
        if ($breached) $parts[] = "Credentials leaked in breaches";
        if (!empty($profiles)) $parts[] = "Profiles: " . implode(', ', array_slice($profiles, 0, 5));
        if ($firstSeen) $parts[] = "First seen: {$firstSeen}";
        $parts[] = "Domain reputation: {$domain}";

        $tags = [self::API_ID, 'email'];
        if ($malicious) $tags[] = 'malicious';
        elseif ($suspicious) $tags[] = 'suspicious';
        else $tags[] = $reputation === 'high' ? 'clean' : 'low_reputation';
        if ($breached) $tags[] = 'breached';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['User-Agent' => 'CTI-Platform/1.0'];
        if ($apiKey) $headers['Key'] = $apiKey;
        $resp = HttpClient::get('https://emailrep.io/test@google.com', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
