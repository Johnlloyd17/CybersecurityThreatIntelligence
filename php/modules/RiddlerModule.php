<?php
// =============================================================================
//  CTI — Riddler.io Module
//  Auth: POST with email/password. Supports: domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class RiddlerModule extends BaseApiModule
{
    private const API_ID   = 'riddler';
    private const API_NAME = 'Riddler.io';
    private const SUPPORTED = ['domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        // apiKey expected as "email:password"
        $creds = explode(':', $apiKey, 2);
        if (count($creds) < 2) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'API key must be email:password');
        }

        // Authenticate first
        $authResp = HttpClient::post('https://riddler.io/auth/login', ['Content-Type' => 'application/json'], [
            'email' => $creds[0],
            'password' => $creds[1],
        ], 15);

        if ($authResp['status'] === 401 || $authResp['status'] === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $authResp['elapsed_ms']);
        }

        $authData = $authResp['json'];
        $token = '';
        if ($authData) {
            $token = $authData['response']['user']['authentication_token'] ?? '';
        }

        // Search/export
        $searchUrl = 'https://riddler.io/search/exportcsv';
        $resp = HttpClient::post($searchUrl, [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Authentication-Token' => $token,
        ], http_build_query(['q' => $queryValue]), 25);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $lines = array_filter(explode("\n", trim($resp['body'])));
        $count = max(0, count($lines) - 1); // subtract header

        if ($count === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $score = min(30, $count * 2);
        $severity = OsintResult::scoreToSeverity($score);
        $summary = "{$queryValue}: {$count} records found via Riddler.io.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 70,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, $queryType, 'recon'], rawData: ['record_count' => $count], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://riddler.io/', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
