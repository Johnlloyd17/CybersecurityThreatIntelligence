<?php
// =============================================================================
//  CTI — Snov.io Module
//  API Docs: https://snov.io/api
//  Auth: client_id/client_secret (apiKey as id:secret). Supports: email, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SnovModule extends BaseApiModule
{
    private const API_ID   = 'snov';
    private const API_NAME = 'Snov.io';
    private const SUPPORTED = ['email', 'domain'];

    private function getAccessToken(string $apiKey): ?string
    {
        $creds = explode(':', $apiKey, 2);
        if (count($creds) < 2) return null;

        $resp = HttpClient::post('https://api.snov.io/v1/oauth/access_token', [], [
            'grant_type' => 'client_credentials',
            'client_id' => $creds[0],
            'client_secret' => $creds[1],
        ], 10);

        if ($resp['status'] === 200 && isset($resp['json']['access_token'])) {
            return $resp['json']['access_token'];
        }
        return null;
    }

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $token = $this->getAccessToken($apiKey);
        if (!$token) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, 0);
        }

        if ($queryType === 'domain') {
            $resp = HttpClient::post('https://api.snov.io/v1/get-domain-emails-count', [], [
                'access_token' => $token,
                'domain' => $queryValue,
            ], 20);
        } else {
            $resp = HttpClient::post('https://api.snov.io/v1/get-emails-verification-status', [], [
                'access_token' => $token,
                'emails' => [$queryValue],
            ], 20);
        }

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $score = 10;
        $severity = OsintResult::scoreToSeverity($score);

        if ($queryType === 'domain') {
            $emailCount = $data['result'] ?? 0;
            $summary = "Domain {$queryValue}: {$emailCount} email(s) found via Snov.io.";
        } else {
            $status = $data['status'] ?? 'unknown';
            $summary = "Email {$queryValue}: Verification status: {$status}.";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 70,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, $queryType, 'email_intel'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $token = $this->getAccessToken($apiKey);
        if (!$token) return ['status' => 'down', 'latency_ms' => 0, 'error' => 'Invalid API credentials'];
        return ['status' => 'healthy', 'latency_ms' => 0, 'error' => null];
    }
}
