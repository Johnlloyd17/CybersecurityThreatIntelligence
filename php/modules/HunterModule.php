<?php
// =============================================================================
//  CTI — Hunter.io Module
//  API Docs: https://hunter.io/api-documentation/v2
//  Auth: api_key param. Supports: domain, email
//  Endpoint: https://api.hunter.io/v2/{action}?{params}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class HunterModule extends BaseApiModule
{
    private const API_ID   = 'hunter';
    private const API_NAME = 'Hunter.io';
    private const SUPPORTED = ['domain', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        if ($queryType === 'domain') {
            $url = 'https://api.hunter.io/v2/domain-search?' . http_build_query(['domain' => $queryValue, 'api_key' => $apiKey]);
        } else {
            $url = 'https://api.hunter.io/v2/email-verifier?' . http_build_query(['email' => $queryValue, 'api_key' => $apiKey]);
        }

        $resp = HttpClient::get($url, [], 15);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json = $resp['json'];
        if (!$json || !isset($json['data'])) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid response', $resp['elapsed_ms']);

        $data = $json['data'];

        if ($queryType === 'domain') {
            $emails = $data['emails'] ?? [];
            $org    = $data['organization'] ?? '';
            $total  = $data['total'] ?? count($emails);
            $pattern = $data['pattern'] ?? '';

            $parts = ["Domain {$queryValue}: {$total} email(s) found via Hunter.io"];
            if ($org) $parts[] = "Organization: {$org}";
            if ($pattern) $parts[] = "Pattern: {$pattern}";
            if (!empty($emails)) {
                $sample = array_map(fn($e) => $e['value'] ?? '', array_slice($emails, 0, 5));
                $parts[] = "Emails: " . implode(', ', array_filter($sample));
            }

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 5, severity: 'info', confidence: 85,
                responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
                tags: [self::API_ID, 'domain', 'email', 'osint', 'clean'],
                rawData: $data, success: true
            );
        }

        // email verification
        $status  = $data['status'] ?? 'unknown';
        $result  = $data['result'] ?? 'unknown';
        $score   = $data['score'] ?? 0;
        $disp    = match ($result) {
            'deliverable' => 0, 'risky' => 30, 'undeliverable' => 10,
            default => 5,
        };

        $parts = ["Email {$queryValue}: Status: {$status}, Result: {$result}, Score: {$score}"];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $disp, severity: OsintResult::scoreToSeverity($disp), confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'email', $result === 'risky' ? 'suspicious' : 'clean'],
            rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.hunter.io/v2/account?api_key=' . urlencode($apiKey), [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
