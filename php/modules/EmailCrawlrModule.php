<?php
// =============================================================================
//  CTI — EmailCrawlr Module
//  API Docs: https://emailcrawlr.com/docs
//  Auth: x-api-key header. Supports: email, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class EmailCrawlrModule extends BaseApiModule
{
    private const API_ID   = 'emailcrawlr';
    private const API_NAME = 'EmailCrawlr';
    private const SUPPORTED = ['email', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        if ($queryType === 'email') {
            $url = 'https://api.emailcrawlr.com/v2/email-info?' . http_build_query(['email' => $queryValue]);
        } else {
            $url = 'https://api.emailcrawlr.com/v2/domain-info?' . http_build_query(['domain' => $queryValue]);
        }

        $resp = HttpClient::get($url, ['x-api-key' => $apiKey], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $score = 10;
        $severity = OsintResult::scoreToSeverity($score);

        if ($queryType === 'email') {
            $valid = isset($data['valid']) ? ($data['valid'] ? 'yes' : 'no') : 'unknown';
            $summary = "Email {$queryValue}: Valid: {$valid}.";
        } else {
            $emails = $data['emails'] ?? [];
            $count = count($emails);
            $preview = implode(', ', array_slice(array_map(fn($e) => $e['email'] ?? '', $emails), 0, 5));
            $summary = "Domain {$queryValue}: {$count} emails found. Preview: {$preview}.";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 75,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: [self::API_ID, $queryType, 'email_intel'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.emailcrawlr.com/v2/domain-info?domain=example.com', ['x-api-key' => $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
