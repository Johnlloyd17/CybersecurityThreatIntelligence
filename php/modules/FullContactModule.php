<?php
// =============================================================================
//  CTI — FullContact Module
//  API Docs: https://docs.fullcontact.com/
//  Auth: Authorization: Bearer {key}. POST JSON. Supports: email, username
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class FullContactModule extends BaseApiModule
{
    private const API_ID   = 'fullcontact';
    private const API_NAME = 'FullContact';
    private const SUPPORTED = ['email', 'username'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $body = [];
        if ($queryType === 'email') {
            $body['email'] = $queryValue;
        } else {
            $body['twitter'] = $queryValue;
        }

        $resp = HttpClient::post(
            'https://api.fullcontact.com/v3/person.enrich',
            ['Authorization' => 'Bearer ' . $apiKey],
            $body,
            20
        );

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404 || $resp['status'] === 422) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $fullName = $data['fullName'] ?? 'Unknown';
        $org = $data['organization'] ?? '';
        $title = $data['title'] ?? '';
        $socials = $data['socialProfiles'] ?? [];

        $score = 15;
        $severity = OsintResult::scoreToSeverity($score);

        $parts = ["{$queryValue}: Name: {$fullName}"];
        if ($org) $parts[] = "Org: {$org}";
        if ($title) $parts[] = "Title: {$title}";
        if (!empty($socials)) {
            $socialNames = array_map(fn($s) => $s['typeName'] ?? '', $socials);
            $parts[] = "Socials: " . implode(', ', array_filter($socialNames));
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 75,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, $queryType, 'enrichment'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::post('https://api.fullcontact.com/v3/person.enrich', ['Authorization' => 'Bearer ' . $apiKey], ['email' => 'test@example.com'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200 || $resp['status'] === 404) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
