<?php
// =============================================================================
//  CTI — Clearbit Module
//  API Docs: https://clearbit.com/docs
//  Auth: Authorization: Bearer {key}. Supports: email, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ClearbitModule extends BaseApiModule
{
    private const API_ID   = 'clearbit';
    private const API_NAME = 'Clearbit';
    private const SUPPORTED = ['email', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        if ($queryType === 'email') {
            $url = 'https://person.clearbit.com/v2/people/find?' . http_build_query(['email' => $queryValue]);
        } else {
            $url = 'https://company.clearbit.com/v2/companies/find?' . http_build_query(['domain' => $queryValue]);
        }

        $resp = HttpClient::get($url, ['Authorization' => 'Bearer ' . $apiKey], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404 || $resp['status'] === 422) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $score = 15;
        $severity = OsintResult::scoreToSeverity($score);

        if ($queryType === 'email') {
            $name = $data['fullName'] ?? 'Unknown';
            $company = isset($data['employment']) ? ($data['employment']['name'] ?? '') : '';
            $parts = ["Email {$queryValue}: Name: {$name}"];
            if ($company) $parts[] = "Company: {$company}";
        } else {
            $compName = $data['name'] ?? 'Unknown';
            $sector = $data['category']['sector'] ?? '';
            $employees = $data['metrics']['employees'] ?? '';
            $parts = ["Domain {$queryValue}: Company: {$compName}"];
            if ($sector) $parts[] = "Sector: {$sector}";
            if ($employees) $parts[] = "Employees: {$employees}";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, $queryType, 'enrichment'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://company.clearbit.com/v2/companies/find?domain=clearbit.com', ['Authorization' => 'Bearer ' . $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
