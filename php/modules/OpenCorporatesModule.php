<?php
// =============================================================================
//  CTI — OpenCorporates Module
//  Queries the OpenCorporates free API for company registration data.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OpenCorporatesModule extends BaseApiModule
{
    private const API_ID   = 'opencorporates';
    private const API_NAME = 'OpenCorporates';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $domain = strtolower(trim($queryValue));

        // Use the domain name (without TLD) as search term
        $searchTerm = preg_replace('/\.(com|net|org|io|co|dev|app|xyz|info|biz)$/i', '', $domain);
        $searchTerm = str_replace(['-', '_', '.'], ' ', $searchTerm);
        $encoded = urlencode($searchTerm);

        $url = "https://api.opencorporates.com/v0.4/companies/search?q={$encoded}&per_page=10";

        if (!empty($apiKey)) {
            $url .= "&api_token={$apiKey}";
        }

        $r = HttpClient::get($url, ['Accept' => 'application/json'], 15);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
        }

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        if ($r['status'] !== 200 || !$r['json']) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$r['status']}", $ms);
        }

        $data = $r['json'];
        $results = isset($data['results']) ? $data['results'] : null;
        $companies = isset($results['companies']) ? $results['companies'] : [];
        $totalCount = isset($results['total_count']) ? (int)$results['total_count'] : 0;

        if (empty($companies)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $searchTerm, $ms);
        }

        $companyList = [];
        foreach ($companies as $item) {
            $c = isset($item['company']) ? $item['company'] : $item;
            $companyName = isset($c['name']) ? $c['name'] : 'Unknown';
            $jurisdiction = isset($c['jurisdiction_code']) ? $c['jurisdiction_code'] : 'unknown';
            $status = isset($c['current_status']) ? $c['current_status'] : 'unknown';
            $number = isset($c['company_number']) ? $c['company_number'] : '';
            $companyList[] = [
                'name' => $companyName,
                'jurisdiction' => $jurisdiction,
                'status' => $status,
                'number' => $number,
            ];
        }

        $showCount = count($companyList);
        $parts = ["Domain '{$domain}' (search: '{$searchTerm}'): {$totalCount} company record(s) found"];
        foreach (array_slice($companyList, 0, 5) as $c) {
            $parts[] = $c['name'] . " ({$c['jurisdiction']}, {$c['status']})";
        }
        if ($totalCount > 5) {
            $remaining = $totalCount - 5;
            $parts[] = "... and {$remaining} more";
        }

        $score      = 5;
        $severity   = 'info';
        $confidence = 60;
        $tags = [self::API_ID, 'domain', 'corporate', 'osint'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'total_count' => $totalCount,
                'companies' => $companyList,
                'search_term' => $searchTerm,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://api.opencorporates.com/v0.4/companies/search?q=google&per_page=1', [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
