<?php
// =============================================================================
//  CTI — URLSCAN.IO MODULE HANDLER
//  php/modules/UrlScanModule.php
//
//  Searches urlscan.io for existing scan results on domains and URLs.
//  API Docs: https://urlscan.io/docs/api/
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class UrlScanModule extends BaseApiModule
{
    private const API_ID   = 'urlscan';
    private const API_NAME = 'urlscan.io';

    /**
     * Execute a query against urlscan.io search API.
     *
     * @param  string $queryType  "url" or "domain"
     * @param  string $queryValue The URL or domain to look up
     * @param  string $apiKey     API key for urlscan.io
     * @param  string $baseUrl    Base URL (default: https://urlscan.io/api/v1)
     * @return OsintResult
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (trim($apiKey) === '') {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, 0);
        }

        $headers = ['API-Key' => $apiKey];
        // urlscan.io search can be noticeably slower than lighter JSON APIs.
        // Use the module-aware timeout floor so a very low global timeout does
        // not make the fallback path fail almost immediately.
        $timeout = max(15, $this->timeoutSeconds());

        // Build search query based on type
        switch ($queryType) {
            case 'domain':
                $searchQuery = 'domain:' . urlencode($queryValue);
                break;
            case 'url':
                $searchQuery = 'page.url:' . urlencode($queryValue);
                break;
            default:
                return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $url = rtrim($baseUrl, '/') . '/search/?q=' . $searchQuery . '&size=1';
        $response = HttpClient::get($url, $headers, $timeout);

        // Handle HTTP-level errors
        if ($response['status'] === 0) {
            return OsintResult::error(self::API_ID, self::API_NAME, $response['error'] ?? 'Connection failed', $response['elapsed_ms']);
        }
        if ($response['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $response['elapsed_ms']);
        }
        if ($response['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$response['status']}", $response['elapsed_ms']);
        }

        $data = $response['json'];
        if ($data === null) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $response['elapsed_ms']);
        }

        $results = $data['results'] ?? [];

        // No scan results found
        if (empty($results)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $response['elapsed_ms']);
        }

        // Use the most recent scan result
        $latest = $results[0];
        $task      = $latest['task'] ?? [];
        $page      = $latest['page'] ?? [];
        $verdicts  = $latest['verdicts'] ?? [];
        $overallVerdict = $verdicts['overall'] ?? [];

        $isMalicious = $overallVerdict['malicious'] ?? false;
        $score = $isMalicious ? 85 : 5;
        $severity = OsintResult::scoreToSeverity($score);

        // Build tags
        $tags = [self::API_ID];
        if ($isMalicious) {
            $tags[] = 'malicious';
        } else {
            $tags[] = 'clean';
        }
        $categories = $overallVerdict['categories'] ?? [];
        foreach (array_slice($categories, 0, 5) as $cat) {
            $tags[] = $cat;
        }

        // Build summary
        $scanDate = $task['time'] ?? 'unknown date';
        $pageUrl  = $page['url'] ?? $queryValue;
        $country  = $page['country'] ?? 'unknown';
        $server   = $page['server'] ?? 'unknown';

        if ($isMalicious) {
            $summary = "urlscan.io flagged {$queryValue} as MALICIOUS. Last scanned: {$scanDate}. Country: {$country}, Server: {$server}.";
        } else {
            $summary = "urlscan.io shows {$queryValue} as clean. Last scanned: {$scanDate}. Country: {$country}, Server: {$server}.";
        }

        $confidence = $isMalicious ? 75 : 60;

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $response['elapsed_ms'],
            summary:    $summary,
            tags:       $tags,
            rawData:    $latest,
            success:    true,
            error:      null
        );
    }

    /**
     * Health check: search for google.com which should always return results.
     *
     * @param  string $apiKey
     * @param  string $baseUrl
     * @return array  ['status'=>'healthy'|'down', 'latency_ms'=>int, 'error'=>?string]
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        if (trim($apiKey) === '') {
            return [
                'status' => 'down',
                'latency_ms' => 0,
                'error' => 'Missing API key',
            ];
        }

        $headers = ['API-Key' => $apiKey];
        $url = rtrim($baseUrl, '/') . '/search/?q=domain:google.com&size=1';
        $response = HttpClient::get($url, $headers, max(15, $this->timeoutSeconds()));

        if ($response['status'] === 200 && !empty($response['json']['results'])) {
            return [
                'status'     => 'healthy',
                'latency_ms' => $response['elapsed_ms'],
                'error'      => null,
            ];
        }

        return [
            'status'     => 'down',
            'latency_ms' => $response['elapsed_ms'],
            'error'      => $response['error'] ?? "HTTP {$response['status']}",
        ];
    }
}
