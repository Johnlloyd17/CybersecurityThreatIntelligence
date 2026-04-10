<?php
// =============================================================================
//  CTI — WiGLE Module
//  API Docs: https://api.wigle.net/swagger
//  Auth: Basic auth from apiKey "name|token"
//  Endpoint: GET https://api.wigle.net/api/v2/network/search
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WigleModule extends BaseApiModule
{
    private const API_ID   = 'wigle';
    private const API_NAME = 'WiGLE';
    private const SUPPORTED = ['domain', 'keyword', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. WiGLE supports SSID/keyword lookups.");
        }

        // Parse apiKey: "name|token" format for Basic auth
        if (strpos($apiKey, '|') === false) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'API key must be in "name|token" format for Basic auth.');
        }

        $parts = explode('|', $apiKey, 2);
        $authHeader = 'Basic ' . base64_encode("{$parts[0]}:{$parts[1]}");

        $base = rtrim($baseUrl ?: 'https://api.wigle.net', '/');
        $url = "{$base}/api/v2/network/search?ssid=" . urlencode($queryValue) . "&resultsPerPage=25";
        $headers = ['Authorization' => $authHeader];

        $resp = HttpClient::get($url, $headers, 25);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $apiSuccess = $data['success'] ?? false;
        if (!$apiSuccess) {
            $message = $data['message'] ?? 'API returned failure';
            return OsintResult::error(self::API_ID, self::API_NAME, $message, $resp['elapsed_ms']);
        }

        $results = $data['results'] ?? [];
        $totalResults = $data['totalResults'] ?? count($results);
        $resultCount = count($results);

        if ($resultCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Analyze networks
        $encTypes = [];
        $channels = [];
        $locations = [];
        foreach ($results as $net) {
            $enc = $net['encryption'] ?? 'unknown';
            $encTypes[$enc] = ($encTypes[$enc] ?? 0) + 1;

            $ch = $net['channel'] ?? null;
            if ($ch !== null) $channels[$ch] = ($channels[$ch] ?? 0) + 1;

            $lat = $net['trilat'] ?? null;
            $lon = $net['trilong'] ?? null;
            if ($lat !== null && $lon !== null) {
                $locations[] = ['lat' => $lat, 'lon' => $lon, 'ssid' => $net['ssid'] ?? ''];
            }
        }

        // Score: wireless networks are informational
        $score = min(25, $totalResults);
        $openCount = $encTypes['none'] ?? ($encTypes['unknown'] ?? 0);
        if ($openCount > 0) $score += $openCount * 5;
        $score = min(60, $score);

        $encSummary = [];
        foreach ($encTypes as $enc => $cnt) {
            $encSummary[] = "{$enc}: {$cnt}";
        }

        $summary = "WiGLE: Found {$totalResults} wireless network(s) matching SSID \"{$queryValue}\". " .
                   "Encryption types: " . implode(', ', $encSummary) . ". " .
                   "Unique locations: " . count($locations) . ".";

        $tags = [self::API_ID, 'wireless', 'wifi', 'geolocation'];
        if ($openCount > 0) $tags[] = 'open_network';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(85, 50 + min(35, $resultCount * 2)),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: ['results' => $results, 'total' => $totalResults],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        if (strpos($apiKey, '|') === false) {
            return ['status' => 'down', 'latency_ms' => 0, 'error' => 'API key must be "name|token" format'];
        }

        $parts = explode('|', $apiKey, 2);
        $authHeader = 'Basic ' . base64_encode("{$parts[0]}:{$parts[1]}");
        $base = rtrim($baseUrl ?: 'https://api.wigle.net', '/');
        $url = "{$base}/api/v2/profile/user";
        $resp = HttpClient::get($url, ['Authorization' => $authHeader], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid credentials'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
