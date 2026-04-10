<?php
// =============================================================================
//  CTI — GreyNoise OSINT Module Handler
//  php/modules/GreyNoiseModule.php
//
//  Queries the GreyNoise Community API v3 for IP classification data.
//  API Docs: https://docs.greynoise.io
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GreyNoiseModule extends BaseApiModule
{
    private const API_ID   = 'greynoise';
    private const API_NAME = 'GreyNoise';

    private const SUPPORTED_TYPES = ['ip'];

    // Classification-to-score mapping
    private const CLASSIFICATION_SCORES = [
        'malicious' => 85,
        'benign'    => 10,
        'unknown'   => 30,
    ];

    /**
     * Execute a threat intelligence query against GreyNoise.
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED_TYPES, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. GreyNoise only supports IP lookups.");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.greynoise.io/v3', '/');
        $headers = ['key' => $apiKey];

        $url = "{$baseUrl}/community/" . urlencode($queryValue);

        $response = HttpClient::get($url, $headers);

        // Handle error status codes
        if ($response['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $response['elapsed_ms']);
        }
        if ($response['status'] === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $response['elapsed_ms']);
        }
        if ($response['status'] === 0 || $response['error']) {
            return OsintResult::error(self::API_ID, self::API_NAME, $response['error'] ?? 'Connection failed', $response['elapsed_ms']);
        }
        if ($response['status'] < 200 || $response['status'] >= 300) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$response['status']}", $response['elapsed_ms']);
        }

        $json = $response['json'];
        if (!$json) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Unexpected response format', $response['elapsed_ms']);
        }

        return $this->parseResponse($json, $queryValue, $response['elapsed_ms']);
    }

    /**
     * Run a health check against the GreyNoise API.
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.greynoise.io/v3', '/');
        $headers = ['key' => $apiKey];

        // Query a known IP (Google DNS) as a health check
        $url = "{$baseUrl}/community/8.8.8.8";

        $response = HttpClient::get($url, $headers);

        if ($response['error'] || $response['status'] === 0) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => $response['error'] ?? 'Connection failed'];
        }
        if ($response['status'] === 401 || $response['status'] === 403) {
            return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => 'Invalid API key'];
        }
        if ($response['status'] >= 200 && $response['status'] < 300) {
            return ['status' => 'healthy', 'latency_ms' => $response['elapsed_ms'], 'error' => null];
        }

        return ['status' => 'down', 'latency_ms' => $response['elapsed_ms'], 'error' => "HTTP {$response['status']}"];
    }

    /**
     * Parse the GreyNoise Community API response and compute risk metrics.
     */
    private function parseResponse(array $data, string $queryValue, int $elapsedMs): OsintResult
    {
        $classification = strtolower($data['classification'] ?? 'unknown');
        $name           = $data['name'] ?? 'Unknown';
        $noise          = $data['noise'] ?? false;
        $riot           = $data['riot'] ?? false;
        $ip             = $data['ip'] ?? $queryValue;
        $link           = $data['link'] ?? null;
        $lastSeen       = $data['last_seen'] ?? null;
        $message        = $data['message'] ?? '';

        // Score based on classification
        $score = self::CLASSIFICATION_SCORES[$classification] ?? 30;

        // Adjust score based on additional signals
        if ($riot) {
            // RIOT = Rule It Out: IP belongs to common business services (benign)
            $score = max(0, $score - 20);
        }
        if ($noise && $classification !== 'benign') {
            // Noise = actively scanning the internet, slightly more suspicious
            $score = min(100, $score + 5);
        }

        $score = max(0, min(100, $score));

        $severity = OsintResult::scoreToSeverity($score);

        // Confidence depends on classification clarity
        $confidence = match ($classification) {
            'malicious' => 85,
            'benign'    => 80,
            'unknown'   => 40,
            default     => 30,
        };

        // Boost confidence if RIOT data confirms benign
        if ($riot && $classification === 'benign') {
            $confidence = 90;
        }

        // Build summary
        $summaryParts = ["IP {$ip}: classified as {$classification} by GreyNoise"];

        if ($name && $name !== 'Unknown' && $name !== 'unknown') {
            $summaryParts[] = "Identified as: {$name}";
        }

        if ($noise) {
            $summaryParts[] = "Observed scanning the internet (noise)";
        } else {
            $summaryParts[] = "Not observed in internet-wide scans";
        }

        if ($riot) {
            $summaryParts[] = "Listed in RIOT dataset (common business service)";
        }

        if ($lastSeen) {
            $summaryParts[] = "Last seen: {$lastSeen}";
        }

        $summary = implode('. ', $summaryParts) . '.';

        // Build tags from classification, name, noise, riot fields
        $tags = [self::API_ID, 'ip'];

        // Classification tag
        $tags[] = $classification;

        // Noise/RIOT tags
        if ($noise) {
            $tags[] = 'internet_scanner';
            $tags[] = 'noise';
        }

        if ($riot) {
            $tags[] = 'riot';
            $tags[] = 'business_service';
        }

        // Name-based tags
        if ($name && $name !== 'Unknown' && $name !== 'unknown') {
            $normalizedName = strtolower(preg_replace('/[^a-zA-Z0-9]/', '_', $name));
            $normalizedName = preg_replace('/_+/', '_', trim($normalizedName, '_'));
            if (strlen($normalizedName) <= 30) {
                $tags[] = $normalizedName;
            }
        }

        // Risk-level tag
        if ($classification === 'malicious') {
            $tags[] = 'malicious';
        } elseif ($classification === 'benign') {
            $tags[] = 'clean';
        } else {
            $tags[] = 'suspicious';
        }

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $elapsedMs,
            summary:    $summary,
            tags:       array_values(array_unique($tags)),
            rawData:    $data,
            success:    true
        );
    }
}
