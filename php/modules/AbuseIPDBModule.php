<?php
// =============================================================================
//  CTI — AbuseIPDB OSINT Module Handler
//  php/modules/AbuseIPDBModule.php
//
//  Queries the AbuseIPDB API v2 for IP address abuse reports.
//  API Docs: https://docs.abuseipdb.com
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../EventTypes.php';
require_once __DIR__ . '/BaseApiModule.php';

class AbuseIPDBModule extends BaseApiModule
{
    private const API_ID   = 'abuseipdb';
    private const API_NAME = 'AbuseIPDB';

    private const SUPPORTED_TYPES = ['ip'];

    /**
     * Execute a threat intelligence query against AbuseIPDB.
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED_TYPES, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. AbuseIPDB only supports IP lookups.");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.abuseipdb.com/api/v2', '/');
        $headers = [
            'Key'    => $apiKey,
            'Accept' => 'application/json',
        ];

        $url = "{$baseUrl}/check?" . http_build_query([
            'ipAddress'    => $queryValue,
            'maxAgeInDays' => 90,
            'verbose'      => '',
        ]);

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
        if (!$json || !isset($json['data'])) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Unexpected response format', $response['elapsed_ms']);
        }

        return $this->parseResponse($json['data'], $queryValue, $response['elapsed_ms']);
    }

    /**
     * Run a health check against the AbuseIPDB API.
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.abuseipdb.com/api/v2', '/');
        $headers = [
            'Key'    => $apiKey,
            'Accept' => 'application/json',
        ];

        $url = "{$baseUrl}/check?" . http_build_query([
            'ipAddress'    => '127.0.0.1',
            'maxAgeInDays' => 1,
        ]);

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
     * Parse the AbuseIPDB response and compute risk metrics.
     */
    private function parseResponse(array $data, string $queryValue, int $elapsedMs): OsintResult
    {
        $abuseScore    = (int) ($data['abuseConfidenceScore'] ?? 0);
        $totalReports  = (int) ($data['totalReports'] ?? 0);
        $countryCode   = $data['countryCode'] ?? 'Unknown';
        $isp           = $data['isp'] ?? 'Unknown ISP';
        $domain        = $data['domain'] ?? 'Unknown';
        $usageType     = $data['usageType'] ?? 'Unknown';
        $isWhitelisted = $data['isWhitelisted'] ?? false;
        $isPublic      = $data['isPublic'] ?? true;
        $numDistinct   = $data['numDistinctUsers'] ?? 0;
        $lastReported  = $data['lastReportedAt'] ?? null;

        // Score: use abuseConfidenceScore directly (already 0-100)
        $score = max(0, min(100, $abuseScore));

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = $totalReports > 0 ? min(99, 60 + min(39, $totalReports)) : 50;

        // Build summary
        $summary = "IP {$queryValue} (Country: {$countryCode}, ISP: {$isp}): " .
                   "Abuse confidence score {$abuseScore}%, {$totalReports} report(s)";

        if ($numDistinct > 0) {
            $summary .= " from {$numDistinct} distinct user(s)";
        }

        if ($lastReported) {
            $summary .= ". Last reported: {$lastReported}";
        } else {
            $summary .= ". No recent reports.";
        }

        // Build tags
        $tags = [self::API_ID, 'ip'];

        if ($abuseScore >= 70) {
            $tags[] = 'malicious';
        } elseif ($abuseScore >= 30) {
            $tags[] = 'suspicious';
        } else {
            $tags[] = 'clean';
        }

        if ($isWhitelisted) {
            $tags[] = 'whitelisted';
        }

        if ($totalReports > 10) {
            $tags[] = 'frequently_reported';
        }

        if ($usageType) {
            $normalizedType = strtolower(str_replace(' ', '_', $usageType));
            $tags[] = $normalizedType;
        }

        // Extract abuse categories from reports if available
        $reports = $data['reports'] ?? [];
        $categories = [];
        foreach ($reports as $report) {
            if (isset($report['categories']) && is_array($report['categories'])) {
                $categories = array_merge($categories, $report['categories']);
            }
        }
        $categories = array_unique($categories);

        $categoryMap = [
            3  => 'fraud',
            4  => 'ddos',
            5  => 'ftp_brute_force',
            10 => 'web_spam',
            11 => 'email_spam',
            14 => 'port_scan',
            15 => 'hacking',
            18 => 'brute_force',
            19 => 'bad_web_bot',
            20 => 'exploited_host',
            21 => 'web_attack',
            22 => 'ssh_brute_force',
            23 => 'iot_targeted',
        ];

        foreach ($categories as $catId) {
            if (isset($categoryMap[$catId])) {
                $tags[] = $categoryMap[$catId];
            }
        }

        $result = new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $elapsedMs,
            summary:    $summary,
            tags:       array_unique($tags),
            rawData:    $data,
            success:    true
        );

        // Discover the domain associated with this IP for enrichment
        if ($domain && $domain !== 'Unknown' && $domain !== '') {
            $result->addDiscovery(EventTypes::INTERNET_NAME, $domain);
        }

        return $result;
    }
}
