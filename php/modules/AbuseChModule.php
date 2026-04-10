<?php
// =============================================================================
//  CTI — ABUSE.CH MODULE HANDLER
//  php/modules/AbuseChModule.php
//
//  Queries abuse.ch MalwareBazaar and URLhaus for threat intelligence.
//  Requires a free Auth-Key from https://auth.abuse.ch/
//  API Docs: https://bazaar.abuse.ch/api/ and https://urlhaus-api.abuse.ch/v1/
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class AbuseChModule extends BaseApiModule
{
    private const API_ID   = 'abusech';
    private const API_NAME = 'abuse.ch';

    // Fixed endpoints — these do not use the $baseUrl parameter
    private const MALWARE_BAZAAR_URL = 'https://mb-api.abuse.ch/api/v1/';
    private const URLHAUS_URL_API    = 'https://urlhaus-api.abuse.ch/v1/url/';
    private const URLHAUS_HOST_API   = 'https://urlhaus-api.abuse.ch/v1/host/';

    /**
     * Execute a query against abuse.ch APIs.
     *
     * @param  string $queryType  "hash", "url", "domain", or "ip"
     * @param  string $queryValue The indicator to look up
     * @param  string $apiKey     Auth-Key from https://auth.abuse.ch/
     * @param  string $baseUrl    Not used for abuse.ch
     * @return OsintResult
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (empty($apiKey)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'API key (Auth-Key) is required. Register free at https://auth.abuse.ch/');
        }

        switch ($queryType) {
            case 'hash':
                return $this->queryHash($queryValue, $apiKey);
            case 'url':
                return $this->queryUrl($queryValue, $apiKey);
            case 'domain':
            case 'ip':
                return $this->queryHost($queryValue, $queryType, $apiKey);
            default:
                return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }
    }

    /**
     * Query MalwareBazaar for a hash (MD5, SHA1, or SHA256).
     */
    private function queryHash(string $hash, string $apiKey): OsintResult
    {
        $body = 'query=get_info&hash=' . urlencode($hash);
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Auth-Key'     => $apiKey,
        ];
        $response = HttpClient::post(self::MALWARE_BAZAAR_URL, $headers, $body);

        $errorResult = $this->checkHttpErrors($response, $hash);
        if ($errorResult !== null) {
            return $errorResult;
        }

        $data = $response['json'];
        if ($data === null) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $response['elapsed_ms']);
        }

        $queryStatus = $data['query_status'] ?? '';

        // "hash_not_found" or "no_results" means not in database
        if ($queryStatus === 'hash_not_found' || $queryStatus === 'no_results') {
            return new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      0,
                severity:   'info',
                confidence: 80,
                responseMs: $response['elapsed_ms'],
                summary:    "abuse.ch MalwareBazaar: Hash {$hash} not found in malware database.",
                tags:       [self::API_ID, 'malware_bazaar', 'clean'],
                rawData:    $data,
                success:    true,
                error:      null
            );
        }

        // Hash was found — this is malware
        $score = 75;
        $severity = OsintResult::scoreToSeverity($score);

        $sampleData = $data['data'][0] ?? [];
        $fileName     = $sampleData['file_name'] ?? 'unknown';
        $fileType     = $sampleData['file_type'] ?? 'unknown';
        $signature    = $sampleData['signature'] ?? 'unknown';
        $firstSeen    = $sampleData['first_seen'] ?? 'unknown';
        $deliveryMethod = $sampleData['delivery_method'] ?? '';

        $tags = [self::API_ID, 'malware_bazaar', 'malware'];
        if ($signature !== 'unknown' && $signature !== '' && $signature !== null) {
            $tags[] = $signature;
        }
        if ($fileType !== 'unknown' && $fileType !== '') {
            $tags[] = $fileType;
        }

        $summary = "abuse.ch MalwareBazaar: Hash found as malware. File: {$fileName} ({$fileType}). Signature: {$signature}. First seen: {$firstSeen}.";

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: 90,
            responseMs: $response['elapsed_ms'],
            summary:    $summary,
            tags:       $tags,
            rawData:    $data,
            success:    true,
            error:      null
        );
    }

    /**
     * Query URLhaus for a URL.
     */
    private function queryUrl(string $url, string $apiKey): OsintResult
    {
        $body = 'url=' . urlencode($url);
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Auth-Key'     => $apiKey,
        ];
        $response = HttpClient::post(self::URLHAUS_URL_API, $headers, $body);

        $errorResult = $this->checkHttpErrors($response, $url);
        if ($errorResult !== null) {
            return $errorResult;
        }

        $data = $response['json'];
        if ($data === null) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $response['elapsed_ms']);
        }

        $queryStatus = $data['query_status'] ?? '';

        if ($queryStatus === 'no_results') {
            return new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      0,
                severity:   'info',
                confidence: 80,
                responseMs: $response['elapsed_ms'],
                summary:    "abuse.ch URLhaus: URL not found in threat database.",
                tags:       [self::API_ID, 'urlhaus', 'clean'],
                rawData:    $data,
                success:    true,
                error:      null
            );
        }

        // URL was found in URLhaus
        $score = 75;
        $severity = OsintResult::scoreToSeverity($score);

        $threat     = $data['threat'] ?? 'unknown';
        $urlStatus  = $data['url_status'] ?? 'unknown';
        $dateAdded  = $data['date_added'] ?? 'unknown';
        $urlTags    = $data['tags'] ?? [];

        $tags = [self::API_ID, 'urlhaus', 'malicious'];
        if ($threat !== 'unknown' && $threat !== '') {
            $tags[] = $threat;
        }
        if (is_array($urlTags)) {
            foreach (array_slice($urlTags, 0, 3) as $t) {
                if (is_string($t) && $t !== '') {
                    $tags[] = $t;
                }
            }
        }

        $summary = "abuse.ch URLhaus: URL found in threat database. Threat: {$threat}. Status: {$urlStatus}. Added: {$dateAdded}.";

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: 85,
            responseMs: $response['elapsed_ms'],
            summary:    $summary,
            tags:       $tags,
            rawData:    $data,
            success:    true,
            error:      null
        );
    }

    /**
     * Query URLhaus for a host (domain or IP).
     */
    private function queryHost(string $host, string $queryType, string $apiKey): OsintResult
    {
        $body = 'host=' . urlencode($host);
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Auth-Key'     => $apiKey,
        ];
        $response = HttpClient::post(self::URLHAUS_HOST_API, $headers, $body);

        $errorResult = $this->checkHttpErrors($response, $host);
        if ($errorResult !== null) {
            return $errorResult;
        }

        $data = $response['json'];
        if ($data === null) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $response['elapsed_ms']);
        }

        $queryStatus = $data['query_status'] ?? '';

        if ($queryStatus === 'no_results') {
            return new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      0,
                severity:   'info',
                confidence: 80,
                responseMs: $response['elapsed_ms'],
                summary:    "abuse.ch URLhaus: Host {$host} not found in threat database.",
                tags:       [self::API_ID, 'urlhaus', 'clean'],
                rawData:    $data,
                success:    true,
                error:      null
            );
        }

        // Host found in URLhaus
        $score = 75;
        $severity = OsintResult::scoreToSeverity($score);

        $urlCount      = $data['url_count'] ?? 0;
        $urlsOnline    = $data['urls_online'] ?? 0;
        $blacklists    = $data['blacklists'] ?? [];
        $urls          = $data['urls'] ?? [];

        $tags = [self::API_ID, 'urlhaus', 'malicious', $queryType];

        // Include blacklist status in tags
        foreach ($blacklists as $blName => $blStatus) {
            if ($blStatus === 'listed') {
                $tags[] = "blacklisted_{$blName}";
            }
        }

        $summary = "abuse.ch URLhaus: Host {$host} found with {$urlCount} malicious URL(s) ({$urlsOnline} currently online).";

        // Add top threats from URLs
        $threats = [];
        foreach (array_slice($urls, 0, 5) as $urlEntry) {
            $t = $urlEntry['threat'] ?? '';
            if ($t !== '' && !in_array($t, $threats, true)) {
                $threats[] = $t;
            }
        }
        if (!empty($threats)) {
            $summary .= ' Threats: ' . implode(', ', $threats) . '.';
        }

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: 85,
            responseMs: $response['elapsed_ms'],
            summary:    $summary,
            tags:       $tags,
            rawData:    $data,
            success:    true,
            error:      null
        );
    }

    /**
     * Check for common HTTP error codes and return an appropriate OsintResult or null if OK.
     */
    private function checkHttpErrors(array $response, string $queryValue): ?OsintResult
    {
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
        return null;
    }

    /**
     * Health check: query URLhaus host API for google.com.
     *
     * @param  string $apiKey   Auth-Key from https://auth.abuse.ch/
     * @param  string $baseUrl  Not used
     * @return array  ['status'=>'healthy'|'down', 'latency_ms'=>int, 'error'=>?string]
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        if (empty($apiKey)) {
            return ['status' => 'down', 'latency_ms' => 0, 'error' => 'Auth-Key required. Register free at https://auth.abuse.ch/'];
        }

        $body = 'host=google.com';
        $headers = [
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Auth-Key'     => $apiKey,
        ];
        $response = HttpClient::post(self::URLHAUS_HOST_API, $headers, $body);

        if ($response['status'] === 200 && $response['json'] !== null) {
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
