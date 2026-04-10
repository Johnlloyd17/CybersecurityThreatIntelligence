<?php
// =============================================================================
//  CTI — IPINFO.IO MODULE HANDLER
//  php/modules/IPInfoModule.php
//
//  IP geolocation and enrichment via ipinfo.io.
//  API Docs: https://ipinfo.io/developers
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class IPInfoModule extends BaseApiModule
{
    private const API_ID   = 'ipinfo';
    private const API_NAME = 'IPInfo';

    /**
     * Execute a query against ipinfo.io.
     *
     * @param  string $queryType  Must be "ip"
     * @param  string $queryValue The IP address to look up
     * @param  string $apiKey     API token for ipinfo.io
     * @param  string $baseUrl    Base URL (default: https://ipinfo.io)
     * @return OsintResult
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'ip') {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. IPInfo supports IP lookups only.");
        }

        $headers = ['Authorization' => "Bearer {$apiKey}"];
        $url = rtrim($baseUrl, '/') . '/' . urlencode($queryValue) . '?token=' . urlencode($apiKey);
        $response = HttpClient::get($url, $headers);

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

        // Check for bogon IPs
        $isBogon = $data['bogon'] ?? false;
        if ($isBogon) {
            return new OsintResult(
                api:        self::API_ID,
                apiName:    self::API_NAME,
                score:      0,
                severity:   'info',
                confidence: 95,
                responseMs: $response['elapsed_ms'],
                summary:    "IPInfo: {$queryValue} is a bogon (private/reserved) IP address.",
                tags:       [self::API_ID, 'bogon', 'private'],
                rawData:    $data,
                success:    true,
                error:      null
            );
        }

        // Extract fields
        $ip       = $data['ip'] ?? $queryValue;
        $hostname = $data['hostname'] ?? 'N/A';
        $city     = $data['city'] ?? 'Unknown';
        $region   = $data['region'] ?? 'Unknown';
        $country  = $data['country'] ?? 'Unknown';
        $org      = $data['org'] ?? 'Unknown';
        $timezone = $data['timezone'] ?? 'Unknown';
        $privacy  = $data['privacy'] ?? [];

        // Evaluate risk from privacy flags
        $isVpn   = $privacy['vpn'] ?? false;
        $isProxy = $privacy['proxy'] ?? false;
        $isTor   = $privacy['tor'] ?? false;
        $isRelay = $privacy['relay'] ?? false;

        $hasPrivacyConcern = $isVpn || $isProxy || $isTor;
        $score = $hasPrivacyConcern ? 50 : 5;
        $severity = OsintResult::scoreToSeverity($score);

        // Build tags
        $tags = [self::API_ID, 'geolocation'];
        if ($isVpn)   $tags[] = 'vpn';
        if ($isProxy) $tags[] = 'proxy';
        if ($isTor)   $tags[] = 'tor';
        if ($isRelay) $tags[] = 'relay';
        if (!$hasPrivacyConcern) $tags[] = 'clean';

        // Build summary
        $locationParts = array_filter([$city, $region, $country]);
        $location = implode(', ', $locationParts);
        $summary = "IPInfo: {$ip} located in {$location}. Org: {$org}.";

        $privacyFlags = [];
        if ($isVpn)   $privacyFlags[] = 'VPN';
        if ($isProxy) $privacyFlags[] = 'Proxy';
        if ($isTor)   $privacyFlags[] = 'Tor';
        if ($isRelay) $privacyFlags[] = 'Relay';

        if (!empty($privacyFlags)) {
            $summary .= ' Privacy flags: ' . implode(', ', $privacyFlags) . '.';
        }

        $confidence = $hasPrivacyConcern ? 70 : 80;

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $response['elapsed_ms'],
            summary:    $summary,
            tags:       $tags,
            rawData:    $data,
            success:    true,
            error:      null
        );
    }

    /**
     * Health check: look up 8.8.8.8 (Google DNS), which should always work.
     *
     * @param  string $apiKey
     * @param  string $baseUrl
     * @return array  ['status'=>'healthy'|'down', 'latency_ms'=>int, 'error'=>?string]
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['Authorization' => "Bearer {$apiKey}"];
        $url = rtrim($baseUrl, '/') . '/8.8.8.8?token=' . urlencode($apiKey);
        $response = HttpClient::get($url, $headers);

        if ($response['status'] === 200 && isset($response['json']['ip'])) {
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
