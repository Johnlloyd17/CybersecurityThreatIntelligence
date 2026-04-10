<?php
// =============================================================================
//  CTI — MaxMind GeoIP2 Module
//  Queries MaxMind GeoIP2 Insights/City API for IP geolocation & risk data.
//  API Docs: https://dev.maxmind.com/geoip/docs/web-services
//  Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class MaxMindModule extends BaseApiModule
{
    private const API_ID   = 'maxmind';
    private const API_NAME = 'MaxMind GeoIP2';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://geoip.maxmind.com', '/');

        // API key format: "account_id:license_key"
        $parts = explode(':', $apiKey, 2);
        $accountId  = $parts[0] ?? '';
        $licenseKey = $parts[1] ?? $apiKey;

        $headers = [
            'Authorization' => 'Basic ' . base64_encode("{$accountId}:{$licenseKey}"),
        ];

        $url = "{$baseUrl}/geoip/v2.1/insights/" . urlencode($queryValue);
        $resp = HttpClient::get($url, $headers);

        // Fallback to city endpoint if insights returns 403
        if ($resp['status'] === 403) {
            $url = "{$baseUrl}/geoip/v2.1/city/" . urlencode($queryValue);
            $resp = HttpClient::get($url, $headers);
        }

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json = $resp['json'];
        if (!$json) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Empty response', $resp['elapsed_ms']);
        }

        $country   = $json['country']['names']['en'] ?? 'Unknown';
        $city      = $json['city']['names']['en'] ?? '';
        $region    = $json['subdivisions'][0]['names']['en'] ?? '';
        $lat       = $json['location']['latitude'] ?? null;
        $lon       = $json['location']['longitude'] ?? null;
        $accuracy  = $json['location']['accuracy_radius'] ?? null;
        $isp       = $json['traits']['isp'] ?? '';
        $org       = $json['traits']['organization'] ?? '';
        $asn       = $json['traits']['autonomous_system_number'] ?? '';
        $asnOrg    = $json['traits']['autonomous_system_organization'] ?? '';
        $userType  = $json['traits']['user_type'] ?? '';
        $isAnon    = $json['traits']['is_anonymous'] ?? false;
        $isAnonVpn = $json['traits']['is_anonymous_vpn'] ?? false;
        $isTor     = $json['traits']['is_tor_exit_node'] ?? false;
        $isProxy   = $json['traits']['is_anonymous_proxy'] ?? $json['traits']['is_public_proxy'] ?? false;
        $isHosting = $json['traits']['is_hosting_provider'] ?? false;
        $riskScore = $json['risk_score'] ?? $json['traits']['static_ip_score'] ?? 0;

        $score = (int)$riskScore;
        $tags = [self::API_ID, 'ip', 'geolocation'];
        if ($isTor) { $score = max($score, 70); $tags[] = 'tor'; }
        if ($isAnonVpn) { $score = max($score, 45); $tags[] = 'vpn'; }
        if ($isProxy) { $score = max($score, 55); $tags[] = 'proxy'; }
        if ($isHosting) { $tags[] = 'hosting'; }
        if ($isAnon) { $tags[] = 'anonymous'; }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 90;

        $location = implode(', ', array_filter([$city, $region, $country]));
        $summary  = "IP {$queryValue}: {$location}.";
        if ($isp) $summary .= " ISP: {$isp}.";
        if ($asn) $summary .= " AS{$asn}" . ($asnOrg ? " ({$asnOrg})" : '') . '.';
        if ($riskScore > 0) $summary .= " Risk score: {$riskScore}.";
        if ($isTor) $summary .= ' Tor exit node.';
        if ($isAnonVpn) $summary .= ' Anonymous VPN.';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: [
                'ip'           => $queryValue,
                'country'      => $country,
                'city'         => $city,
                'region'       => $region,
                'latitude'     => $lat,
                'longitude'    => $lon,
                'accuracy_km'  => $accuracy,
                'isp'          => $isp,
                'org'          => $org,
                'asn'          => $asn,
                'asn_org'      => $asnOrg,
                'user_type'    => $userType,
                'is_anonymous' => $isAnon,
                'is_vpn'       => $isAnonVpn,
                'is_tor'       => $isTor,
                'is_proxy'     => $isProxy,
                'is_hosting'   => $isHosting,
                'risk_score'   => $riskScore,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://geoip.maxmind.com', '/');
        $parts = explode(':', $apiKey, 2);
        $headers = ['Authorization' => 'Basic ' . base64_encode("{$parts[0]}:" . ($parts[1] ?? $apiKey))];
        $resp = HttpClient::get("{$baseUrl}/geoip/v2.1/city/8.8.8.8", $headers);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
