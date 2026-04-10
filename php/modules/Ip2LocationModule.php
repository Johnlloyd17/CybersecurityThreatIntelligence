<?php
// =============================================================================
//  CTI — IP2Location Module
//  Queries IP2Location API for geolocation and proxy/VPN detection.
//  API Docs: https://www.ip2location.io/ip2location-documentation
//  Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class Ip2LocationModule extends BaseApiModule
{
    private const API_ID   = 'ip2location';
    private const API_NAME = 'IP2Location';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.ip2location.io', '/');
        $url = "{$baseUrl}/?key=" . urlencode($apiKey) . "&ip=" . urlencode($queryValue) . "&format=json";

        $resp = HttpClient::get($url, []);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json = $resp['json'];
        if (!$json || isset($json['error'])) {
            return OsintResult::error(self::API_ID, self::API_NAME, $json['error']['error_message'] ?? 'API error', $resp['elapsed_ms']);
        }

        $country  = $json['country_name'] ?? 'Unknown';
        $region   = $json['region_name'] ?? '';
        $city     = $json['city_name'] ?? '';
        $isp      = $json['isp'] ?? '';
        $domain   = $json['domain'] ?? '';
        $asn      = $json['asn'] ?? '';
        $as       = $json['as'] ?? '';
        $isProxy  = $json['is_proxy'] ?? false;
        $proxyType= $json['proxy_type'] ?? '';
        $usageType= $json['usage_type'] ?? '';

        $score = 5;
        $tags = [self::API_ID, 'ip', 'geolocation'];

        if ($isProxy) {
            $score = max($score, 55);
            $tags[] = 'proxy';
            if (stripos($proxyType, 'VPN') !== false) { $score = max($score, 45); $tags[] = 'vpn'; }
            if (stripos($proxyType, 'TOR') !== false) { $score = max($score, 70); $tags[] = 'tor'; }
            if (stripos($proxyType, 'DCH') !== false) { $score = max($score, 50); $tags[] = 'datacenter'; }
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 85;

        $location = implode(', ', array_filter([$city, $region, $country]));
        $summary  = "IP {$queryValue}: {$location}.";
        if ($isp) $summary .= " ISP: {$isp}.";
        if ($isProxy) $summary .= " Proxy detected ({$proxyType}).";
        if ($asn) $summary .= " ASN: {$asn}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: array_values(array_unique($tags)),
            rawData: [
                'ip'         => $queryValue,
                'country'    => $country,
                'region'     => $region,
                'city'       => $city,
                'isp'        => $isp,
                'domain'     => $domain,
                'asn'        => $asn,
                'as'         => $as,
                'is_proxy'   => $isProxy,
                'proxy_type' => $proxyType,
                'usage_type' => $usageType,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.ip2location.io', '/');
        $resp = HttpClient::get("{$baseUrl}/?key=" . urlencode($apiKey) . "&ip=8.8.8.8&format=json", []);
        return [
            'status'     => ($resp['status'] === 200 && !isset($resp['json']['error'])) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
