<?php
// =============================================================================
//  CTI — ipapi.com Module
//  API Docs: https://ipapi.com/documentation
//  Auth: access_key param. Supports: ip
//  Endpoint: http://api.ipapi.com/{ip}?access_key={key}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class IpApiModule extends BaseApiModule
{
    private const API_ID   = 'ipapi';
    private const API_NAME = 'ipapi.com';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if ($queryType !== 'ip') return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");

        $url = 'http://api.ipapi.com/' . urlencode($queryValue) . '?access_key=' . urlencode($apiKey) . '&output=json';
        $resp = HttpClient::get($url, [], 15);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);
        if (isset($data['error'])) return OsintResult::error(self::API_ID, self::API_NAME, $data['error']['info'] ?? 'API error', $resp['elapsed_ms']);

        $country = $data['country_name'] ?? '';
        $city    = $data['city'] ?? '';
        $region  = $data['region_name'] ?? '';
        $lat     = $data['latitude'] ?? '';
        $lon     = $data['longitude'] ?? '';

        $parts = ["IP {$queryValue}"];
        if ($country) $parts[] = "Country: {$country}";
        if ($city) $parts[] = "City: {$city}, {$region}";
        if ($lat && $lon) $parts[] = "Coordinates: {$lat}, {$lon}";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 5, severity: 'info', confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'ip', 'geolocation', 'clean'],
            rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('http://api.ipapi.com/8.8.8.8?access_key=' . urlencode($apiKey), [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200 && !isset($resp['json']['error'])) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['json']['error']['info'] ?? "HTTP {$resp['status']}"];
    }
}
