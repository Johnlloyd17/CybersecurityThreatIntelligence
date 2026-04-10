<?php
// =============================================================================
//  CTI — Google Maps Geocoding Module
//  API Docs: https://developers.google.com/maps/documentation/geocoding/
//  Auth: API key as query param
//  Endpoint: https://maps.googleapis.com/maps/api/geocode/json
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GoogleMapsModule extends BaseApiModule
{
    private const API_ID   = 'google-maps';
    private const API_NAME = 'Google Maps Geocoding';
    private const SUPPORTED = ['domain', 'ip', 'keyword', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $url = 'https://maps.googleapis.com/maps/api/geocode/json?address=' . urlencode($queryValue) .
               '&key=' . urlencode($apiKey);

        $resp = HttpClient::get($url, [], 15);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $status = $data['status'] ?? 'UNKNOWN';
        if ($status === 'ZERO_RESULTS') {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }
        if ($status === 'REQUEST_DENIED') {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        }
        if ($status === 'OVER_QUERY_LIMIT') {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        }
        if ($status !== 'OK') {
            return OsintResult::error(self::API_ID, self::API_NAME, "API status: {$status}", $resp['elapsed_ms']);
        }

        $results = $data['results'] ?? [];
        if (empty($results)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $first = $results[0];
        $formattedAddress = $first['formatted_address'] ?? 'Unknown';
        $geometry = $first['geometry'] ?? [];
        $location = $geometry['location'] ?? [];
        $lat = $location['lat'] ?? 0;
        $lng = $location['lng'] ?? 0;
        $locationType = $geometry['location_type'] ?? 'UNKNOWN';

        // Extract address components
        $components = $first['address_components'] ?? [];
        $country = '';
        $adminArea = '';
        $locality = '';
        foreach ($components as $comp) {
            $types = $comp['types'] ?? [];
            if (in_array('country', $types, true)) {
                $country = $comp['long_name'] ?? '';
            }
            if (in_array('administrative_area_level_1', $types, true)) {
                $adminArea = $comp['long_name'] ?? '';
            }
            if (in_array('locality', $types, true)) {
                $locality = $comp['long_name'] ?? '';
            }
        }

        $resultCount = count($results);
        // Geolocation is informational, low threat score
        $score = 5;

        $locationParts = array_filter([$locality, $adminArea, $country]);
        $locationStr = implode(', ', $locationParts);
        $summary = "Geocoded \"{$queryValue}\" to: {$formattedAddress}. " .
                   "Coordinates: {$lat}, {$lng} ({$locationType}). " .
                   "Location: {$locationStr}. {$resultCount} result(s) total.";

        $tags = [self::API_ID, 'geolocation', 'clean'];
        if ($country) $tags[] = 'country:' . strtolower(str_replace(' ', '_', $country));

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: $locationType === 'ROOFTOP' ? 95 : ($locationType === 'RANGE_INTERPOLATED' ? 80 : 60),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url = 'https://maps.googleapis.com/maps/api/geocode/json?address=1600+Amphitheatre+Parkway&key=' . urlencode($apiKey);
        $resp = HttpClient::get($url, [], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        $json = $resp['json'];
        $apiStatus = $json['status'] ?? 'UNKNOWN';
        if ($apiStatus === 'REQUEST_DENIED') return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($apiStatus === 'OK') return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "API status: {$apiStatus}"];
    }
}
