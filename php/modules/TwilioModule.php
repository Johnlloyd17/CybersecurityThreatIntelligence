<?php
// =============================================================================
//  CTI — Twilio Lookup Module
//  API Docs: https://www.twilio.com/docs/lookup/v2
//  Auth: Basic Auth (SID:Token). Supports: phone
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class TwilioModule extends BaseApiModule
{
    private const API_ID   = 'twilio';
    private const API_NAME = 'Twilio Lookup';
    private const SUPPORTED = ['phone'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://lookups.twilio.com/v2/PhoneNumbers/' . urlencode($queryValue);
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get($url, ['Authorization' => $authHeader], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $valid = $data['valid'] ?? false;
        $countryCode = $data['country_code'] ?? 'Unknown';
        $callerName = $data['caller_name'] ?? null;
        $carrier = $data['carrier'] ?? null;

        $score = $valid ? 5 : 25;
        $severity = OsintResult::scoreToSeverity($score);

        $validStr = $valid ? 'yes' : 'no';
        $parts = ["Phone {$queryValue}: Valid: {$validStr}. Country: {$countryCode}"];
        if ($callerName && isset($callerName['caller_name'])) {
            $name = $callerName['caller_name'];
            $parts[] = "Caller: {$name}";
        }
        if ($carrier && isset($carrier['name'])) {
            $carrierName = $carrier['name'];
            $parts[] = "Carrier: {$carrierName}";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 85,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'phone', 'lookup'], rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $authHeader = 'Basic ' . base64_encode($apiKey);
        $resp = HttpClient::get('https://lookups.twilio.com/v2/PhoneNumbers/+15108675310', ['Authorization' => $authHeader], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
