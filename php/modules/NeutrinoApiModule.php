<?php
// =============================================================================
//  CTI — NeutrinoAPI Module
//  Auth: user-id and api-key in POST. Supports: ip, email, phone
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class NeutrinoApiModule extends BaseApiModule
{
    private const API_ID   = 'neutrinoapi';
    private const API_NAME = 'NeutrinoAPI';
    private const SUPPORTED = ['ip', 'email', 'phone'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        // apiKey expected as "user-id:api-key"
        $creds = explode(':', $apiKey, 2);
        if (count($creds) < 2) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'API key must be user-id:api-key');
        }

        $userId = $creds[0];
        $apiKeyVal = $creds[1];

        if ($queryType === 'ip') {
            $endpoint = 'https://neutrinoapi.net/ip-info';
            $body = ['user-id' => $userId, 'api-key' => $apiKeyVal, 'ip' => $queryValue];
        } elseif ($queryType === 'email') {
            $endpoint = 'https://neutrinoapi.net/email-validate';
            $body = ['user-id' => $userId, 'api-key' => $apiKeyVal, 'email' => $queryValue];
        } else {
            $endpoint = 'https://neutrinoapi.net/phone-validate';
            $body = ['user-id' => $userId, 'api-key' => $apiKeyVal, 'number' => $queryValue];
        }

        $resp = HttpClient::post($endpoint, ['Content-Type' => 'application/x-www-form-urlencoded'], http_build_query($body), 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $score = 10;
        $tags = [self::API_ID, $queryType];

        if ($queryType === 'ip') {
            $country = $data['country'] ?? 'Unknown';
            $city = $data['city'] ?? '';
            $isProxy = $data['is-hosting'] ?? false;
            if ($isProxy) {
                $score = 40;
                $tags[] = 'hosting';
            }
            $parts = ["IP {$queryValue}: Country: {$country}"];
            if ($city) $parts[] = "City: {$city}";
            $summary = implode('. ', $parts) . '.';
        } elseif ($queryType === 'email') {
            $valid = $data['valid'] ?? false;
            $isDisposable = $data['is-disposable'] ?? false;
            if ($isDisposable) {
                $score = 45;
                $tags[] = 'disposable';
            }
            $validStr = $valid ? 'yes' : 'no';
            $summary = "Email {$queryValue}: Valid: {$validStr}. Disposable: " . ($isDisposable ? 'yes' : 'no') . '.';
        } else {
            $valid = $data['valid'] ?? false;
            $intNumber = $data['international-number'] ?? $queryValue;
            $country = $data['country'] ?? 'Unknown';
            $validStr = $valid ? 'yes' : 'no';
            $summary = "Phone {$intNumber}: Valid: {$validStr}. Country: {$country}.";
        }

        $severity = OsintResult::scoreToSeverity($score);

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $creds = explode(':', $apiKey, 2);
        if (count($creds) < 2) return ['status' => 'down', 'latency_ms' => 0, 'error' => 'Invalid API key format'];
        $body = http_build_query(['user-id' => $creds[0], 'api-key' => $creds[1], 'ip' => '8.8.8.8']);
        $resp = HttpClient::post('https://neutrinoapi.net/ip-info', ['Content-Type' => 'application/x-www-form-urlencoded'], $body, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
