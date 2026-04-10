<?php
// =============================================================================
//  CTI — Google Safe Browsing Module
//  API Docs: https://developers.google.com/safe-browsing/v4/lookup-api
//  Auth: key param. Supports: url, domain
//  POST to: https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GoogleSafeBrowsingModule extends BaseApiModule
{
    private const API_ID   = 'google-safebrowsing';
    private const API_NAME = 'Google Safe Browsing';
    private const SUPPORTED = ['url', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $lookupUrl = $queryType === 'domain' ? "http://{$queryValue}/" : $queryValue;

        $endpoint = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . urlencode($apiKey);

        $body = json_encode([
            'client' => ['clientId' => 'cti-platform', 'clientVersion' => '1.0.0'],
            'threatInfo' => [
                'threatTypes'      => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes'    => ['ANY_PLATFORM'],
                'threatEntryTypes' => ['URL'],
                'threatEntries'    => [['url' => $lookupUrl]],
            ],
        ]);

        $resp = HttpClient::post($endpoint, ['Content-Type' => 'application/json'], $body, 15);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if ($data === null) $data = []; // Empty response = no threats

        $matches = $data['matches'] ?? [];

        if (empty($matches)) {
            $label = $queryType === 'domain' ? "Domain {$queryValue}" : "URL {$queryValue}";
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 99,
                responseMs: $resp['elapsed_ms'],
                summary: "{$label}: No threats detected by Google Safe Browsing.",
                tags: [self::API_ID, $queryType, 'clean', 'safe'],
                rawData: $data, success: true
            );
        }

        // Threats found
        $threatTypes = [];
        foreach ($matches as $m) {
            $tt = $m['threatType'] ?? '';
            if ($tt) $threatTypes[$tt] = true;
        }

        $score = 90;
        $label = $queryType === 'domain' ? "Domain {$queryValue}" : "URL {$queryValue}";
        $summary = "{$label}: UNSAFE — Google Safe Browsing detected: " . implode(', ', array_keys($threatTypes)) . ".";

        $tags = [self::API_ID, $queryType, 'malicious'];
        foreach (array_keys($threatTypes) as $tt) $tags[] = strtolower(str_replace('_', ' ', $tt));

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: 'critical', confidence: 99,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $body = json_encode(['client' => ['clientId' => 'cti-platform', 'clientVersion' => '1.0.0'], 'threatInfo' => ['threatTypes' => ['MALWARE'], 'platformTypes' => ['ANY_PLATFORM'], 'threatEntryTypes' => ['URL'], 'threatEntries' => [['url' => 'http://google.com/']]]]);
        $resp = HttpClient::post('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . urlencode($apiKey), ['Content-Type' => 'application/json'], $body, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
