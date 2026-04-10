<?php
// =============================================================================
//  CTI — PhishTank Module
//  API Docs: https://phishtank.org/api_info.php
//  Free, no key needed for basic check. Supports: url
//  POST to: https://checkurl.phishtank.com/checkurl/
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PhishTankModule extends BaseApiModule
{
    private const API_ID   = 'phishtank';
    private const API_NAME = 'PhishTank';
    private const SUPPORTED = ['url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'https://checkurl.phishtank.com/checkurl/';

        // PhishTank expects form-encoded POST
        $postData = http_build_query([
            'url'              => $queryValue,
            'format'           => 'json',
            'app_key'          => $apiKey ?: '',
        ]);

        $resp = HttpClient::post($url, ['Content-Type' => 'application/x-www-form-urlencoded'], $postData, 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data || !isset($data['results'])) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Unexpected response', $resp['elapsed_ms']);
        }

        $results = $data['results'];
        $inDb    = (bool)($results['in_database'] ?? false);
        $isPhish = (bool)($results['valid'] ?? false); // "valid" means confirmed phish
        $phishId = $results['phish_id'] ?? '';
        $detail  = $results['phish_detail_page'] ?? '';
        $verified = (bool)($results['verified'] ?? false);
        $verifiedAt = $results['verified_at'] ?? '';

        if (!$inDb) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 85,
                responseMs: $resp['elapsed_ms'],
                summary: "URL {$queryValue} is NOT in the PhishTank database.",
                tags: [self::API_ID, 'url', 'clean'],
                rawData: $results, success: true
            );
        }

        if ($isPhish) {
            $score      = $verified ? 95 : 80;
            $confidence = $verified ? 99 : 80;
            $summary    = "URL {$queryValue} IS a confirmed phishing site in PhishTank (ID: {$phishId}).";
            if ($verified) $summary .= " Verified: {$verifiedAt}.";
            $tags = [self::API_ID, 'url', 'phishing', 'malicious'];
        } else {
            $score      = 40;
            $confidence = 60;
            $summary    = "URL {$queryValue} is in PhishTank database but NOT confirmed as phishing (ID: {$phishId}).";
            $tags       = [self::API_ID, 'url', 'suspicious'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score), confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $results, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        // Use a known safe URL to test
        $postData = http_build_query(['url' => 'https://google.com', 'format' => 'json', 'app_key' => $apiKey ?: '']);
        $resp = HttpClient::post('https://checkurl.phishtank.com/checkurl/', ['Content-Type' => 'application/x-www-form-urlencoded'], $postData, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
