<?php
// =============================================================================
//  CTI — CRXcavator Module (Chrome Extension Analysis)
//  Queries CRXcavator API for Chrome extension data.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CrxcavatorModule extends BaseApiModule
{
    private const API_ID   = 'crxcavator';
    private const API_NAME = 'CRXcavator';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $domain = urlencode(trim($queryValue));
        $url = "https://api.crxcavator.io/v1/search/{$domain}";

        $r = HttpClient::get($url, [
            'Accept' => 'application/json',
        ], 15);

        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
        }

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        if ($r['status'] === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $ms);
        }

        if ($r['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$r['status']}", $ms);
        }

        $data = $r['json'];
        if (!$data || empty($data)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $ms);
        }

        $extensions = is_array($data) ? $data : [];
        $extCount = count($extensions);

        $extList = [];
        $totalRisk = 0;
        foreach (array_slice($extensions, 0, 10) as $ext) {
            $extName = isset($ext['name']) ? $ext['name'] : 'Unknown';
            $extId = isset($ext['extension_id']) ? $ext['extension_id'] : '';
            $riskScore = isset($ext['risk_score']) ? (int)$ext['risk_score'] : 0;
            $totalRisk += $riskScore;
            $extList[] = [
                'name' => $extName,
                'id' => $extId,
                'risk_score' => $riskScore,
            ];
        }

        $parts = ["Domain {$queryValue}: {$extCount} Chrome extension(s) found"];
        foreach (array_slice($extList, 0, 5) as $e) {
            $parts[] = $e['name'] . " (risk: " . $e['risk_score'] . ")";
        }

        $avgRisk = $extCount > 0 ? (int)($totalRisk / min($extCount, 10)) : 0;
        $score = min(70, $avgRisk);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 65;
        $tags = [self::API_ID, 'domain', 'chrome_extension'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'extension_count' => $extCount,
                'extensions' => $extList,
                'avg_risk_score' => $avgRisk,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://api.crxcavator.io/v1/search/google.com', [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] >= 200 && $r['status'] < 500) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
