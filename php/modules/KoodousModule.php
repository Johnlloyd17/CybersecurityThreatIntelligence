<?php
// =============================================================================
//  CTI — Koodous Module (Android Malware Analysis)
//  Queries Koodous API for APK hash analysis.
//  Supports: hash
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class KoodousModule extends BaseApiModule
{
    private const API_ID   = 'koodous';
    private const API_NAME = 'Koodous';
    private const SUPPORTED = ['hash'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $hash = trim($queryValue);
        $url = "https://api.koodous.com/apks/{$hash}";

        $headers = [];
        if (!empty($apiKey)) {
            $headers['Authorization'] = "Token {$apiKey}";
        }

        $r = HttpClient::get($url, $headers, 15);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
        }

        if ($r['status'] === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $hash, $ms);
        }

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        if ($r['status'] !== 200 || !$r['json']) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$r['status']}", $ms);
        }

        $data = $r['json'];
        $appName = isset($data['app']) ? $data['app'] : 'Unknown';
        $packageName = isset($data['package_name']) ? $data['package_name'] : 'Unknown';
        $size = isset($data['size']) ? $data['size'] : 0;
        $detected = isset($data['detected']) ? $data['detected'] : false;
        $rating = isset($data['rating']) ? (int)$data['rating'] : 0;
        $analyzedAt = isset($data['analyzed']) ? $data['analyzed'] : null;
        $sha256 = isset($data['sha256']) ? $data['sha256'] : $hash;

        $parts = ["Hash {$hash}: Found in Koodous"];
        $parts[] = "App: {$appName} ({$packageName})";
        if ($size > 0) {
            $sizeMb = round($size / 1048576, 2);
            $parts[] = "Size: {$sizeMb} MB";
        }
        $detectedStr = $detected ? 'YES' : 'No';
        $parts[] = "Detected as malware: {$detectedStr}";
        $parts[] = "Rating: {$rating}";

        $score = 0;
        if ($detected) {
            $score = 80;
        } elseif ($rating < 0) {
            $score = 50;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 80;
        $tags = [self::API_ID, 'hash', 'android', 'malware'];
        if ($detected) {
            $tags[] = 'malicious';
        } else {
            $tags[] = 'clean';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'app' => $appName,
                'package_name' => $packageName,
                'sha256' => $sha256,
                'size' => $size,
                'detected' => $detected,
                'rating' => $rating,
                'analyzed' => $analyzedAt,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://api.koodous.com/apks?search=whatsapp&page_size=1', [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
