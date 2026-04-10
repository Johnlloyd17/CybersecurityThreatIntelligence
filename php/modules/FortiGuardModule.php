<?php
// =============================================================================
//  CTI — FortiGuard Module (URL/IP Classification)
//  Queries FortiGuard web filter for category classification.
//  Supports: ip, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class FortiGuardModule extends BaseApiModule
{
    private const API_ID   = 'fortiguard';
    private const API_NAME = 'FortiGuard';
    private const SUPPORTED = ['ip', 'domain'];

    /** Categories considered risky */
    private const RISKY_CATEGORIES = [
        'Malicious Websites', 'Phishing', 'Spam URLs', 'Newly Observed Domain',
        'Newly Registered Domain', 'Hacking', 'Proxy Avoidance',
        'Adult/Mature Content', 'Pornography', 'Gambling',
        'Command and Control', 'Botnet', 'Malware', 'Crypto Mining',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $value = urlencode($queryValue);
        $url = "https://www.fortiguard.com/webfilter?q={$value}";

        $r = HttpClient::get($url, [
            'Accept' => 'text/html',
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ], 15);

        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
        }

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        if ($r['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$r['status']}", $ms);
        }

        $body = $r['body'];

        // Try to extract category from the HTML
        $category = 'Unknown';
        if (preg_match('/Category:\s*([^<\n]+)/i', $body, $m)) {
            $category = trim(strip_tags($m[1]));
        } elseif (preg_match('/<h4[^>]*class=["\'][^"\']*cat[^"\']*["\'][^>]*>([^<]+)/i', $body, $m)) {
            $category = trim($m[1]);
        } elseif (preg_match('/<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
            $category = trim($m[1]);
        }

        $isRisky = false;
        foreach (self::RISKY_CATEGORIES as $rc) {
            if (stripos($category, $rc) !== false) {
                $isRisky = true;
                break;
            }
        }

        $parts = ["{$queryType} '{$queryValue}': FortiGuard classification"];
        $parts[] = "Category: {$category}";

        $score = 0;
        if ($isRisky) {
            $score = 65;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 70;
        $tags = [self::API_ID, $queryType, 'web_filter'];
        if ($isRisky) {
            $tags[] = 'risky_category';
        } else {
            $tags[] = 'clean';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'category' => $category,
                'is_risky' => $isRisky,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://www.fortiguard.com/webfilter?q=google.com', [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
