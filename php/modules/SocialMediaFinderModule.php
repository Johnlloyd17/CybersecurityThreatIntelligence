<?php
// =============================================================================
//  CTI — Social Media Finder Module
//  Enhanced social media lookup with API key. Supports: username, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/../GlobalSettings.php';
require_once __DIR__ . '/BaseApiModule.php';

class SocialMediaFinderModule extends BaseApiModule
{
    private const API_ID   = 'social-media-finder';
    private const API_NAME = 'Social Media Finder';
    private const SUPPORTED = ['username', 'email'];

    private const PLATFORMS = [
        'twitter'   => 'https://twitter.com/%s',
        'github'    => 'https://github.com/%s',
        'instagram' => 'https://www.instagram.com/%s/',
        'linkedin'  => 'https://www.linkedin.com/in/%s/',
        'reddit'    => 'https://www.reddit.com/user/%s',
        'pinterest' => 'https://www.pinterest.com/%s/',
        'medium'    => 'https://medium.com/@%s',
        'tiktok'    => 'https://www.tiktok.com/@%s',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $username = $queryValue;
        if ($queryType === 'email') {
            $atPos = strpos($queryValue, '@');
            if ($atPos !== false) {
                $username = substr($queryValue, 0, $atPos);
            }
        }
        $isGeneric = GlobalSettings::isGenericUsername($username);

        $found = [];
        $checked = 0;

        foreach (self::PLATFORMS as $platform => $urlTpl) {
            $url = sprintf($urlTpl, urlencode($username));
            $resp = HttpClient::get($url, ['Authorization' => 'Bearer ' . $apiKey], 8, 0);
            $checked++;

            if ($resp['status'] === 200) {
                $found[] = ['platform' => $platform, 'url' => $url];
            }
        }

        $elapsed = 0; // aggregate

        if (empty($found)) {
            return new OsintResult(
                api: self::API_ID,
                apiName: self::API_NAME,
                score: 0,
                severity: 'info',
                confidence: $isGeneric ? 35 : 90,
                responseMs: $elapsed,
                summary: self::API_NAME . ": No records found for {$queryValue}."
                    . ($isGeneric ? ' Username is generic; confidence reduced.' : ''),
                tags: array_values(array_unique(array_filter([
                    self::API_ID,
                    'clean',
                    'not_found',
                    $isGeneric ? 'generic_username' : null,
                ]))),
                rawData: null,
                success: true
            );
        }

        $count = count($found);
        $score = $isGeneric ? min(10, $count * 2) : min(30, $count * 5);
        $severity = OsintResult::scoreToSeverity($score);

        $platformNames = array_map(fn($f) => $f['platform'], $found);
        $summary = "{$queryValue}: Found on {$count}/{$checked} platforms: " . implode(', ', $platformNames) . '.';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $isGeneric ? 45 : 65,
            responseMs: $elapsed, summary: $summary,
            tags: array_values(array_unique(array_filter([
                self::API_ID,
                $queryType,
                'social_media',
                $isGeneric ? 'generic_username' : null,
            ]))),
            rawData: $found,
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://twitter.com/', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
    }
}
