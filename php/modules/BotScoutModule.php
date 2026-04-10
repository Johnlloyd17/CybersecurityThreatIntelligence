<?php
// =============================================================================
//  CTI — BotScout Module
//  Free-tier bot detection service.
//  Supports: ip, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class BotScoutModule extends BaseApiModule
{
    private const API_ID   = 'botscout';
    private const API_NAME = 'BotScout';
    private const SUPPORTED = ['ip', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $value = urlencode($queryValue);

        $param = $queryType === 'ip' ? 'ip' : 'mail';
        $url = "https://botscout.com/test/?{$param}={$value}";

        if (!empty($apiKey)) {
            $url .= "&key={$apiKey}";
        }

        $r = HttpClient::get($url, [], 15);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
        }

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        $body = trim($r['body']);

        // BotScout returns format: Y|IP|COUNT or N|IP|0
        $isBot = false;
        $botCount = 0;

        if (preg_match('/^(Y|N)\|[^|]*\|(\d+)/i', $body, $m)) {
            $isBot = strtoupper($m[1]) === 'Y';
            $botCount = (int)$m[2];
        } else {
            // Try to parse as HTML result
            if (stripos($body, 'appears') !== false && stripos($body, 'time') !== false) {
                if (preg_match('/(\d+)\s*time/i', $body, $m2)) {
                    $botCount = (int)$m2[1];
                    $isBot = $botCount > 0;
                }
            } elseif ($r['status'] !== 200) {
                return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$r['status']}", $ms);
            }
        }

        $parts = ["{$queryType} '{$queryValue}'"];

        if ($isBot) {
            $parts[] = "Flagged as bot/spam ({$botCount} appearance(s))";
            $score = min(85, 40 + $botCount * 5);
        } else {
            $parts[] = "Not flagged as bot/spam";
            $score = 0;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 75;
        $tags = [self::API_ID, $queryType, 'bot_detection'];
        if ($isBot) {
            $tags[] = 'bot';
            $tags[] = 'spam';
        } else {
            $tags[] = 'clean';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'is_bot' => $isBot,
                'appearances' => $botCount,
                'raw_response' => substr($body, 0, 500),
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://botscout.com/test/?ip=127.0.0.1', [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
