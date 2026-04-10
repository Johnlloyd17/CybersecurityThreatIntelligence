<?php
// =============================================================================
//  CTI — CleanTalk Spam Check Module
//  Free spam check service.
//  Supports: ip, email, domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CleanTalkModule extends BaseApiModule
{
    private const API_ID   = 'cleantalk';
    private const API_NAME = 'CleanTalk';
    private const SUPPORTED = ['ip', 'email', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $value = urlencode($queryValue);

        // Build URL based on query type
        $authKey = !empty($apiKey) ? $apiKey : '';
        if ($queryType === 'email') {
            $url = "https://api.cleantalk.org/?method_name=spam_check&auth_key={$authKey}&email={$value}";
        } elseif ($queryType === 'ip') {
            $url = "https://api.cleantalk.org/?method_name=spam_check&auth_key={$authKey}&ip={$value}";
        } else {
            // domain - check as IP-like
            $url = "https://api.cleantalk.org/?method_name=spam_check&auth_key={$authKey}&email=test@{$value}";
        }

        $r = HttpClient::get($url, ['Accept' => 'application/json'], 15);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $ms);
        }

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        $data = $r['json'];
        if (!$data) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Invalid response from API", $ms);
        }

        // CleanTalk response structure: { "data": { "value": { ... } } }
        $resultData = isset($data['data']) ? $data['data'] : $data;

        // Find the entry for our query value
        $entry = null;
        if (is_array($resultData)) {
            foreach ($resultData as $key => $val) {
                if (is_array($val)) {
                    $entry = $val;
                    break;
                }
            }
        }

        if (!$entry) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $ms);
        }

        $appears = isset($entry['appears']) ? (int)$entry['appears'] : 0;
        $frequency = isset($entry['frequency']) ? (int)$entry['frequency'] : 0;
        $lastSeen = isset($entry['updated']) ? $entry['updated'] : null;
        $isSpam = $appears > 0;

        $parts = ["{$queryType} '{$queryValue}'"];
        if ($isSpam) {
            $parts[] = "Flagged as spam (appearances: {$appears}, frequency: {$frequency})";
            if ($lastSeen) {
                $parts[] = "Last seen: {$lastSeen}";
            }
        } else {
            $parts[] = "Not found in spam database";
        }

        $score = 0;
        if ($isSpam) {
            $score = min(80, 30 + $frequency);
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 70;
        $tags = [self::API_ID, $queryType, 'spam_check'];
        if ($isSpam) {
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
                'appears' => $appears,
                'frequency' => $frequency,
                'last_seen' => $lastSeen,
                'is_spam' => $isSpam,
                'raw' => $entry,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://api.cleantalk.org/?method_name=spam_check&auth_key=&ip=127.0.0.1', [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
