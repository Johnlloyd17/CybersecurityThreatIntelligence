<?php
// =============================================================================
//  CTI — Base64 Decoder Module
//  Checks if a value contains base64-encoded strings and decodes them.
//  Supports: url, domain
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class Base64DecoderModule extends BaseApiModule
{
    private const API_ID   = 'base64-decoder';
    private const API_NAME = 'Base64 Decoder';
    private const SUPPORTED = ['url', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);

        $decoded = [];

        // Check the raw value
        $this->tryDecode($value, $decoded);

        // If URL, parse and check components
        if ($queryType === 'url') {
            $parsed = parse_url($value);
            $query = isset($parsed['query']) ? $parsed['query'] : '';
            $path = isset($parsed['path']) ? $parsed['path'] : '';
            $fragment = isset($parsed['fragment']) ? $parsed['fragment'] : '';

            // Check query string parameters
            if ($query) {
                parse_str($query, $params);
                foreach ($params as $key => $val) {
                    if (is_string($val)) {
                        $this->tryDecode($val, $decoded, "param:{$key}");
                    }
                }
            }

            // Check path segments
            $segments = explode('/', trim($path, '/'));
            foreach ($segments as $seg) {
                $this->tryDecode($seg, $decoded, 'path');
            }

            // Check fragment
            if ($fragment) {
                $this->tryDecode($fragment, $decoded, 'fragment');
            }
        }

        $ms = (int)((microtime(true) - $start) * 1000);

        $decodedCount = count($decoded);

        if ($decodedCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 80,
                responseMs: $ms,
                summary: "No base64-encoded strings detected in the input.",
                tags: [self::API_ID, $queryType, 'clean'],
                rawData: ['decoded' => []],
                success: true
            );
        }

        $parts = ["{$decodedCount} base64-encoded string(s) found"];
        foreach ($decoded as $d) {
            $truncated = mb_substr($d['decoded'], 0, 80);
            $location = $d['location'];
            $parts[] = "[{$location}] => {$truncated}";
        }

        // Check if decoded content looks suspicious
        $score = 10;
        foreach ($decoded as $d) {
            $dec = strtolower($d['decoded']);
            if (preg_match('/password|secret|token|key|admin|root|exec|eval|script/i', $dec)) {
                $score = max($score, 50);
            }
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 70;
        $tags = [self::API_ID, $queryType, 'base64'];
        if ($score >= 40) {
            $tags[] = 'suspicious_content';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['decoded' => $decoded],
            success: true
        );
    }

    private function tryDecode(string $value, array &$results, string $location = 'value'): void
    {
        // Look for base64 patterns (at least 8 chars, valid charset)
        if (preg_match_all('/[A-Za-z0-9+\/]{8,}={0,2}/', $value, $matches)) {
            foreach ($matches[0] as $candidate) {
                $raw = base64_decode($candidate, true);
                if ($raw === false) continue;
                // Check if decoded output is printable text
                if (mb_check_encoding($raw, 'UTF-8') && preg_match('/^[\x20-\x7E\s]+$/', $raw) && strlen($raw) >= 4) {
                    $results[] = [
                        'encoded' => $candidate,
                        'decoded' => $raw,
                        'location' => $location,
                    ];
                }
            }
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'healthy', 'latency_ms' => 0, 'error' => null];
    }
}
