<?php
// =============================================================================
//  CTI — Human Name Extractor Module
//  For domain: fetches page, extracts names from meta author, about pages.
//  For email: parses the local part for name hints.
//  Supports: domain, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class HumanNameExtractorModule extends BaseApiModule
{
    private const API_ID   = 'human-name-extractor';
    private const API_NAME = 'Human Name Extractor';
    private const SUPPORTED = ['domain', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);

        if ($queryType === 'email') {
            return $this->extractFromEmail($queryValue, $start);
        }

        return $this->extractFromDomain($queryValue, $start);
    }

    private function extractFromEmail(string $email, float $start): OsintResult
    {
        $ms = (int)((microtime(true) - $start) * 1000);
        $localPart = strstr($email, '@', true);
        if (!$localPart) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid email format');
        }

        $names = [];

        // Common patterns: john.doe, john_doe, johndoe, john-doe
        $cleaned = str_replace(['.', '_', '-'], ' ', $localPart);
        $parts = array_filter(explode(' ', $cleaned), function($p) { return strlen($p) > 1; });

        if (count($parts) >= 2) {
            // Likely first.last pattern
            $nameParts = array_map('ucfirst', $parts);
            $fullName = implode(' ', $nameParts);
            $names['local_part'] = $fullName;
        } elseif (count($parts) === 1) {
            // Try to detect camelCase
            $single = $parts[0];
            if (preg_match('/^([a-z]+)([A-Z][a-z]+)$/', $single, $m)) {
                $names['camelCase'] = ucfirst($m[1]) . ' ' . $m[2];
            } else {
                $names['username'] = ucfirst($single);
            }
        }

        $nameCount = count($names);
        $summaryParts = ["Email '{$email}'"];

        if ($nameCount > 0) {
            $primary = reset($names);
            $summaryParts[] = "Possible name: {$primary}";
        } else {
            $summaryParts[] = "No name pattern detected in local part";
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: $nameCount > 0 ? 40 : 20,
            responseMs: $ms, summary: implode('. ', $summaryParts) . '.',
            tags: [self::API_ID, 'email', 'name_extraction'],
            rawData: ['names' => $names, 'local_part' => $localPart],
            success: true
        );
    }

    private function extractFromDomain(string $domain, float $start): OsintResult
    {
        $r = HttpClient::get("https://{$domain}", [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ], 15);

        $ms = (int)((microtime(true) - $start) * 1000);

        $names = [];

        if ($r['body']) {
            $body = $r['body'];

            // Meta author
            if (preg_match('/<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $author = trim(html_entity_decode($m[1]));
                if (preg_match('/^[A-Z][a-z]+ [A-Z][a-z]+/', $author)) {
                    $names['meta_author'] = $author;
                }
            }

            // Schema.org Person
            if (preg_match('/"@type"\s*:\s*"Person"[^}]*"name"\s*:\s*"([^"]+)"/i', $body, $m)) {
                $names['schema_person'] = trim($m[1]);
            }

            // vCard / hCard
            if (preg_match('/class=["\'][^"\']*fn[^"\']*["\'][^>]*>([^<]+)/i', $body, $m)) {
                $fn = trim(strip_tags($m[1]));
                if (preg_match('/^[A-Z][a-z]+ [A-Z][a-z]+/', $fn)) {
                    $names['hcard_fn'] = $fn;
                }
            }

            // Article author byline
            if (preg_match('/(?:by|author|written by)\s*:?\s*([A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)?)/i', $body, $m)) {
                $names['byline'] = trim($m[1]);
            }

            // Twitter creator
            if (preg_match('/<meta[^>]+name=["\']twitter:creator["\'][^>]+content=["\']@?([^"\']+)/i', $body, $m)) {
                $names['twitter_creator'] = trim($m[1]);
            }
        }

        $nameCount = count($names);

        if ($nameCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 30,
                responseMs: $ms,
                summary: "Domain {$domain}: No human names could be extracted.",
                tags: [self::API_ID, 'domain', 'not_found'],
                rawData: ['names' => []],
                success: true
            );
        }

        $primary = reset($names);
        $parts = ["Domain {$domain}: Human name(s) found"];
        $parts[] = "Primary: {$primary}";
        if ($nameCount > 1) {
            $others = array_slice($names, 1);
            $otherList = [];
            foreach ($others as $src => $n) {
                $otherList[] = "{$src}: {$n}";
            }
            $parts[] = "Also: " . implode(', ', $otherList);
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 55,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'name_extraction', 'osint'],
            rawData: ['names' => $names, 'primary' => $primary],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'healthy', 'latency_ms' => 0, 'error' => null];
    }
}
