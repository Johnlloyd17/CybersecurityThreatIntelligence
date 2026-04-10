<?php
// =============================================================================
//  CTI — Company Name Extractor Module
//  Fetches page, extracts company/org name from meta tags, title, copyright.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CompanyNameExtractorModule extends BaseApiModule
{
    private const API_ID   = 'company-name-extractor';
    private const API_NAME = 'Company Name Extractor';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $domain = trim($queryValue);
        $url = "https://{$domain}";

        $r = HttpClient::get($url, [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ], 15);

        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['status'] === 0) {
            $err = $r['error'] ? $r['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $ms);
        }

        $body = $r['body'];
        $names = [];

        if ($body) {
            // og:site_name
            if (preg_match('/<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $names['og_site_name'] = trim(html_entity_decode($m[1]));
            }

            // application-name
            if (preg_match('/<meta[^>]+name=["\']application-name["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $names['application_name'] = trim(html_entity_decode($m[1]));
            }

            // author
            if (preg_match('/<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $names['author'] = trim(html_entity_decode($m[1]));
            }

            // title tag
            if (preg_match('/<title[^>]*>([^<]+)<\/title>/i', $body, $m)) {
                $names['title'] = trim(html_entity_decode($m[1]));
            }

            // Copyright patterns
            if (preg_match('/(?:copyright|\x{00A9}|&copy;)\s*(?:\d{4}\s*)?([^<\n\r.]{2,60})/iu', $body, $m)) {
                $copyrightName = trim($m[1]);
                // Clean up common suffixes
                $copyrightName = preg_replace('/\s*(all\s+rights|inc\.|ltd\.|llc|co\.)\s*/i', ' $1', $copyrightName);
                $copyrightName = trim($copyrightName, ' .,;:-');
                if (strlen($copyrightName) > 2) {
                    $names['copyright'] = $copyrightName;
                }
            }

            // Schema.org organization
            if (preg_match('/"@type"\s*:\s*"Organization"[^}]*"name"\s*:\s*"([^"]+)"/i', $body, $m)) {
                $names['schema_org'] = trim($m[1]);
            }

            // Twitter site
            if (preg_match('/<meta[^>]+name=["\']twitter:site["\'][^>]+content=["\']@?([^"\']+)/i', $body, $m)) {
                $names['twitter_site'] = trim($m[1]);
            }
        }

        $nameCount = count($names);

        if ($nameCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 40,
                responseMs: $ms,
                summary: "Domain {$domain}: No company/organization name could be extracted.",
                tags: [self::API_ID, 'domain', 'not_found'],
                rawData: ['names' => []],
                success: true
            );
        }

        // Try to pick the best name
        $bestName = '';
        $priority = ['schema_org', 'og_site_name', 'application_name', 'copyright', 'author', 'twitter_site', 'title'];
        foreach ($priority as $key) {
            if (isset($names[$key]) && strlen($names[$key]) > 1) {
                $bestName = $names[$key];
                break;
            }
        }
        if (empty($bestName)) {
            $bestName = reset($names);
        }

        $parts = ["Domain {$domain}: Company/Org name identified"];
        $parts[] = "Primary: {$bestName}";
        if ($nameCount > 1) {
            $otherNames = array_diff($names, [$bestName]);
            $otherList = [];
            foreach ($otherNames as $src => $n) {
                $otherList[] = "{$src}: {$n}";
            }
            $parts[] = "Also found: " . implode(', ', array_slice($otherList, 0, 5));
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 70,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'company', 'osint'],
            rawData: [
                'primary_name' => $bestName,
                'all_names' => $names,
                'source_count' => $nameCount,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://www.google.com', [], 5);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
