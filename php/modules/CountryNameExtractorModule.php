<?php
// =============================================================================
//  CTI — Country Name Extractor Module
//  For IP: uses reverse DNS + basic GeoIP approach.
//  For domain: fetches page and looks for country references.
//  Supports: domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CountryNameExtractorModule extends BaseApiModule
{
    private const API_ID   = 'country-name-extractor';
    private const API_NAME = 'Country Name Extractor';
    private const SUPPORTED = ['domain', 'ip'];

    /** Country TLD mapping (subset) */
    private const TLD_COUNTRIES = [
        'uk' => 'United Kingdom', 'de' => 'Germany', 'fr' => 'France',
        'jp' => 'Japan', 'cn' => 'China', 'au' => 'Australia',
        'ca' => 'Canada', 'br' => 'Brazil', 'in' => 'India',
        'ru' => 'Russia', 'it' => 'Italy', 'es' => 'Spain',
        'nl' => 'Netherlands', 'kr' => 'South Korea', 'se' => 'Sweden',
        'ch' => 'Switzerland', 'no' => 'Norway', 'dk' => 'Denmark',
        'fi' => 'Finland', 'pl' => 'Poland', 'pt' => 'Portugal',
        'be' => 'Belgium', 'at' => 'Austria', 'ie' => 'Ireland',
        'nz' => 'New Zealand', 'sg' => 'Singapore', 'za' => 'South Africa',
        'mx' => 'Mexico', 'ar' => 'Argentina', 'cl' => 'Chile',
        'co' => 'Colombia', 'il' => 'Israel', 'ae' => 'UAE',
        'ph' => 'Philippines', 'th' => 'Thailand', 'tw' => 'Taiwan',
        'my' => 'Malaysia', 'id' => 'Indonesia', 'vn' => 'Vietnam',
        'ua' => 'Ukraine', 'cz' => 'Czech Republic', 'hu' => 'Hungary',
        'ro' => 'Romania', 'bg' => 'Bulgaria', 'hr' => 'Croatia',
        'sk' => 'Slovakia', 'si' => 'Slovenia', 'ee' => 'Estonia',
        'lv' => 'Latvia', 'lt' => 'Lithuania',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);

        if ($queryType === 'ip') {
            return $this->extractFromIp($queryValue, $start);
        }

        return $this->extractFromDomain($queryValue, $start);
    }

    private function extractFromIp(string $ip, float $start): OsintResult
    {
        // Use free ip-api.com for geolocation
        $r = HttpClient::get("http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,regionName,city,isp,org", [], 10);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['json'] && isset($r['json']['status']) && $r['json']['status'] === 'success') {
            $data = $r['json'];
            $country = isset($data['country']) ? $data['country'] : 'Unknown';
            $countryCode = isset($data['countryCode']) ? $data['countryCode'] : '';
            $region = isset($data['regionName']) ? $data['regionName'] : '';
            $city = isset($data['city']) ? $data['city'] : '';
            $isp = isset($data['isp']) ? $data['isp'] : '';
            $org = isset($data['org']) ? $data['org'] : '';

            $parts = ["IP {$ip}: Located in {$country} ({$countryCode})"];
            if ($city && $region) {
                $parts[] = "Location: {$city}, {$region}";
            }
            if ($isp) {
                $parts[] = "ISP: {$isp}";
            }
            if ($org) {
                $parts[] = "Org: {$org}";
            }

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 80,
                responseMs: $ms, summary: implode('. ', $parts) . '.',
                tags: [self::API_ID, 'ip', 'geolocation', $countryCode],
                rawData: $data,
                success: true
            );
        }

        // Fallback: reverse DNS
        $hostname = @gethostbyaddr($ip);
        $ms = (int)((microtime(true) - $start) * 1000);

        if ($hostname && $hostname !== $ip) {
            // Check TLD for country hint
            $tld = strtolower(substr(strrchr($hostname, '.'), 1));
            $country = isset(self::TLD_COUNTRIES[$tld]) ? self::TLD_COUNTRIES[$tld] : null;
            if ($country) {
                return new OsintResult(
                    api: self::API_ID, apiName: self::API_NAME,
                    score: 0, severity: 'info', confidence: 50,
                    responseMs: $ms,
                    summary: "IP {$ip}: Hostname {$hostname} suggests {$country} (TLD .{$tld}).",
                    tags: [self::API_ID, 'ip', 'geolocation', $tld],
                    rawData: ['hostname' => $hostname, 'tld' => $tld, 'country' => $country],
                    success: true
                );
            }
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 20,
            responseMs: $ms,
            summary: "IP {$ip}: Country could not be determined.",
            tags: [self::API_ID, 'ip', 'not_found'],
            rawData: ['hostname' => $hostname],
            success: true
        );
    }

    private function extractFromDomain(string $domain, float $start): OsintResult
    {
        $countries = [];

        // Check TLD
        $tld = strtolower(substr(strrchr($domain, '.'), 1));
        // Handle co.uk style TLDs
        if (preg_match('/\.([a-z]{2})$/i', $domain, $m)) {
            $cc = strtolower($m[1]);
            if (isset(self::TLD_COUNTRIES[$cc])) {
                $countries['tld'] = self::TLD_COUNTRIES[$cc];
            }
        }

        // Fetch page and look for country references
        $r = HttpClient::get("https://{$domain}", [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ], 15);

        $ms = (int)((microtime(true) - $start) * 1000);

        if ($r['body']) {
            $body = $r['body'];

            // Check meta tags for geo info
            if (preg_match('/<meta[^>]+name=["\']geo\.country["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $countries['geo_meta'] = trim($m[1]);
            }
            if (preg_match('/<meta[^>]+name=["\']geo\.placename["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $countries['geo_place'] = trim($m[1]);
            }

            // Check for hreflang tags
            if (preg_match_all('/hreflang=["\']([a-z]{2})-([a-z]{2})["\']/', $body, $m)) {
                foreach ($m[2] as $cc) {
                    $cc = strtolower($cc);
                    if (isset(self::TLD_COUNTRIES[$cc])) {
                        $countries['hreflang_' . $cc] = self::TLD_COUNTRIES[$cc];
                    }
                }
            }

            // Schema.org address
            if (preg_match('/"addressCountry"\s*:\s*"([^"]+)"/i', $body, $m)) {
                $countries['schema_address'] = trim($m[1]);
            }
        }

        $countryCount = count($countries);

        if ($countryCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 30,
                responseMs: $ms,
                summary: "Domain {$domain}: No country information could be extracted.",
                tags: [self::API_ID, 'domain', 'not_found'],
                rawData: ['countries' => []],
                success: true
            );
        }

        $primary = reset($countries);
        $parts = ["Domain {$domain}: Country information found"];
        $parts[] = "Primary: {$primary}";
        if ($countryCount > 1) {
            $sources = [];
            foreach ($countries as $src => $c) {
                $sources[] = "{$src}: {$c}";
            }
            $parts[] = "Sources: " . implode(', ', $sources);
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 65,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: [self::API_ID, 'domain', 'geolocation', 'country'],
            rawData: ['countries' => $countries, 'primary' => $primary],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('http://ip-api.com/json/8.8.8.8?fields=status', [], 5);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['json'] && isset($r['json']['status']) && $r['json']['status'] === 'success') {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'GeoIP lookup failed';
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
