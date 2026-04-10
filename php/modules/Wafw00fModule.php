<?php
// =============================================================================
//  CTI — WAF Detection Module (wafw00f alternative)
//  Fetches page and inspects response headers for WAF signatures.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class Wafw00fModule extends BaseApiModule
{
    private const API_ID   = 'wafw00f';
    private const API_NAME = 'WAF Detection';
    private const SUPPORTED = ['domain', 'url'];

    /** WAF signature patterns: key => [header_pattern, name] */
    private const WAF_SIGNATURES = [
        'cloudflare'     => ['header' => 'server',           'pattern' => '/cloudflare/i',       'name' => 'Cloudflare'],
        'cloudflare_ray' => ['header' => 'cf-ray',           'pattern' => '/.+/',                'name' => 'Cloudflare'],
        'akamai'         => ['header' => 'x-akamai-transformed', 'pattern' => '/.+/',            'name' => 'Akamai'],
        'akamai_ghost'   => ['header' => 'server',           'pattern' => '/AkamaiGHost/i',      'name' => 'Akamai'],
        'sucuri'         => ['header' => 'server',           'pattern' => '/Sucuri/i',            'name' => 'Sucuri WAF'],
        'sucuri_id'      => ['header' => 'x-sucuri-id',      'pattern' => '/.+/',                'name' => 'Sucuri WAF'],
        'aws_waf'        => ['header' => 'x-amzn-requestid', 'pattern' => '/.+/',               'name' => 'AWS WAF'],
        'aws_cf'         => ['header' => 'x-amz-cf-id',      'pattern' => '/.+/',               'name' => 'AWS CloudFront'],
        'incapsula'      => ['header' => 'x-iinfo',          'pattern' => '/.+/',               'name' => 'Imperva Incapsula'],
        'incapsula_vis'  => ['header' => 'x-cdn',            'pattern' => '/Incapsula/i',       'name' => 'Imperva Incapsula'],
        'f5_bigip'       => ['header' => 'server',           'pattern' => '/BigIP|BIG-IP/i',    'name' => 'F5 BIG-IP'],
        'f5_cookie'      => ['header' => 'set-cookie',       'pattern' => '/BIGipServer/i',     'name' => 'F5 BIG-IP'],
        'barracuda'      => ['header' => 'server',           'pattern' => '/Barracuda/i',       'name' => 'Barracuda WAF'],
        'fortiweb'       => ['header' => 'server',           'pattern' => '/FortiWeb/i',        'name' => 'FortiWeb WAF'],
        'dotdefender'    => ['header' => 'x-dotdefender-denied', 'pattern' => '/.+/',           'name' => 'dotDefender'],
        'citrix_ns'      => ['header' => 'via',              'pattern' => '/NS-CACHE/i',        'name' => 'Citrix NetScaler'],
        'wallarm'        => ['header' => 'server',           'pattern' => '/wallarm/i',         'name' => 'Wallarm WAF'],
        'reblaze'        => ['header' => 'server',           'pattern' => '/Reblaze/i',         'name' => 'Reblaze WAF'],
        'stackpath'      => ['header' => 'x-sp-url',         'pattern' => '/.+/',              'name' => 'StackPath WAF'],
        'fastly'         => ['header' => 'x-fastly-request-id', 'pattern' => '/.+/',           'name' => 'Fastly CDN/WAF'],
        'varnish'        => ['header' => 'via',              'pattern' => '/varnish/i',         'name' => 'Varnish'],
        'ddosguard'      => ['header' => 'server',           'pattern' => '/ddos-guard/i',      'name' => 'DDoS-Guard'],
        'wordfence'      => ['header' => 'x-wordfence',      'pattern' => '/.+/',              'name' => 'Wordfence WAF'],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);

        $url = $queryValue;
        if ($queryType === 'domain') {
            $url = "https://{$queryValue}";
        }
        if (!preg_match('#^https?://#i', $url)) {
            $url = "https://{$url}";
        }

        $headerString = '';
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            CURLOPT_HEADERFUNCTION => function($curl, $header) use (&$headerString) {
                $headerString .= $header;
                return strlen($header);
            },
        ]);
        $body = curl_exec($ch);
        $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        $ms = (int)((microtime(true) - $start) * 1000);

        if ($httpCode === 0 && $curlError) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Failed to fetch: {$curlError}", $ms);
        }

        // Parse headers into associative array (lowercase keys)
        $headers = [];
        foreach (explode("\n", $headerString) as $line) {
            $line = trim($line);
            $colonPos = strpos($line, ':');
            if ($colonPos === false) continue;
            $key = strtolower(trim(substr($line, 0, $colonPos)));
            $val = trim(substr($line, $colonPos + 1));
            // Append for duplicate headers (e.g. set-cookie)
            if (isset($headers[$key])) {
                $headers[$key] .= '; ' . $val;
            } else {
                $headers[$key] = $val;
            }
        }

        // Check body for WAF clues too
        $bodyIndicators = [];
        if ($body) {
            if (preg_match('/cloudflare/i', $body)) $bodyIndicators[] = 'Cloudflare';
            if (preg_match('/sucuri/i', $body)) $bodyIndicators[] = 'Sucuri WAF';
            if (preg_match('/incapsula/i', $body)) $bodyIndicators[] = 'Imperva Incapsula';
            if (preg_match('/ddos-guard/i', $body)) $bodyIndicators[] = 'DDoS-Guard';
        }

        // Match WAF signatures
        $detected = [];
        foreach (self::WAF_SIGNATURES as $sigKey => $sig) {
            $hdrName = $sig['header'];
            $hdrVal = $headers[$hdrName] ?? null;
            if ($hdrVal === null) continue;
            if (preg_match($sig['pattern'], $hdrVal)) {
                $detected[$sig['name']] = true;
            }
        }

        // Add body indicators
        foreach ($bodyIndicators as $bi) {
            $detected[$bi] = true;
        }

        $wafList = array_keys($detected);
        $wafCount = count($wafList);
        $displayName = $queryType === 'domain' ? $queryValue : $url;

        if ($wafCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 60,
                responseMs: $ms,
                summary: "{$displayName}: No WAF detected. The site may not use a WAF or uses one that is not fingerprinted.",
                tags: [self::API_ID, $queryType, 'no_waf'],
                rawData: ['wafs' => [], 'http_status' => $httpCode],
                success: true
            );
        }

        $parts = ["{$displayName}: {$wafCount} WAF/CDN detected"];
        $parts[] = "Detected: " . implode(', ', $wafList);

        $score      = 5;
        $severity   = 'info';
        $confidence = 80;
        $tags = [self::API_ID, $queryType, 'waf_detected'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'wafs' => $wafList,
                'waf_count' => $wafCount,
                'http_status' => $httpCode,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://www.cloudflare.com', [], 5);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] >= 200 && $r['status'] < 400) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
