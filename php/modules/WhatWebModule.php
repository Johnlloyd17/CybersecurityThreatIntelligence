<?php
// =============================================================================
//  CTI — WhatWeb Module
//  Fetches page, inspects HTTP headers + HTML for web server/technology info.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WhatWebModule extends BaseApiModule
{
    private const API_ID   = 'whatweb';
    private const API_NAME = 'WhatWeb';
    private const SUPPORTED = ['domain', 'url'];

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
        $effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $curlError = curl_error($ch);
        curl_close($ch);

        $ms = (int)((microtime(true) - $start) * 1000);

        if (!$body && $curlError) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Failed to fetch: {$curlError}", $ms);
        }

        $info = [];

        // Parse headers
        $headers = $this->parseHeaders($headerString);

        // Server
        $server = $headers['server'] ?? null;
        if ($server) {
            $info['server'] = $server;
        }

        // X-Powered-By
        $poweredBy = $headers['x-powered-by'] ?? null;
        if ($poweredBy) {
            $info['powered_by'] = $poweredBy;
        }

        // X-AspNet-Version
        $aspnet = $headers['x-aspnet-version'] ?? null;
        if ($aspnet) {
            $info['aspnet_version'] = $aspnet;
        }

        // X-Generator
        $xgen = $headers['x-generator'] ?? null;
        if ($xgen) {
            $info['x_generator'] = $xgen;
        }

        // Content-Type
        $contentType = $headers['content-type'] ?? null;
        if ($contentType) {
            $info['content_type'] = $contentType;
        }

        // Security headers presence
        $secHeaders = [];
        $checkHeaders = [
            'x-frame-options', 'x-content-type-options', 'x-xss-protection',
            'strict-transport-security', 'content-security-policy',
            'referrer-policy', 'permissions-policy',
        ];
        foreach ($checkHeaders as $h) {
            $val = $headers[$h] ?? null;
            if ($val) {
                $secHeaders[$h] = $val;
            }
        }
        $info['security_headers'] = $secHeaders;
        $info['security_headers_count'] = count($secHeaders);
        $info['security_headers_missing'] = array_values(array_diff($checkHeaders, array_keys($secHeaders)));

        // Parse HTML
        if ($body) {
            // Title
            if (preg_match('/<title[^>]*>([^<]+)<\/title>/i', $body, $m)) {
                $info['title'] = trim($m[1]);
            }

            // Meta generator
            if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $body, $m)) {
                $info['generator'] = trim($m[1]);
            }

            // Charset
            if (preg_match('/<meta[^>]+charset=["\']?([^"\'\s>]+)/i', $body, $m)) {
                $info['charset'] = $m[1];
            }

            // Detect CMS hints
            if (preg_match('/wp-content|wp-includes/i', $body)) {
                $info['cms'] = 'WordPress';
            } elseif (preg_match('/Joomla!/i', $body)) {
                $info['cms'] = 'Joomla';
            } elseif (preg_match('/Drupal\.settings/i', $body)) {
                $info['cms'] = 'Drupal';
            }
        }

        $info['http_status'] = $httpCode;
        $info['effective_url'] = $effectiveUrl;

        $displayName = $queryType === 'domain' ? $queryValue : $url;

        // Build summary
        $parts = ["{$displayName}: HTTP {$httpCode}"];
        if (isset($info['server'])) {
            $parts[] = "Server: " . $info['server'];
        }
        if (isset($info['powered_by'])) {
            $parts[] = "Powered-By: " . $info['powered_by'];
        }
        if (isset($info['generator'])) {
            $parts[] = "Generator: " . $info['generator'];
        }
        if (isset($info['cms'])) {
            $parts[] = "CMS: " . $info['cms'];
        }
        if (isset($info['title'])) {
            $titleTrunc = mb_substr($info['title'], 0, 60);
            $parts[] = "Title: {$titleTrunc}";
        }
        $missingCount = count($info['security_headers_missing']);
        $parts[] = "Security headers: " . $info['security_headers_count'] . "/7 present ({$missingCount} missing)";

        // Score based on missing security headers
        $score = 0;
        if ($missingCount >= 5) {
            $score = 40;
        } elseif ($missingCount >= 3) {
            $score = 25;
        } elseif ($missingCount >= 1) {
            $score = 10;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 80;
        $tags = [self::API_ID, $queryType, 'web_info'];
        if ($missingCount >= 3) {
            $tags[] = 'missing_security_headers';
        }
        if ($score === 0) {
            $tags[] = 'clean';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: $info,
            success: true
        );
    }

    private function parseHeaders(string $raw): array
    {
        $headers = [];
        $lines = explode("\n", $raw);
        foreach ($lines as $line) {
            $line = trim($line);
            if (strpos($line, ':') === false) continue;
            $colonPos = strpos($line, ':');
            $key = strtolower(trim(substr($line, 0, $colonPos)));
            $val = trim(substr($line, $colonPos + 1));
            $headers[$key] = $val;
        }
        return $headers;
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
