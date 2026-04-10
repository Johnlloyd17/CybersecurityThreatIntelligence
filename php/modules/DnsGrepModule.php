<?php
// =============================================================================
//  CTI — DNSGrep Module
//  API Docs: https://www.dnsgrep.cn
//  Free, no key. Supports: domain
//  Endpoint: GET https://www.dnsgrep.cn/api/lookup?q={domain}
//  Note: This service may be unreliable, implemented with fallback error handling
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsGrepModule extends BaseApiModule
{
    private const API_ID   = 'dnsgrep';
    private const API_NAME = 'DNSGrep';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://www.dnsgrep.cn/api/lookup?q=' . urlencode($queryValue);
        $resp = HttpClient::get($url, ['Accept' => 'application/json'], 20);

        // This service may be unreliable — handle connection failures gracefully
        if ($resp['error'] || $resp['status'] === 0) {
            $errorMsg = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(
                self::API_ID,
                self::API_NAME,
                "Service may be unavailable: {$errorMsg}",
                $resp['elapsed_ms']
            );
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 403 || $resp['status'] === 503) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Service unavailable (HTTP {$resp['status']}). DNSGrep may be temporarily down.", $resp['elapsed_ms']);
        }
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];

        // Handle various response formats
        if ($data === null && $resp['body']) {
            // Try parsing NDJSON or line-delimited response
            $lines = explode("\n", trim($resp['body']));
            $parsed = [];
            foreach ($lines as $line) {
                $line = trim($line);
                if ($line === '') continue;
                $decoded = json_decode($line, true);
                if ($decoded !== null) {
                    $parsed[] = $decoded;
                }
            }
            if (!empty($parsed)) {
                $data = $parsed;
            }
        }

        if (!is_array($data) || count($data) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $totalRecords = count($data);

        // Extract domains and record types
        $domains = [];
        $types   = [];
        foreach ($data as $entry) {
            if (is_array($entry)) {
                $name = isset($entry['name']) ? $entry['name'] : (isset($entry['domain']) ? $entry['domain'] : '');
                if ($name) $domains[$name] = true;
                $type = isset($entry['type']) ? $entry['type'] : '';
                if ($type) $types[$type] = true;
            } elseif (is_string($entry)) {
                $domains[$entry] = true;
            }
        }

        $uniqueDomains = array_keys($domains);
        $domainCount = count($uniqueDomains);

        $score = min(20, (int)($domainCount / 5));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(90, 60 + min(25, $domainCount));

        $parts = ["Domain {$queryValue}: {$totalRecords} DNS record(s) found via DNSGrep"];

        if ($domainCount > 0) {
            $sample = array_slice($uniqueDomains, 0, 10);
            $parts[] = "Domains: " . implode(', ', $sample);
            if ($domainCount > 10) {
                $remaining = $domainCount - 10;
                $parts[] = "... and {$remaining} more";
            }
        }

        $typeKeys = array_keys($types);
        if (!empty($typeKeys)) {
            $parts[] = "Record types: " . implode(', ', $typeKeys);
        }

        $tags = [self::API_ID, 'domain', 'dns', 'passive_dns'];
        if ($domainCount > 50) $tags[] = 'large_infrastructure';
        $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['total_records' => $totalRecords, 'unique_domains' => array_slice($uniqueDomains, 0, 50)],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://www.dnsgrep.cn/api/lookup?q=google.com', ['Accept' => 'application/json'], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Service may be unavailable: ' . ($resp['error'] ? $resp['error'] : 'Connection failed')];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
