<?php
// =============================================================================
//  CTI — Emerging Threats (Proofpoint ET) Module
//  API: https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
//  Free, no key. Supports: ip
//  Checks against Emerging Threats compromised IP list.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class EmergingThreatsModule extends BaseApiModule
{
    private const API_ID   = 'emerging-threats';
    private const API_NAME = 'Emerging Threats';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        // ET provides several lists; we check the compromised IPs list
        $url = 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt';
        $resp = HttpClient::get($url, [], 20);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $lines = array_filter(array_map('trim', explode("\n", $resp['body'])), fn($l) => $l !== '' && $l[0] !== '#');
        $total = count($lines);

        // Check for exact match or CIDR
        $listed = false;
        $ipLong = ip2long($queryValue);

        foreach ($lines as $line) {
            if ($line === $queryValue) { $listed = true; break; }
            if (strpos($line, '/') !== false && $ipLong !== false) {
                $parts = explode('/', $line, 2);
                $subLong = ip2long($parts[0]);
                if ($subLong !== false) {
                    $mask = ~((1 << (32 - (int)$parts[1])) - 1);
                    if (($ipLong & $mask) === ($subLong & $mask)) { $listed = true; break; }
                }
            }
        }

        if ($listed) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 80, severity: 'high', confidence: 95,
                responseMs: $resp['elapsed_ms'],
                summary: "IP {$queryValue} IS in the Emerging Threats block list ({$total} entries). Known compromised/malicious IP.",
                tags: [self::API_ID, 'ip', 'blocklisted', 'malicious', 'compromised'],
                rawData: ['listed' => true, 'total' => $total], success: true
            );
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 85,
            responseMs: $resp['elapsed_ms'],
            summary: "IP {$queryValue} is NOT in the Emerging Threats block list. Checked {$total} entries.",
            tags: [self::API_ID, 'ip', 'clean'],
            rawData: ['listed' => false, 'total' => $total], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
