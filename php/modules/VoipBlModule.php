<?php
// =============================================================================
//  CTI — VoIP Blacklist (VoIPBL) Module
//  API: https://voipbl.org/update/ (plaintext IP/CIDR list)
//  Free, no key. Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class VoipBlModule extends BaseApiModule
{
    private const API_ID   = 'voipbl';
    private const API_NAME = 'VoIP Blacklist (VoIPBL)';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = $baseUrl ?: 'https://voipbl.org/update/';
        $resp = HttpClient::get($url, [], 25);

        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $lines = array_filter(array_map('trim', explode("\n", $resp['body'])), fn($l) => $l !== '' && $l[0] !== '#');
        $total = count($lines);

        // Check exact match and CIDR ranges
        $listed = false;
        $matchedEntry = '';
        $ipLong = ip2long($queryValue);

        foreach ($lines as $line) {
            if ($line === $queryValue) {
                $listed = true;
                $matchedEntry = $line;
                break;
            }
            // Check CIDR
            if (strpos($line, '/') !== false && $ipLong !== false) {
                list($subnet, $mask) = explode('/', $line, 2);
                $subnetLong = ip2long($subnet);
                if ($subnetLong !== false) {
                    $maskBits = (int)$mask;
                    $netMask = ~((1 << (32 - $maskBits)) - 1);
                    if (($ipLong & $netMask) === ($subnetLong & $netMask)) {
                        $listed = true;
                        $matchedEntry = $line;
                        break;
                    }
                }
            }
        }

        if ($listed) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 65, severity: 'high', confidence: 90,
                responseMs: $resp['elapsed_ms'],
                summary: "IP {$queryValue} IS listed in VoIPBL (matched: {$matchedEntry}). Known for VoIP abuse/fraud.",
                tags: [self::API_ID, 'ip', 'blocklisted', 'voip_abuse', 'suspicious'],
                rawData: ['listed' => true, 'matched' => $matchedEntry, 'total' => $total], success: true
            );
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: 0, severity: 'info', confidence: 85,
            responseMs: $resp['elapsed_ms'],
            summary: "IP {$queryValue} is NOT in VoIPBL. Checked {$total} entries.",
            tags: [self::API_ID, 'ip', 'clean'],
            rawData: ['listed' => false, 'total' => $total], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://voipbl.org/update/', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
