<?php
// =============================================================================
//  CTI — PGP Key Servers Module
//  API: https://keys.openpgp.org/vks/v1/by-email/{email}
//  Free, no key. Supports: email
//  Checks if an email address has a PGP key published on OpenPGP key servers.
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class PgpKeyserversModule extends BaseApiModule
{
    private const API_ID   = 'pgp-keyservers';
    private const API_NAME = 'PGP Key Servers';
    private const SUPPORTED = ['email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $encodedEmail = urlencode($queryValue);
        $base = $baseUrl ?: 'https://keys.openpgp.org';
        $url = "{$base}/vks/v1/by-email/{$encodedEmail}";
        $resp = HttpClient::get($url, [], 15);

        if ($resp['error'] || $resp['status'] === 0) {
            $errMsg = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $errMsg, $resp['elapsed_ms']);
        }

        if ($resp['status'] === 404) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        if ($resp['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        }

        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        // If we got a 200 with body content, the key exists
        $keyData = $resp['body'];
        $hasKey = !empty(trim($keyData));

        if ($hasKey) {
            // Try to extract basic info from the ASCII-armored key
            $keySize = strlen($keyData);
            $score      = 10;
            $severity   = OsintResult::scoreToSeverity($score);
            $confidence = 95;
            $summary    = "Email {$queryValue} has a PGP public key published on OpenPGP key servers ({$keySize} bytes).";
            $tags       = [self::API_ID, 'email', 'pgp', 'key-found', 'identity'];
        } else {
            $score      = 0;
            $severity   = 'info';
            $confidence = 90;
            $summary    = "No PGP public key found for {$queryValue} on OpenPGP key servers.";
            $tags       = [self::API_ID, 'email', 'no-key'];
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: ['has_key' => $hasKey, 'key_size_bytes' => $hasKey ? strlen($keyData) : 0],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        // Use a known test lookup to verify service is responding
        $resp = HttpClient::get('https://keys.openpgp.org', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
