<?php
// =============================================================================
//  CTI — Abusix Module
//  DNS-based check. Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class AbusixModule extends BaseApiModule
{
    private const API_ID   = 'abusix';
    private const API_NAME = 'Abusix';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $octets = explode('.', $queryValue);
        if (count($octets) !== 4) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid IPv4 address');
        }

        $reversed = implode('.', array_reverse($octets));
        $lookup = "{$apiKey}.{$reversed}.combined.mail.abusix.zone";

        $startMs = (int)(microtime(true) * 1000);
        $result = gethostbyname($lookup);
        $elapsed = (int)(microtime(true) * 1000) - $startMs;

        if ($result === $lookup) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $elapsed);
        }

        // Listed - parse response
        $listed = true;
        $score = 70;
        $severity = OsintResult::scoreToSeverity($score);

        $tags = [self::API_ID, 'ip', 'blacklist'];
        if (strpos($result, '127.0.0.2') !== false) $tags[] = 'spam_source';
        if (strpos($result, '127.0.0.4') !== false) $tags[] = 'exploit';
        if (strpos($result, '127.0.0.8') !== false) $tags[] = 'policy';

        $summary = "IP {$queryValue}: Listed in Abusix blocklist. Response: {$result}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 85,
            responseMs: $elapsed, summary: $summary,
            tags: $tags, rawData: ['listed' => true, 'response' => $result], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $lookup = "{$apiKey}.1.0.0.127.combined.mail.abusix.zone";
        $startMs = (int)(microtime(true) * 1000);
        gethostbyname($lookup);
        $elapsed = (int)(microtime(true) * 1000) - $startMs;
        return ['status' => 'healthy', 'latency_ms' => $elapsed, 'error' => null];
    }
}
