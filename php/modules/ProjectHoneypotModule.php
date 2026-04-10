<?php
// =============================================================================
//  CTI — Project Honey Pot Module
//  API Docs: https://www.projecthoneypot.org/httpbl_api.php
//  Auth: DNS-based with API key as first octet. Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ProjectHoneypotModule extends BaseApiModule
{
    private const API_ID   = 'project-honeypot';
    private const API_NAME = 'Project Honey Pot';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        // Reverse the IP octets
        $octets = explode('.', $queryValue);
        if (count($octets) !== 4) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid IPv4 address');
        }
        $reversed = implode('.', array_reverse($octets));
        $lookup = "{$apiKey}.{$reversed}.dnsbl.httpbl.org";

        $startMs = (int)(microtime(true) * 1000);
        $result = gethostbyname($lookup);
        $elapsed = (int)(microtime(true) * 1000) - $startMs;

        // If DNS resolution returns the same string, no record was found
        if ($result === $lookup) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $elapsed);
        }

        $parts = explode('.', $result);
        if (count($parts) !== 4 || $parts[0] !== '127') {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $elapsed);
        }

        $days = (int)$parts[1];
        $threat = (int)$parts[2];
        $type = (int)$parts[3];

        $typeLabels = [];
        if ($type & 1) $typeLabels[] = 'suspicious';
        if ($type & 2) $typeLabels[] = 'harvester';
        if ($type & 4) $typeLabels[] = 'comment_spammer';

        $score = min(100, $threat);
        $severity = OsintResult::scoreToSeverity($score);
        $confidence = $days < 30 ? 85 : 60;

        $typeStr = !empty($typeLabels) ? implode(', ', $typeLabels) : 'unknown';
        $summary = "IP {$queryValue}: Threat score: {$threat}. Type: {$typeStr}. Last seen: {$days} days ago.";

        $tags = [self::API_ID, 'ip'];
        if ($threat >= 50) $tags[] = 'malicious';
        elseif ($threat >= 25) $tags[] = 'suspicious';
        foreach ($typeLabels as $l) $tags[] = $l;

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $elapsed, summary: $summary,
            tags: array_values(array_unique($tags)), rawData: [
                'days_since_last_activity' => $days,
                'threat_score' => $threat,
                'visitor_type' => $type,
                'type_labels' => $typeLabels,
            ], success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $lookup = "{$apiKey}.1.0.0.127.dnsbl.httpbl.org";
        $startMs = (int)(microtime(true) * 1000);
        $result = gethostbyname($lookup);
        $elapsed = (int)(microtime(true) * 1000) - $startMs;

        if ($result === $lookup) {
            // DNS didn't resolve - could be invalid key or no record
            return ['status' => 'healthy', 'latency_ms' => $elapsed, 'error' => null];
        }
        $parts = explode('.', $result);
        if (count($parts) === 4 && $parts[0] === '127') {
            return ['status' => 'healthy', 'latency_ms' => $elapsed, 'error' => null];
        }
        return ['status' => 'down', 'latency_ms' => $elapsed, 'error' => 'Unexpected DNS response'];
    }
}
