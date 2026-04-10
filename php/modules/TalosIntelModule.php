<?php
// =============================================================================
//  CTI — Talos Intelligence Module
//  Free (scraping-based). Supports: ip, domain
//  Endpoint: https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fip%2F&query_entry={ip}
//  Note: Uses SenderBase/reputation check endpoint
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class TalosIntelModule extends BaseApiModule
{
    private const API_ID   = 'talos-intelligence';
    private const API_NAME = 'Talos Intelligence';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://talosintelligence.com', '/');

        $queryPath = ($queryType === 'ip')
            ? '%2Fapi%2Fv2%2Fdetails%2Fip%2F'
            : '%2Fapi%2Fv2%2Fdetails%2Fdomain%2F';

        $endpoint = "{$baseUrl}/sb_api/query_lookup?query={$queryPath}&query_entry=" . urlencode($queryValue);

        $headers = [
            'Referer' => 'https://talosintelligence.com/reputation_center',
            'Accept'  => 'application/json',
        ];

        $resp = HttpClient::get($endpoint, $headers, 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $data = $resp['json'];
        if (!$data) {
            // Talos may return non-JSON; treat the body as plaintext data
            $body = trim($resp['body']);
            if (empty($body)) {
                return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
            }
            $data = ['raw_response' => $body];
        }

        return $this->parse($data, $queryType, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $type, string $value, int $ms): OsintResult
    {
        // Talos response fields vary; try to extract reputation
        $reputation = isset($data['reputation']) ? $data['reputation'] : '';
        $emailRep   = isset($data['email_score_name']) ? $data['email_score_name'] : '';
        $webRep     = isset($data['web_score_name']) ? $data['web_score_name'] : '';
        $category   = isset($data['category']) ? $data['category'] : '';
        $weightedRep = isset($data['weighted_reputation']) ? $data['weighted_reputation'] : null;

        // Determine score from reputation
        $repLower = strtolower($reputation);
        if (in_array($repLower, ['poor', 'bad', 'untrusted'], true)) {
            $score = 80;
        } elseif (in_array($repLower, ['questionable', 'suspicious'], true)) {
            $score = 55;
        } elseif ($repLower === 'neutral') {
            $score = 20;
        } elseif (in_array($repLower, ['good', 'favorable', 'trusted'], true)) {
            $score = 5;
        } elseif ($weightedRep !== null) {
            // Use weighted reputation as a fallback (lower = worse in Talos)
            $wr = (float)$weightedRep;
            if ($wr < -3) $score = 80;
            elseif ($wr < -1) $score = 55;
            elseif ($wr < 1) $score = 20;
            else $score = 5;
        } else {
            $score = 15;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = ($reputation || $weightedRep !== null) ? 75 : 40;

        $label = ($type === 'ip') ? "IP {$value}" : "Domain {$value}";
        $parts = [];
        $parts[] = "{$label} — Talos reputation: " . ($reputation ? $reputation : 'unknown');
        if ($emailRep) $parts[] = "Email reputation: {$emailRep}";
        if ($webRep) $parts[] = "Web reputation: {$webRep}";
        if ($category) {
            $catDisplay = is_array($category) ? implode(', ', $category) : $category;
            $parts[] = "Category: {$catDisplay}";
        }
        if ($weightedRep !== null) $parts[] = "Weighted reputation score: {$weightedRep}";

        $tags = [self::API_ID, $type, 'reputation'];
        if ($score >= 70) $tags[] = 'malicious';
        elseif ($score >= 40) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = [
            'Referer' => 'https://talosintelligence.com/reputation_center',
            'Accept'  => 'application/json',
        ];
        $resp = HttpClient::get('https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fip%2F&query_entry=8.8.8.8', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
