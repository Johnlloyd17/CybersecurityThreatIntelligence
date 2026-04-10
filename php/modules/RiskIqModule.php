<?php
// =============================================================================
//  CTI — RiskIQ / PassiveTotal Module
//  API Docs: https://api.passivetotal.org/api/docs/
//  Auth: Basic auth (user:key from apiKey as "user|key")
//  Endpoint: GET https://api.passivetotal.org/v2/dns/passive
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class RiskIqModule extends BaseApiModule
{
    private const API_ID   = 'riskiq';
    private const API_NAME = 'RiskIQ PassiveTotal';
    private const SUPPORTED = ['ip', 'domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. Supports IP and domain.");
        }

        // Parse apiKey: "user|key" format
        if (strpos($apiKey, '|') === false) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'API key must be in "user|key" format for Basic auth.');
        }

        $parts = explode('|', $apiKey, 2);
        $user = $parts[0];
        $pass = $parts[1];
        $authHeader = 'Basic ' . base64_encode("{$user}:{$pass}");

        $base = rtrim($baseUrl ?: 'https://api.passivetotal.org', '/');
        $url = "{$base}/v2/dns/passive?query=" . urlencode($queryValue);
        $headers = ['Authorization' => $authHeader];

        $resp = HttpClient::get($url, $headers, 25);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        $results   = $data['results'] ?? [];
        $totalRecords = $data['totalRecords'] ?? count($results);
        $firstSeen = $data['firstSeen'] ?? 'unknown';
        $lastSeen  = $data['lastSeen'] ?? 'unknown';

        if (empty($results)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Extract unique resolved values and record types
        $resolvedValues = [];
        $recordTypes = [];
        $sources = [];
        foreach ($results as $record) {
            $resolve = $record['resolve'] ?? '';
            if ($resolve) $resolvedValues[$resolve] = true;
            $type = $record['recordType'] ?? '';
            if ($type) $recordTypes[$type] = true;
            $src = $record['source'] ?? [];
            foreach ($src as $s) {
                $sources[$s] = true;
            }
        }

        $uniqueResolved = array_keys($resolvedValues);
        $resolvedCount = count($uniqueResolved);
        $typeList = array_keys($recordTypes);

        // Score based on DNS record diversity and volume
        $score = min(30, $resolvedCount * 2);
        if ($totalRecords > 100) $score += 15;
        if ($totalRecords > 500) $score += 15;
        $score = min(70, $score);

        $resolvedSample = implode(', ', array_slice($uniqueResolved, 0, 10));
        $summary = "PassiveTotal: {$totalRecords} passive DNS record(s) for {$queryValue}. " .
                   "Unique resolutions: {$resolvedCount}. Record types: " . implode(', ', $typeList) . ". " .
                   "First seen: {$firstSeen}, Last seen: {$lastSeen}. " .
                   "Sample: {$resolvedSample}";

        $tags = [self::API_ID, $queryType, 'passive_dns'];
        if ($resolvedCount > 20) $tags[] = 'high_dns_activity';
        if ($totalRecords > 100) $tags[] = 'extensive_history';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(92, 60 + min(32, $resolvedCount * 2)),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        if (strpos($apiKey, '|') === false) {
            return ['status' => 'down', 'latency_ms' => 0, 'error' => 'API key must be "user|key" format'];
        }

        $parts = explode('|', $apiKey, 2);
        $authHeader = 'Basic ' . base64_encode("{$parts[0]}:{$parts[1]}");
        $base = rtrim($baseUrl ?: 'https://api.passivetotal.org', '/');
        $url = "{$base}/v2/account";
        $resp = HttpClient::get($url, ['Authorization' => $authHeader], 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid credentials'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
