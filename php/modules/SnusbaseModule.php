<?php
// =============================================================================
//  CTI — Snusbase Module
//  Queries Snusbase API for data breach/leak search.
//  API Docs: https://docs.snusbase.com/
//  Supports: email, domain, ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SnusbaseModule extends BaseApiModule
{
    private const API_ID   = 'snusbase';
    private const API_NAME = 'Snusbase';
    private const SUPPORTED = ['email', 'domain', 'ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.snusbase.com', '/');
        $headers = [
            'Auth'         => $apiKey,
            'Content-Type' => 'application/json',
        ];

        $searchType = match ($queryType) {
            'email'  => 'email',
            'domain' => 'domain',
            'ip'     => 'lastip',
            default  => 'email',
        };

        $body = json_encode([
            'terms' => [$queryValue],
            'types' => [$searchType],
        ]);

        $resp = HttpClient::post("{$baseUrl}/data/search", $body, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json    = $resp['json'];
        $results = $json['results'] ?? [];

        // Flatten results across databases
        $totalHits = 0;
        $databases = [];
        foreach ($results as $db => $entries) {
            if (is_array($entries)) {
                $totalHits += count($entries);
                $databases[$db] = count($entries);
            }
        }

        if ($totalHits === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $score      = min(90, 35 + $totalHits * 5);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 65 + min(30, $totalHits * 3));

        arsort($databases);
        $topDbs = array_slice(array_keys($databases), 0, 5);

        $summary = "Snusbase: {$queryValue} found in {$totalHits} record(s) across " . count($databases) . " database(s).";
        if (!empty($topDbs)) $summary .= ' Databases: ' . implode(', ', $topDbs) . '.';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: [self::API_ID, $queryType, 'data_leak', 'breach'],
            rawData: [
                'total_hits' => $totalHits,
                'databases'  => $databases,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://api.snusbase.com', '/');
        $resp = HttpClient::get("{$baseUrl}/data/stats", ['Auth' => $apiKey]);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
