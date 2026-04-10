<?php
// =============================================================================
//  CTI — Ahmia Module (Dark Web Search)
//  API Docs: https://ahmia.fi/api/
//  Free, no key required. Supports: domain
//  Endpoint: https://ahmia.fi/api/search/?q={domain}&limit=20
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class AhmiaModule extends BaseApiModule
{
    private const API_ID   = 'ahmia';
    private const API_NAME = 'Ahmia';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://ahmia.fi/api', '/');
        $endpoint = "{$baseUrl}/search/?q=" . urlencode($queryValue) . "&limit=20";

        $resp = HttpClient::get($endpoint, [], 20);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        return $this->parse($data, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $value, int $ms): OsintResult
    {
        $results = isset($data['results']) ? $data['results'] : [];
        $total   = isset($data['total']) ? (int)$data['total'] : count($results);

        if ($total === 0 && count($results) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $value, $ms);
        }

        // Score based on number of dark web mentions
        if ($total >= 20) {
            $score = 80;
        } elseif ($total >= 10) {
            $score = 65;
        } elseif ($total >= 5) {
            $score = 50;
        } elseif ($total >= 1) {
            $score = 35;
        } else {
            $score = 0;
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 40 + min(50, $total * 5));

        $parts = [];
        $parts[] = "Domain {$value} — {$total} dark web mention(s) found via Ahmia";

        // Extract unique onion domains from results
        $onionDomains = [];
        foreach (array_slice($results, 0, 10) as $r) {
            $url = isset($r['url']) ? $r['url'] : '';
            if (preg_match('/([a-z2-7]{16,56}\.onion)/i', $url, $m)) {
                $onionDomains[] = $m[1];
            }
        }
        $onionDomains = array_unique($onionDomains);
        if (count($onionDomains) > 0) {
            $parts[] = count($onionDomains) . " unique .onion domain(s) referencing target";
        }

        $tags = [self::API_ID, 'domain', 'darkweb'];
        if ($total >= 10) $tags[] = 'suspicious';
        if ($total >= 20) $tags[] = 'high_exposure';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://ahmia.fi/api/search/?q=test&limit=1', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
