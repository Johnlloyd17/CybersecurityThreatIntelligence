<?php
// =============================================================================
//  CTI — Onion.link Proxy Module
//  Free, no key required. Supports: domain
//  Checks onion.link proxy for .onion equivalents
//  Basic informational module
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class OnionLinkModule extends BaseApiModule
{
    private const API_ID   = 'onion-link';
    private const API_NAME = 'Onion.link';
    private const SUPPORTED = ['domain'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        // Check if the domain itself is an onion domain
        $isOnion = (bool)preg_match('/\.onion$/i', $queryValue);

        if ($isOnion) {
            // Try to access via onion.link proxy
            $proxyDomain = preg_replace('/\.onion$/i', '.onion.link', $queryValue);
            $proxyUrl = "https://{$proxyDomain}";

            $resp = HttpClient::get($proxyUrl, [], 20);

            if ($resp['error'] || $resp['status'] === 0) {
                return $this->buildOnionResult($queryValue, true, false, $resp['elapsed_ms']);
            }

            $accessible = ($resp['status'] >= 200 && $resp['status'] < 400);
            return $this->buildOnionResult($queryValue, true, $accessible, $resp['elapsed_ms']);
        }

        // For non-onion domains, check if there's a known onion equivalent
        // Try a basic search pattern
        $searchUrl = $baseUrl
            ? rtrim($baseUrl, '/') . '/?q=' . urlencode($queryValue)
            : 'https://onion.link/?q=' . urlencode($queryValue);

        $resp = HttpClient::get($searchUrl, [], 15);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);

        // Check if the response body contains any .onion references
        $body = $resp['body'];
        $onionMatches = [];
        if (preg_match_all('/([a-z2-7]{16,56}\.onion)/i', $body, $matches)) {
            $onionMatches = array_unique($matches[1]);
        }

        if (count($onionMatches) === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        return $this->buildSearchResult($queryValue, $onionMatches, $resp['elapsed_ms']);
    }

    private function buildOnionResult(string $domain, bool $isOnion, bool $accessible, int $ms): OsintResult
    {
        $score = $isOnion ? 60 : 10;
        if ($accessible) $score += 15;

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 70;

        $parts = [];
        $parts[] = "Domain {$domain} is a .onion address";
        if ($accessible) {
            $parts[] = "Accessible via onion.link proxy";
        } else {
            $parts[] = "Not accessible via onion.link proxy (may be offline)";
        }

        $tags = [self::API_ID, 'domain', 'darkweb', 'onion'];
        if ($accessible) $tags[] = 'active';
        else $tags[] = 'inactive';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['domain' => $domain, 'is_onion' => $isOnion, 'accessible' => $accessible],
            success: true
        );
    }

    private function buildSearchResult(string $domain, array $onionDomains, int $ms): OsintResult
    {
        $count = count($onionDomains);
        $score = min(70, 30 + $count * 10);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 40 + $count * 10);

        $parts = [];
        $parts[] = "Domain {$domain} — {$count} associated .onion address(es) found";
        foreach (array_slice($onionDomains, 0, 3) as $onion) {
            $parts[] = "Onion: {$onion}";
        }

        $tags = [self::API_ID, 'domain', 'darkweb', 'onion'];
        if ($count > 3) $tags[] = 'suspicious';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: ['domain' => $domain, 'onion_domains' => $onionDomains],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://onion.link/', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] >= 200 && $resp['status'] < 400) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
