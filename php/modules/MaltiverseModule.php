<?php
// =============================================================================
//  CTI — Maltiverse Module
//  API Docs: https://maltiverse.com/api
//  Free, no key required. Supports: ip, domain, hash, url
//  Endpoint: https://api.maltiverse.com/ip/{ip} or /hostname/{domain} or /sample/{hash}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class MaltiverseModule extends BaseApiModule
{
    private const API_ID   = 'maltiverse';
    private const API_NAME = 'Maltiverse';
    private const SUPPORTED = ['ip', 'domain', 'hash', 'url'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.maltiverse.com', '/');

        $endpoint = match ($queryType) {
            'ip'     => "{$baseUrl}/ip/" . urlencode($queryValue),
            'domain' => "{$baseUrl}/hostname/" . urlencode($queryValue),
            'hash'   => "{$baseUrl}/sample/" . urlencode($queryValue),
            'url'    => "{$baseUrl}/url/" . urlencode($queryValue),
            default  => "{$baseUrl}/ip/" . urlencode($queryValue),
        };

        $headers = ['Accept' => 'application/json'];
        if ($apiKey) {
            $headers['Authorization'] = "Bearer {$apiKey}";
        }

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
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        return $this->parse($data, $queryType, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $type, string $value, int $ms): OsintResult
    {
        $classification = isset($data['classification']) ? $data['classification'] : 'unknown';
        $blacklist      = isset($data['blacklist']) ? $data['blacklist'] : [];
        $tags           = isset($data['tag']) ? $data['tag'] : [];
        $isIoc          = isset($data['is_ioc']) ? (bool)$data['is_ioc'] : false;
        $isAlive        = isset($data['is_alive']) ? (bool)$data['is_alive'] : false;

        // Score based on classification
        $score = match ($classification) {
            'malicious'  => 85,
            'suspicious' => 55,
            'neutral'    => 15,
            'whitelist'  => 0,
            default      => 10,
        };

        // Boost score based on blacklists
        $blCount = count($blacklist);
        if ($blCount > 0) {
            $score = min(100, $score + $blCount * 5);
        }
        if ($isIoc) {
            $score = max($score, 70);
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 50 + $blCount * 5 + ($isIoc ? 20 : 0));

        $label = match ($type) {
            'ip'     => "IP {$value}",
            'domain' => "Domain {$value}",
            'hash'   => "Hash {$value}",
            'url'    => "URL {$value}",
            default  => $value,
        };

        $parts = [];
        $parts[] = "{$label} — Classification: {$classification}";
        if ($isIoc) $parts[] = "Identified as IoC";
        if ($isAlive) $parts[] = "Currently active";
        if ($blCount > 0) {
            $parts[] = "Listed on {$blCount} blacklist(s)";
            $blNames = [];
            foreach (array_slice($blacklist, 0, 3) as $bl) {
                $blName = isset($bl['source']) ? $bl['source'] : (isset($bl['description']) ? $bl['description'] : '');
                if ($blName) $blNames[] = $blName;
            }
            if (count($blNames) > 0) {
                $parts[] = "Sources: " . implode(', ', $blNames);
            }
        }
        if (count($tags) > 0) {
            $parts[] = "Tags: " . implode(', ', array_slice($tags, 0, 5));
        }

        $resultTags = [self::API_ID, $type];
        if ($classification === 'malicious') $resultTags[] = 'malicious';
        elseif ($classification === 'suspicious') $resultTags[] = 'suspicious';
        else $resultTags[] = 'clean';
        if ($isIoc) $resultTags[] = 'ioc';
        if ($blCount > 0) $resultTags[] = 'blacklisted';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($resultTags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['Accept' => 'application/json'];
        if ($apiKey) {
            $headers['Authorization'] = "Bearer {$apiKey}";
        }
        $resp = HttpClient::get('https://api.maltiverse.com/ip/8.8.8.8', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
