<?php
// =============================================================================
//  CTI — ThreatCrowd Module
//  API Docs: https://github.com/AlienVault-OTX/ApiV2 (ThreatCrowd is community)
//  Free, no key required. Supports: ip, domain, email, hash
//  Endpoint: https://www.threatcrowd.org/searchApi/v2/{type}/report/
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class ThreatCrowdModule extends BaseApiModule
{
    private const API_ID   = 'threatcrowd';
    private const API_NAME = 'ThreatCrowd';
    private const SUPPORTED = ['ip', 'domain', 'email', 'hash'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://www.threatcrowd.org/searchApi/v2', '/');

        $endpoint = match ($queryType) {
            'ip'     => "{$baseUrl}/ip/report/?ip=" . urlencode($queryValue),
            'domain' => "{$baseUrl}/domain/report/?domain=" . urlencode($queryValue),
            'email'  => "{$baseUrl}/email/report/?email=" . urlencode($queryValue),
            'hash'   => "{$baseUrl}/file/report/?resource=" . urlencode($queryValue),
            default  => "{$baseUrl}/ip/report/?ip=" . urlencode($queryValue),
        };

        $resp = HttpClient::get($endpoint, [], 20);

        if ($resp['error'] || $resp['status'] === 0) {
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        // response_code: 1 = found, 0 = not found, -1 = error
        $responseCode = (int)($data['response_code'] ?? -1);
        if ($responseCode === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        return $this->parse($data, $queryType, $queryValue, $resp['elapsed_ms']);
    }

    private function parse(array $data, string $type, string $value, int $ms): OsintResult
    {
        $votes     = (int)($data['votes'] ?? 0);
        $resolutions = $data['resolutions'] ?? [];
        $hashes    = $data['hashes'] ?? [];
        $emails    = $data['emails'] ?? [];
        $subdomains = $data['subdomains'] ?? [];
        $references = $data['references'] ?? [];
        $permalink = $data['permalink'] ?? '';

        // Score based on votes and data density
        $dataPoints = count($resolutions) + count($hashes) + count($references);
        if ($votes < 0) {
            $score = min(100, 60 + abs($votes) * 5 + min(30, $dataPoints));
        } elseif ($dataPoints > 20) {
            $score = 50;
        } elseif ($dataPoints > 5) {
            $score = 30;
        } else {
            $score = max(0, 10 + $dataPoints * 2);
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 50 + min(40, $dataPoints * 2));

        $parts = [];
        $label = match ($type) {
            'ip'     => "IP {$value}",
            'domain' => "Domain {$value}",
            'email'  => "Email {$value}",
            'hash'   => "Hash {$value}",
            default  => $value,
        };

        $parts[] = "{$label} — Votes: {$votes}";
        if (count($resolutions) > 0) $parts[] = count($resolutions) . " DNS resolution(s)";
        if (count($hashes) > 0)      $parts[] = count($hashes) . " associated hash(es)";
        if (count($subdomains) > 0)   $parts[] = count($subdomains) . " subdomain(s)";
        if (count($emails) > 0)       $parts[] = count($emails) . " associated email(s)";
        if (count($references) > 0)   $parts[] = count($references) . " reference(s)";

        $tags = [self::API_ID, $type];
        if ($votes < 0) $tags[] = 'malicious';
        elseif ($dataPoints > 10) $tags[] = 'suspicious';
        else $tags[] = 'clean';

        if (count($hashes) > 0) $tags[] = 'malware';
        if (count($subdomains) > 5) $tags[] = 'infrastructure';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=8.8.8.8', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
