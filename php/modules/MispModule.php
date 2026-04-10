<?php
// =============================================================================
//  CTI — MISP Module
//  Queries a MISP (Malware Information Sharing Platform) instance REST API.
//  API Docs: https://www.misp-project.org/openapi/
//  Supports: ip, domain, url, hash, email
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class MispModule extends BaseApiModule
{
    private const API_ID   = 'misp';
    private const API_NAME = 'MISP';
    private const SUPPORTED = ['ip', 'domain', 'url', 'hash', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://localhost', '/');
        $headers = [
            'Authorization' => $apiKey,
            'Accept'        => 'application/json',
            'Content-Type'  => 'application/json',
        ];

        // Search for attributes matching the indicator
        $url  = "{$baseUrl}/attributes/restSearch";
        $body = json_encode([
            'value'          => $queryValue,
            'type'           => self::mispType($queryType),
            'limit'          => $this->maxResults(),
            'includeContext'  => true,
            'includeCorrelations' => true,
        ]);

        $resp = HttpClient::post($url, $body, $headers);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0) return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300) return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $json = $resp['json'];
        $attributes = $json['response']['Attribute'] ?? [];

        if (empty($attributes)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        $totalHits   = count($attributes);
        $eventIds    = [];
        $categories  = [];
        $threatLevels = [];
        $tags        = [];

        foreach ($attributes as $attr) {
            $eid = $attr['event_id'] ?? '';
            if ($eid) $eventIds[$eid] = true;

            $cat = $attr['category'] ?? '';
            if ($cat) $categories[$cat] = ($categories[$cat] ?? 0) + 1;

            // Extract event-level threat info if context is included
            $event = $attr['Event'] ?? [];
            if (!empty($event['threat_level_id'])) {
                $threatLevels[] = (int)$event['threat_level_id'];
            }

            foreach ($attr['Tag'] ?? [] as $tag) {
                $tagName = $tag['name'] ?? '';
                if ($tagName) $tags[$tagName] = true;
            }
        }

        // Score based on threat levels (1=High, 2=Medium, 3=Low, 4=Undefined)
        $score = 0;
        if (!empty($threatLevels)) {
            $minThreat = min($threatLevels);
            $score = match ($minThreat) {
                1 => 90,
                2 => 65,
                3 => 35,
                default => 15,
            };
        } else {
            $score = min(70, $totalHits * 10);
        }

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 60 + $totalHits * 5);

        $eventCount = count($eventIds);
        $summary = "{$queryValue} found in {$totalHits} MISP attribute(s) across {$eventCount} event(s).";
        if (!empty($categories)) {
            arsort($categories);
            $topCats = array_slice(array_keys($categories), 0, 3);
            $summary .= ' Categories: ' . implode(', ', $topCats) . '.';
        }

        $resultTags = [self::API_ID, $queryType, 'threat_intel'];
        foreach (array_keys($tags) as $t) {
            if (stripos($t, 'tlp:') === 0 || stripos($t, 'misp-galaxy:') === 0) {
                $resultTags[] = $t;
            }
        }

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'total_attributes' => $totalHits,
                'event_count'      => $eventCount,
                'categories'       => $categories,
                'tags'             => array_keys($tags),
            ],
            success: true
        );

        // Discover related indicators from correlated attributes
        foreach (array_slice($attributes, 0, 20) as $attr) {
            $val  = $attr['value'] ?? '';
            $type = $attr['type']  ?? '';
            if ($val === $queryValue) continue;
            if (filter_var($val, FILTER_VALIDATE_IP)) {
                $result->addDiscovery('IP Address', $val);
            } elseif (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/i', $val)) {
                $result->addDiscovery('Internet Name', $val);
            }
        }

        return $result;
    }

    private static function mispType(string $queryType): string
    {
        return match ($queryType) {
            'ip'     => 'ip-src',
            'domain' => 'domain',
            'url'    => 'url',
            'hash'   => 'md5',
            'email'  => 'email-src',
            default  => 'text',
        };
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $baseUrl = rtrim($baseUrl ?: 'https://localhost', '/');
        $headers = ['Authorization' => $apiKey, 'Accept' => 'application/json'];
        $resp = HttpClient::get("{$baseUrl}/servers/getVersion", $headers);
        return [
            'status'     => ($resp['status'] === 200) ? 'healthy' : 'down',
            'latency_ms' => $resp['elapsed_ms'],
            'error'      => $resp['error'],
        ];
    }
}
