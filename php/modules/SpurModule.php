<?php
// =============================================================================
//  CTI — Spur.us Module
//  API Docs: https://docs.spur.us/
//  Auth: Token header
//  Endpoint: GET https://api.spur.us/v2/context/{ip}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class SpurModule extends BaseApiModule
{
    private const API_ID   = 'spur';
    private const API_NAME = 'Spur.us';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}. Spur supports IP lookups only.");
        }

        $base = rtrim($baseUrl ?: 'https://api.spur.us', '/');
        $url = "{$base}/v2/context/" . urlencode($queryValue);
        $headers = ['Token' => $apiKey];

        $resp = HttpClient::get($url, $headers, 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] < 200 || $resp['status'] >= 300)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        // Parse Spur context data
        $ip       = $data['ip'] ?? $queryValue;
        $as       = $data['as'] ?? [];
        $asOrg    = $as['organization'] ?? 'Unknown';
        $asNum    = $as['number'] ?? '';
        $geoInfo  = $data['location'] ?? [];
        $country  = $geoInfo['country'] ?? 'Unknown';
        $city     = $geoInfo['city'] ?? '';
        $tunnels  = $data['tunnels'] ?? [];
        $risks    = $data['risks'] ?? [];
        $client   = $data['client'] ?? [];
        $clientType = $client['type'] ?? 'unknown';
        $infrastructure = $data['infrastructure'] ?? '';

        // Score based on risk indicators
        $score = 0;
        $riskLabels = [];
        foreach ($risks as $risk) {
            $label = is_string($risk) ? $risk : ($risk['label'] ?? '');
            if ($label) {
                $riskLabels[] = $label;
                $score += 15;
            }
        }

        // Tunnels indicate VPN/proxy usage
        $tunnelTypes = [];
        foreach ($tunnels as $tunnel) {
            $tType = $tunnel['type'] ?? '';
            $tOperator = $tunnel['operator'] ?? '';
            if ($tType) $tunnelTypes[] = $tType;
            if ($tType === 'VPN') $score += 15;
            if ($tType === 'PROXY') $score += 20;
            if ($tType === 'TOR') $score += 30;
        }

        if ($infrastructure === 'DATACENTER') $score += 10;
        if ($infrastructure === 'MOBILE') $score -= 5;

        $score = max(0, min(100, $score));

        $locationStr = array_filter([$city, $country]);
        $locationDisplay = implode(', ', $locationStr);
        $tunnelDisplay = !empty($tunnelTypes) ? implode(', ', $tunnelTypes) : 'none';
        $riskDisplay   = !empty($riskLabels) ? implode(', ', $riskLabels) : 'none';

        $summary = "Spur: IP {$ip} (AS{$asNum} {$asOrg}, {$locationDisplay}). " .
                   "Client type: {$clientType}. Infrastructure: {$infrastructure}. " .
                   "Tunnels: {$tunnelDisplay}. Risks: {$riskDisplay}.";

        $tags = [self::API_ID, 'ip', 'context'];
        if (!empty($tunnelTypes)) {
            $tags[] = 'proxy_vpn';
            foreach ($tunnelTypes as $tt) {
                $tags[] = strtolower($tt);
            }
        }
        if (!empty($riskLabels)) $tags[] = 'risk_flagged';
        if ($infrastructure === 'DATACENTER') $tags[] = 'datacenter';
        $tags[] = $score >= 40 ? 'suspicious' : 'clean';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: OsintResult::scoreToSeverity($score),
            confidence: min(92, 70 + count($risks) * 3 + count($tunnels) * 5),
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $base = rtrim($baseUrl ?: 'https://api.spur.us', '/');
        $url = "{$base}/v2/context/8.8.8.8";
        $headers = ['Token' => $apiKey];
        $resp = HttpClient::get($url, $headers, 10);

        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error'] ?? 'Connection failed'];
        if ($resp['status'] === 401 || $resp['status'] === 403) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
