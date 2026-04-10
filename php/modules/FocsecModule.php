<?php
// =============================================================================
//  CTI — Focsec Module
//  Auth: x-api-key header. Supports: ip
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class FocsecModule extends BaseApiModule
{
    private const API_ID   = 'focsec';
    private const API_NAME = 'Focsec';
    private const SUPPORTED = ['ip'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $url = 'https://api.focsec.com/v1/ip/' . urlencode($queryValue);
        $resp = HttpClient::get($url, ['x-api-key' => $apiKey], 20);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 401 || $resp['status'] === 403) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?: 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON', $resp['elapsed_ms']);

        $isVpn = $data['is_vpn'] ?? false;
        $isProxy = $data['is_proxy'] ?? false;
        $isTor = $data['is_tor'] ?? false;
        $isBot = $data['is_bot'] ?? false;
        $riskScore = $data['risk_score'] ?? 0;

        $score = (int)$riskScore;
        if ($isVpn) $score = max($score, 30);
        if ($isProxy) $score = max($score, 40);
        if ($isTor) $score = max($score, 50);
        if ($isBot) $score = max($score, 60);
        $score = min(100, $score);

        $severity = OsintResult::scoreToSeverity($score);
        $tags = [self::API_ID, 'ip'];
        if ($isVpn) $tags[] = 'vpn';
        if ($isProxy) $tags[] = 'proxy';
        if ($isTor) $tags[] = 'tor';
        if ($isBot) $tags[] = 'bot';

        $flags = [];
        if ($isVpn) $flags[] = 'VPN';
        if ($isProxy) $flags[] = 'Proxy';
        if ($isTor) $flags[] = 'Tor';
        if ($isBot) $flags[] = 'Bot';
        $flagStr = !empty($flags) ? implode(', ', $flags) : 'None';

        $summary = "IP {$queryValue}: Risk: {$riskScore}. Flags: {$flagStr}.";

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: 80,
            responseMs: $resp['elapsed_ms'], summary: $summary,
            tags: $tags, rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://api.focsec.com/v1/ip/8.8.8.8', ['x-api-key' => $apiKey], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 401) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => 'Invalid API key'];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
