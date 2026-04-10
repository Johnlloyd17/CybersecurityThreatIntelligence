<?php
// =============================================================================
//  CTI — IPQualityScore Module
//  API Docs: https://www.ipqualityscore.com/documentation/overview
//  Auth: key in URL path. Supports: ip, email, url, phone
//  Endpoint: https://ipqualityscore.com/api/json/{type}/{key}/{value}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class IpQualityScoreModule extends BaseApiModule
{
    private const API_ID   = 'ipqualityscore';
    private const API_NAME = 'IPQualityScore';
    private const SUPPORTED = ['ip', 'email', 'url', 'phone'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $endpoint = match ($queryType) {
            'ip'    => "https://ipqualityscore.com/api/json/ip/" . urlencode($apiKey) . "/" . urlencode($queryValue),
            'email' => "https://ipqualityscore.com/api/json/email/" . urlencode($apiKey) . "/" . urlencode($queryValue),
            'url'   => "https://ipqualityscore.com/api/json/url/" . urlencode($apiKey) . "/" . urlencode($queryValue),
            'phone' => "https://ipqualityscore.com/api/json/phone/" . urlencode($apiKey) . "/" . urlencode($queryValue),
            default => '',
        };

        $resp = HttpClient::get($endpoint, [], 15);

        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['error'] || $resp['status'] === 0)
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        if ($resp['status'] !== 200)
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);

        $data = $resp['json'];
        if (!$data || !($data['success'] ?? true)) {
            $msg = $data['message'] ?? 'API error';
            if (stripos($msg, 'key') !== false) return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
            return OsintResult::error(self::API_ID, self::API_NAME, $msg, $resp['elapsed_ms']);
        }

        $fraudScore = (int)($data['fraud_score'] ?? 0);
        $score = $fraudScore;
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 70 + min(25, $fraudScore / 4));

        $label = match ($queryType) {
            'ip' => "IP {$queryValue}", 'email' => "Email {$queryValue}",
            'url' => "URL {$queryValue}", 'phone' => "Phone {$queryValue}", default => $queryValue,
        };

        $parts = ["{$label}: IPQS Fraud Score: {$fraudScore}/100"];

        if ($queryType === 'ip') {
            $isProxy = $data['proxy'] ?? false;
            $isVpn   = $data['vpn'] ?? false;
            $isTor   = $data['tor'] ?? false;
            $isBot   = $data['bot_status'] ?? false;
            $country = $data['country_code'] ?? '';
            $isp     = $data['ISP'] ?? '';

            if ($isProxy) $parts[] = "Proxy detected";
            if ($isVpn) $parts[] = "VPN detected";
            if ($isTor) $parts[] = "TOR detected";
            if ($isBot) $parts[] = "Bot detected";
            if ($country) $parts[] = "Country: {$country}";
            if ($isp) $parts[] = "ISP: {$isp}";
        } elseif ($queryType === 'email') {
            $valid     = $data['valid'] ?? false;
            $disposable = $data['disposable'] ?? false;
            $leaked    = $data['leaked'] ?? false;

            if (!$valid) $parts[] = "Invalid email";
            if ($disposable) $parts[] = "Disposable email";
            if ($leaked) $parts[] = "Found in data breaches";
        } elseif ($queryType === 'url') {
            $unsafe    = $data['unsafe'] ?? false;
            $phishing  = $data['phishing'] ?? false;
            $malware   = $data['malware'] ?? false;
            $suspicious = $data['suspicious'] ?? false;

            if ($phishing) $parts[] = "Phishing detected";
            if ($malware) $parts[] = "Malware detected";
            if ($unsafe) $parts[] = "Unsafe";
            if ($suspicious) $parts[] = "Suspicious";
        }

        $tags = [self::API_ID, $queryType];
        if ($fraudScore >= 85) $tags[] = 'malicious';
        elseif ($fraudScore >= 50) $tags[] = 'suspicious';
        else $tags[] = 'clean';
        if (($data['proxy'] ?? false) || ($data['vpn'] ?? false)) $tags[] = 'proxy';
        if ($data['tor'] ?? false) $tags[] = 'tor';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $resp = HttpClient::get('https://ipqualityscore.com/api/json/ip/' . urlencode($apiKey) . '/8.8.8.8', [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200 && ($resp['json']['success'] ?? false)) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['json']['message'] ?? "HTTP {$resp['status']}"];
    }
}
