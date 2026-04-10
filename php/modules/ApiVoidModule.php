<?php
// =============================================================================
//  CTI — APIVOID MODULE HANDLER
//  php/modules/ApiVoidModule.php
//
//  Queries APIVoid for threat intelligence on IPs, domains, URLs, and emails.
//  Requires an API key (free tier available).
//  API Docs: https://docs.apivoid.com
//
//  Endpoints used:
//    IP Reputation:     /iprep/v1/pay-as-you-go/?key=KEY&ip=VALUE
//    Domain Reputation: /domainbl/v1/pay-as-you-go/?key=KEY&host=VALUE
//    URL Reputation:    /urlrep/v1/pay-as-you-go/?key=KEY&url=VALUE
//    Email Verify:      /emailverify/v1/pay-as-you-go/?key=KEY&email=VALUE
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';

class ApiVoidModule extends BaseApiModule
{
    private const API_ID   = 'apivoid';
    private const API_NAME = 'APIVoid';
    private const BASE     = 'https://endpoint.apivoid.com';

    private const SUPPORTED_TYPES = ['ip', 'domain', 'url', 'email'];

    /**
     * Execute a query against APIVoid APIs.
     */
    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (empty($apiKey)) {
            return OsintResult::error(self::API_ID, self::API_NAME, 'API key is required for APIVoid.');
        }

        if (!in_array($queryType, self::SUPPORTED_TYPES, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        switch ($queryType) {
            case 'ip':     return $this->queryIpReputation($queryValue, $apiKey);
            case 'domain': return $this->queryDomainReputation($queryValue, $apiKey);
            case 'url':    return $this->queryUrlReputation($queryValue, $apiKey);
            case 'email':  return $this->queryEmailVerify($queryValue, $apiKey);
            default:       return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported type: {$queryType}");
        }
    }

    /**
     * IP Reputation — checks an IP against 40+ blacklist engines.
     */
    private function queryIpReputation(string $ip, string $key): OsintResult
    {
        $url  = self::BASE . '/iprep/v1/pay-as-you-go/?key=' . urlencode($key) . '&ip=' . urlencode($ip);
        $resp = HttpClient::get($url, [], 15);

        $errorResult = $this->checkErrors($resp, 'IP Reputation');
        if ($errorResult !== null) return $errorResult;

        $data   = $resp['json'];
        $report = $data['data']['report'] ?? [];
        $bl     = $report['blacklists'] ?? [];
        $info   = $report['information'] ?? [];
        $anon   = $report['anonymity'] ?? [];

        $detections  = $bl['detection_rate'] ?? '0/0';
        $enginesUsed = $bl['engines_count'] ?? 0;
        $isp         = $info['isp'] ?? 'N/A';
        $country     = ($info['country_name'] ?? 'N/A') . ' (' . ($info['country_code'] ?? '') . ')';
        $city        = $info['city_name'] ?? 'N/A';
        $reverseDns  = $info['reverse_dns'] ?? 'N/A';
        $isProxy     = !empty($anon['is_proxy']);
        $isVpn       = !empty($anon['is_vpn']);
        $isTor       = !empty($anon['is_tor']);

        // Parse detection rate "X/Y" for scoring
        $hits = 0;
        $total = 0;
        if (is_string($detections) && str_contains($detections, '/')) {
            [$hits, $total] = array_map('intval', explode('/', $detections));
        }

        // Score based on detections
        $score = 0;
        if ($hits >= 5)      $score = 90;
        elseif ($hits >= 3)  $score = 70;
        elseif ($hits >= 1)  $score = 40;

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = $enginesUsed > 0 ? min(99, 60 + min(39, $hits * 10)) : 40;

        // Build summary
        $summary = "IP {$ip}: Detected by {$detections} blacklist engines. ISP: {$isp}, Country: {$country}.";
        if ($isProxy || $isVpn || $isTor) {
            $anonTypes = [];
            if ($isProxy) $anonTypes[] = 'Proxy';
            if ($isVpn)   $anonTypes[] = 'VPN';
            if ($isTor)   $anonTypes[] = 'Tor';
            $summary .= ' Anonymity: ' . implode(', ', $anonTypes) . '.';
        }

        // Build tags
        $tags = [self::API_ID, 'ip'];
        if ($hits > 0) $tags[] = 'blacklisted';
        if ($isProxy)  $tags[] = 'proxy';
        if ($isVpn)    $tags[] = 'vpn';
        if ($isTor)    $tags[] = 'tor';
        if ($hits === 0) $tags[] = 'clean';

        // Detected engine names
        $detectedEngines = [];
        if (!empty($bl['engines'])) {
            foreach ($bl['engines'] as $e) {
                if (!empty($e['detected'])) {
                    $detectedEngines[] = $e['engine'] ?? 'Unknown';
                }
            }
        }
        if (!empty($detectedEngines)) {
            $summary .= ' Detected by: ' . implode(', ', $detectedEngines) . '.';
        }

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary:    $summary,
            tags:       array_unique($tags),
            rawData:    $data,
            success:    true,
            dataType:   'IP Address'
        );
    }

    /**
     * Domain Reputation — checks a domain against blacklist engines.
     */
    private function queryDomainReputation(string $domain, string $key): OsintResult
    {
        $url  = self::BASE . '/domainbl/v1/pay-as-you-go/?key=' . urlencode($key) . '&host=' . urlencode($domain);
        $resp = HttpClient::get($url, [], 15);

        $errorResult = $this->checkErrors($resp, 'Domain Reputation');
        if ($errorResult !== null) return $errorResult;

        $data   = $resp['json'];
        $report = $data['data']['report'] ?? [];
        $bl     = $report['blacklists'] ?? [];
        $server = $report['server'] ?? [];

        $detections = $bl['detection_rate'] ?? '0/0';

        $hits = 0;
        if (is_string($detections) && str_contains($detections, '/')) {
            [$hits] = array_map('intval', explode('/', $detections));
        }

        $score = 0;
        if ($hits >= 5)      $score = 90;
        elseif ($hits >= 3)  $score = 70;
        elseif ($hits >= 1)  $score = 40;

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 60 + min(39, $hits * 10);

        $serverIp   = $server['ip'] ?? 'N/A';
        $serverCtry = $server['country_name'] ?? 'N/A';
        $serverIsp  = $server['isp'] ?? 'N/A';

        $summary = "Domain {$domain}: Detected by {$detections} blacklist engines. Server IP: {$serverIp}, Country: {$serverCtry}, ISP: {$serverIsp}.";

        $tags = [self::API_ID, 'domain'];
        if ($hits > 0)  $tags[] = 'blacklisted';
        if ($hits === 0) $tags[] = 'clean';

        // Detected engine names
        if (!empty($bl['engines'])) {
            $detected = array_filter($bl['engines'], fn($e) => !empty($e['detected']));
            if ($detected) {
                $names = array_map(fn($e) => $e['engine'] ?? 'Unknown', $detected);
                $summary .= ' Detected by: ' . implode(', ', $names) . '.';
            }
        }

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary:    $summary,
            tags:       array_unique($tags),
            rawData:    $data,
            success:    true,
            dataType:   'Internet Name'
        );
    }

    /**
     * URL Reputation — checks a URL for malware, phishing, and suspicious content.
     */
    private function queryUrlReputation(string $targetUrl, string $key): OsintResult
    {
        $url  = self::BASE . '/urlrep/v1/pay-as-you-go/?key=' . urlencode($key) . '&url=' . urlencode($targetUrl);
        $resp = HttpClient::get($url, [], 20);

        $errorResult = $this->checkErrors($resp, 'URL Reputation');
        if ($errorResult !== null) return $errorResult;

        $data      = $resp['json'];
        $report    = $data['data']['report'] ?? [];
        $riskScore = $report['risk_score']['result'] ?? 0;
        $suspicious = !empty($report['is_suspicious']);

        $score = min((int)$riskScore, 100);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 65;

        $responseCode = $report['response_headers']['code'] ?? 'N/A';
        $server       = $report['response_headers']['server'] ?? 'N/A';

        $summary = "URL risk score: {$riskScore}/100. Suspicious: " . ($suspicious ? 'Yes' : 'No') . ". HTTP response: {$responseCode}, Server: {$server}.";

        $tags = [self::API_ID, 'url'];
        if ($suspicious) $tags[] = 'suspicious';
        if ($score >= 70) $tags[] = 'malicious';
        if ($score === 0) $tags[] = 'clean';

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary:    $summary,
            tags:       array_unique($tags),
            rawData:    $data,
            success:    true,
            dataType:   $score >= 70 ? 'Malicious URL' : 'Linked URL - Internal'
        );
    }

    /**
     * Email Verify — validates an email address and checks for disposable/free providers.
     */
    private function queryEmailVerify(string $email, string $key): OsintResult
    {
        $url  = self::BASE . '/emailverify/v1/pay-as-you-go/?key=' . urlencode($key) . '&email=' . urlencode($email);
        $resp = HttpClient::get($url, [], 15);

        $errorResult = $this->checkErrors($resp, 'Email Verify');
        if ($errorResult !== null) return $errorResult;

        $data = $resp['json'];
        $d    = $data['data'] ?? [];

        $isDisposable  = !empty($d['is_disposable']);
        $isSuspicious  = !empty($d['is_suspicious_domain']);
        $isBlacklisted = !empty($d['is_domain_blacklisted']);
        $validFormat   = !empty($d['valid_format']);
        $hasMx         = !empty($d['has_mx_records']);
        $isFree        = !empty($d['is_free']);
        $domainAge     = $d['domain_age_in_days'] ?? 'N/A';

        $score = 0;
        if ($isDisposable)  $score += 30;
        if ($isSuspicious)  $score += 40;
        if ($isBlacklisted) $score += 50;
        $score = min($score, 100);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 70;

        $summary = "Email {$email}: Format " . ($validFormat ? 'valid' : 'invalid') . ". MX records: " . ($hasMx ? 'found' : 'none') . ".";
        if ($isDisposable)  $summary .= ' Disposable provider detected.';
        if ($isSuspicious)  $summary .= ' Suspicious domain.';
        if ($isBlacklisted) $summary .= ' Domain is blacklisted.';
        if ($isFree)        $summary .= ' Free email provider.';
        $summary .= " Domain age: {$domainAge} days.";

        $tags = [self::API_ID, 'email'];
        if ($isDisposable)  $tags[] = 'disposable';
        if ($isSuspicious)  $tags[] = 'suspicious';
        if ($isBlacklisted) $tags[] = 'blacklisted';
        if ($isFree)        $tags[] = 'free_provider';
        if ($score === 0)   $tags[] = 'clean';

        return new OsintResult(
            api:        self::API_ID,
            apiName:    self::API_NAME,
            score:      $score,
            severity:   $severity,
            confidence: $confidence,
            responseMs: $resp['elapsed_ms'],
            summary:    $summary,
            tags:       array_unique($tags),
            rawData:    $data,
            success:    true,
            dataType:   'Email Address'
        );
    }

    /**
     * Check for HTTP/API errors and return an OsintResult or null if OK.
     */
    private function checkErrors(array $resp, string $endpoint): ?OsintResult
    {
        if ($resp['status'] === 0 || !empty($resp['error'])) {
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) {
            return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 401 || $resp['status'] === 403) {
            return OsintResult::unauthorized(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        }
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']} from {$endpoint}", $resp['elapsed_ms']);
        }

        // Check for API-level errors in the JSON response
        $json = $resp['json'];
        if (!$json) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Invalid response from {$endpoint}", $resp['elapsed_ms']);
        }
        if (!empty($json['error'])) {
            return OsintResult::error(self::API_ID, self::API_NAME, $json['error'], $resp['elapsed_ms']);
        }

        return null; // No errors
    }

    /**
     * Health check: query the IP reputation endpoint with 8.8.8.8.
     */
    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $url  = self::BASE . '/iprep/v1/pay-as-you-go/?key=' . urlencode($apiKey) . '&ip=8.8.8.8';
        $resp = HttpClient::get($url, [], 10);

        $latency = $resp['elapsed_ms'] ?? 0;

        if ($resp['status'] === 200 && $resp['json'] !== null && empty($resp['json']['error'])) {
            return ['status' => 'healthy', 'latency_ms' => $latency, 'error' => null];
        }

        $error = $resp['error'] ?? '';
        if (!$error && $resp['json'] && !empty($resp['json']['error'])) {
            $error = $resp['json']['error'];
        }
        if (!$error) {
            $error = "HTTP {$resp['status']}";
        }

        return ['status' => 'down', 'latency_ms' => $latency, 'error' => $error];
    }
}

require_once __DIR__ . '/BaseApiModule.php';