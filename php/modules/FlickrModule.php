<?php
// =============================================================================
//  CTI — Flickr Module
//  API Docs: https://www.flickr.com/services/api/
//  Free, no API key needed for basic search. Supports: username, email
//  Endpoint: https://api.flickr.com/services/rest/?method=flickr.people.findByUsername
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class FlickrModule extends BaseApiModule
{
    private const API_ID   = 'flickr';
    private const API_NAME = 'Flickr';
    private const SUPPORTED = ['username', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.flickr.com/services/rest', '/');

        // Use API key if provided, otherwise try without
        $keyParam = $apiKey ? "&api_key=" . urlencode($apiKey) : '';

        if ($queryType === 'username') {
            $method = 'flickr.people.findByUsername';
            $param  = '&username=' . urlencode($queryValue);
        } else {
            $method = 'flickr.people.findByEmail';
            $param  = '&find_email=' . urlencode($queryValue);
        }

        $endpoint = "{$baseUrl}/?method={$method}{$param}&format=json&nojsoncallback=1{$keyParam}";

        $resp = HttpClient::get($endpoint, [], 15);

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

        $stat = isset($data['stat']) ? $data['stat'] : '';
        if ($stat === 'fail') {
            $code = isset($data['code']) ? (int)$data['code'] : 0;
            $message = isset($data['message']) ? $data['message'] : 'Unknown error';
            if ($code === 1) {
                // User not found
                return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
            }
            return OsintResult::error(self::API_ID, self::API_NAME, $message, $resp['elapsed_ms']);
        }

        return $this->parse($data, $queryType, $queryValue, $resp['elapsed_ms'], $baseUrl, $keyParam);
    }

    private function parse(array $data, string $type, string $value, int $ms, string $baseUrl, string $keyParam): OsintResult
    {
        $user   = isset($data['user']) ? $data['user'] : [];
        $nsid   = isset($user['nsid']) ? $user['nsid'] : '';
        $uname  = isset($user['username']) ? $user['username'] : [];
        $username = isset($uname['_content']) ? $uname['_content'] : $value;

        // Try to get more info if we have an nsid
        $photoCount = 0;
        $realname = '';
        $location = '';
        if ($nsid && $keyParam) {
            $infoEndpoint = "{$baseUrl}/?method=flickr.people.getInfo&user_id=" . urlencode($nsid) . "&format=json&nojsoncallback=1{$keyParam}";
            $infoResp = HttpClient::get($infoEndpoint, [], 10);
            if ($infoResp['json']) {
                $person = isset($infoResp['json']['person']) ? $infoResp['json']['person'] : [];
                $photos = isset($person['photos']) ? $person['photos'] : [];
                $photoCount = isset($photos['count']) ? (int)(isset($photos['count']['_content']) ? $photos['count']['_content'] : 0) : 0;
                $rnData = isset($person['realname']) ? $person['realname'] : [];
                $realname = isset($rnData['_content']) ? $rnData['_content'] : '';
                $locData = isset($person['location']) ? $person['location'] : [];
                $location = isset($locData['_content']) ? $locData['_content'] : '';
            }
        }

        // Informational score
        $score      = min(20, 5 + (int)($photoCount / 50));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 85;

        $label = ($type === 'email') ? "Email {$value}" : "Username {$value}";
        $parts = [];
        $parts[] = "{$label} — Flickr account found: {$username}";
        if ($nsid) $parts[] = "NSID: {$nsid}";
        if ($realname) $parts[] = "Real name: {$realname}";
        if ($location) $parts[] = "Location: {$location}";
        if ($photoCount > 0) $parts[] = "{$photoCount} photo(s)";

        $tags = [self::API_ID, $type, 'osint', 'profile'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $keyParam = $apiKey ? "&api_key=" . urlencode($apiKey) : '';
        $url = "https://api.flickr.com/services/rest/?method=flickr.people.findByUsername&username=test&format=json&nojsoncallback=1{$keyParam}";
        $resp = HttpClient::get($url, [], 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
