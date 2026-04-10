<?php
// =============================================================================
//  CTI — GitHub OSINT Module
//  API Docs: https://docs.github.com/en/rest
//  Free (unauthenticated). Supports: username, email
//  Endpoint: https://api.github.com/users/{username} or /search/users?q={email}
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class GithubOsintModule extends BaseApiModule
{
    private const API_ID   = 'github';
    private const API_NAME = 'GitHub OSINT';
    private const SUPPORTED = ['username', 'email'];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $baseUrl = rtrim($baseUrl ?: 'https://api.github.com', '/');

        $headers = ['Accept' => 'application/vnd.github.v3+json'];
        if ($apiKey) {
            $headers['Authorization'] = "token {$apiKey}";
        }

        if ($queryType === 'username') {
            return $this->queryUser($baseUrl, $queryValue, $headers);
        } else {
            return $this->queryEmail($baseUrl, $queryValue, $headers);
        }
    }

    private function queryUser(string $baseUrl, string $username, array $headers): OsintResult
    {
        // Fetch user profile
        $resp = HttpClient::get("{$baseUrl}/users/" . urlencode($username), $headers, 15);

        if ($resp['error'] || $resp['status'] === 0) {
            $err = $resp['error'] ? $resp['error'] : 'Connection failed';
            return OsintResult::error(self::API_ID, self::API_NAME, $err, $resp['elapsed_ms']);
        }
        if ($resp['status'] === 429) return OsintResult::rateLimited(self::API_ID, self::API_NAME, $resp['elapsed_ms']);
        if ($resp['status'] === 404) return OsintResult::notFound(self::API_ID, self::API_NAME, $username, $resp['elapsed_ms']);
        if ($resp['status'] !== 200) {
            return OsintResult::error(self::API_ID, self::API_NAME, "HTTP {$resp['status']}", $resp['elapsed_ms']);
        }

        $user = $resp['json'];
        if (!$user) return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid JSON response', $resp['elapsed_ms']);

        // Also fetch repos
        $repoResp = HttpClient::get("{$baseUrl}/users/" . urlencode($username) . "/repos?per_page=5&sort=updated", $headers, 10);
        $repos = ($repoResp['json'] && is_array($repoResp['json'])) ? $repoResp['json'] : [];

        return $this->parseUser($user, $repos, $resp['elapsed_ms']);
    }

    private function queryEmail(string $baseUrl, string $email, array $headers): OsintResult
    {
        $endpoint = "{$baseUrl}/search/users?q=" . urlencode($email) . "+in:email";
        $resp = HttpClient::get($endpoint, $headers, 15);

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

        $totalCount = isset($data['total_count']) ? (int)$data['total_count'] : 0;
        $items = isset($data['items']) ? $data['items'] : [];

        if ($totalCount === 0) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $email, $resp['elapsed_ms']);
        }

        $parts = [];
        $parts[] = "Email {$email} — {$totalCount} GitHub account(s) found";
        foreach (array_slice($items, 0, 3) as $item) {
            $login = isset($item['login']) ? $item['login'] : 'unknown';
            $parts[] = "Account: {$login}";
        }

        $score      = min(30, $totalCount * 10);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(99, 60 + $totalCount * 10);

        $tags = [self::API_ID, 'email', 'osint'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $resp['elapsed_ms'], summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $data, success: true
        );
    }

    private function parseUser(array $user, array $repos, int $ms): OsintResult
    {
        $login      = isset($user['login']) ? $user['login'] : 'unknown';
        $name       = isset($user['name']) ? $user['name'] : '';
        $publicRepos = isset($user['public_repos']) ? (int)$user['public_repos'] : 0;
        $followers  = isset($user['followers']) ? (int)$user['followers'] : 0;
        $following  = isset($user['following']) ? (int)$user['following'] : 0;
        $bio        = isset($user['bio']) ? $user['bio'] : '';
        $company    = isset($user['company']) ? $user['company'] : '';
        $location   = isset($user['location']) ? $user['location'] : '';
        $createdAt  = isset($user['created_at']) ? $user['created_at'] : '';

        // Informational score, not threat-based
        $score = min(25, 5 + (int)($publicRepos / 5) + (int)($followers / 10));
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 90;

        $parts = [];
        $parts[] = "GitHub user {$login}";
        if ($name) $parts[] = "Name: {$name}";
        $parts[] = "{$publicRepos} public repo(s), {$followers} follower(s)";
        if ($company) $parts[] = "Company: {$company}";
        if ($location) $parts[] = "Location: {$location}";
        if ($createdAt) $parts[] = "Joined: {$createdAt}";

        // Recent repos
        if (count($repos) > 0) {
            $repoNames = [];
            foreach (array_slice($repos, 0, 3) as $r) {
                $rName = isset($r['name']) ? $r['name'] : '';
                if ($rName) $repoNames[] = $rName;
            }
            if (count($repoNames) > 0) {
                $parts[] = "Recent repos: " . implode(', ', $repoNames);
            }
        }

        $tags = [self::API_ID, 'username', 'osint', 'profile'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)), rawData: $user, success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $headers = ['Accept' => 'application/vnd.github.v3+json'];
        if ($apiKey) {
            $headers['Authorization'] = "token {$apiKey}";
        }
        $resp = HttpClient::get('https://api.github.com/users/octocat', $headers, 10);
        if ($resp['error'] || $resp['status'] === 0) return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => $resp['error']];
        if ($resp['status'] === 200) return ['status' => 'healthy', 'latency_ms' => $resp['elapsed_ms'], 'error' => null];
        return ['status' => 'down', 'latency_ms' => $resp['elapsed_ms'], 'error' => "HTTP {$resp['status']}"];
    }
}
