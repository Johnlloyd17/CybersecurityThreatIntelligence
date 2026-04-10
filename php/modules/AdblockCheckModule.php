<?php
require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';

class AdblockCheckModule extends BaseApiModule
{
    private const EASYLIST_URL = 'https://easylist.to/easylist/easylist.txt';

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        $target = $queryValue;
        $resp = HttpClient::get(self::EASYLIST_URL, [], 15);

        if ($resp['error'] || $resp['status'] !== 200) {
            return OsintResult::error('adblock-check', 'Adblock Check', 'Failed to fetch EasyList: ' . ($resp['error'] ?: "HTTP {$resp['status']}"));
        }

        $lines = explode("\n", $resp['body']);
        $matches = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '!' || $line[0] === '[') continue;
            if (stripos($line, $target) !== false) {
                $matches[] = $line;
                if (count($matches) >= 20) break;
            }
        }

        $found = count($matches);
        $score = $found > 0 ? min(30 + $found * 5, 70) : 0;

        return new OsintResult(
            api:        'adblock-check',
            apiName:    'Adblock Check',
            score:      $score,
            severity:   OsintResult::scoreToSeverity($score),
            confidence: $found > 0 ? 80 : 90,
            responseMs: $resp['elapsed_ms'],
            summary:    $found > 0
                ? "{$target} found in {$found} EasyList filter rule(s). Domain may serve ads or tracking content."
                : "{$target} not found in EasyList filters. No ad/tracking associations detected.",
            tags:       $found > 0 ? ['adblock', 'tracking', 'ads'] : ['adblock', 'clean'],
            rawData:    ['matches' => $matches, 'total_rules_checked' => count($lines)],
            success:    true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $resp = HttpClient::get(self::EASYLIST_URL, [], 10);
        $ms = round((microtime(true) - $start) * 1000);
        return [
            'status' => $resp['status'] === 200 ? 'up' : 'down',
            'latency_ms' => $ms,
            'error' => $resp['error'],
        ];
    }
}

require_once __DIR__ . '/BaseApiModule.php';