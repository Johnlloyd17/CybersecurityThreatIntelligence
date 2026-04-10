<?php
// =============================================================================
//  CTI — Junk File Finder Module
//  Probes for common exposed/leftover files on web servers.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class JunkFileFinderModule extends BaseApiModule
{
    private const API_ID   = 'junk-file-finder';
    private const API_NAME = 'Junk File Finder';
    private const SUPPORTED = ['domain', 'url'];

    private const PROBE_PATHS = [
        '/.env'              => ['risk' => 'critical', 'desc' => 'Environment configuration file'],
        '/.git/config'       => ['risk' => 'critical', 'desc' => 'Git repository configuration'],
        '/.git/HEAD'         => ['risk' => 'critical', 'desc' => 'Git HEAD reference'],
        '/wp-config.php.bak' => ['risk' => 'critical', 'desc' => 'WordPress config backup'],
        '/.htaccess'         => ['risk' => 'high',     'desc' => 'Apache configuration file'],
        '/backup.sql'        => ['risk' => 'critical', 'desc' => 'SQL database backup'],
        '/debug.log'         => ['risk' => 'high',     'desc' => 'Debug log file'],
        '/phpinfo.php'       => ['risk' => 'high',     'desc' => 'PHP info page'],
        '/.DS_Store'         => ['risk' => 'medium',   'desc' => 'macOS directory listing'],
        '/web.config'        => ['risk' => 'medium',   'desc' => 'IIS configuration file'],
        '/.htpasswd'         => ['risk' => 'critical', 'desc' => 'Apache password file'],
        '/server-status'     => ['risk' => 'high',     'desc' => 'Apache server status'],
        '/config.php.bak'    => ['risk' => 'critical', 'desc' => 'Config backup file'],
        '/database.sql'      => ['risk' => 'critical', 'desc' => 'Database dump file'],
        '/dump.sql'          => ['risk' => 'critical', 'desc' => 'Database dump file'],
        '/.svn/entries'      => ['risk' => 'high',     'desc' => 'SVN repository data'],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);

        $targetBase = $value;
        if ($queryType === 'domain') {
            $targetBase = 'https://' . $value;
        }
        if (!preg_match('#^https?://#i', $targetBase)) {
            $targetBase = 'https://' . $targetBase;
        }
        $targetBase = rtrim($targetBase, '/');

        try {
            $exposed = [];
            $checked = 0;

            foreach (self::PROBE_PATHS as $path => $info) {
                $probeUrl = $targetBase . $path;
                $resp = HttpClient::get($probeUrl, [], 5, 0);
                $checked++;

                $status = $resp['status'];

                // Consider 200 as exposed; also check body isn't a generic error page
                if ($status === 200 && !$resp['error']) {
                    $bodyLen = strlen($resp['body']);
                    // Skip very small responses that might be empty/error pages
                    if ($bodyLen < 5) {
                        continue;
                    }
                    // Skip if it looks like a custom 404 page
                    $bodyLower = strtolower($resp['body']);
                    if (strpos($bodyLower, 'not found') !== false || strpos($bodyLower, '404') !== false) {
                        continue;
                    }

                    $exposed[] = [
                        'path'        => $path,
                        'status'      => $status,
                        'size'        => $bodyLen,
                        'risk'        => $info['risk'],
                        'description' => $info['desc'],
                    ];
                }
            }

            $ms = (int)((microtime(true) - $start) * 1000);
            $exposedCount = count($exposed);

            if ($exposedCount === 0) {
                return new OsintResult(
                    api: self::API_ID, apiName: self::API_NAME,
                    score: 0, severity: 'info', confidence: 70,
                    responseMs: $ms,
                    summary: "No exposed junk files found ({$checked} paths checked).",
                    tags: [self::API_ID, $queryType, 'clean'],
                    rawData: ['checked' => $checked, 'exposed' => []],
                    success: true
                );
            }

            // Score based on highest risk found
            $maxScore = 0;
            foreach ($exposed as $item) {
                switch ($item['risk']) {
                    case 'critical': $maxScore = max($maxScore, 90); break;
                    case 'high':     $maxScore = max($maxScore, 70); break;
                    case 'medium':   $maxScore = max($maxScore, 45); break;
                    default:         $maxScore = max($maxScore, 20); break;
                }
            }

            $severity = OsintResult::scoreToSeverity($maxScore);
            $fileList = array_map(function ($f) { return $f['path']; }, $exposed);
            $fileListStr = implode(', ', $fileList);

            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: $maxScore, severity: $severity, confidence: 85,
                responseMs: $ms,
                summary: "{$exposedCount} exposed file(s) found: {$fileListStr}.",
                tags: array_values(array_unique([self::API_ID, $queryType, 'exposed_files', 'misconfiguration'])),
                rawData: ['checked' => $checked, 'exposed' => $exposed],
                success: true
            );
        } catch (\Throwable $e) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return OsintResult::error(self::API_ID, self::API_NAME, $e->getMessage(), $ms);
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null];
    }
}
