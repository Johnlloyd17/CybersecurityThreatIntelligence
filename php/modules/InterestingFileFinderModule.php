<?php
// =============================================================================
//  CTI — Interesting File Finder Module
//  Checks for common interesting/sensitive paths on a web server.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class InterestingFileFinderModule extends BaseApiModule
{
    private const API_ID   = 'interesting-file-finder';
    private const API_NAME = 'Interesting File Finder';
    private const SUPPORTED = ['domain', 'url'];

    /** Paths to check: path => [description, severity_weight] */
    private const PATHS = [
        '/robots.txt'          => ['Robots.txt', 5],
        '/sitemap.xml'         => ['Sitemap', 5],
        '/.git/HEAD'           => ['Git repository exposed', 90],
        '/.git/config'         => ['Git config exposed', 90],
        '/.env'                => ['Environment file exposed', 95],
        '/.htaccess'           => ['htaccess file', 30],
        '/.htpasswd'           => ['htpasswd file exposed', 90],
        '/wp-config.php.bak'   => ['WordPress config backup', 95],
        '/wp-config.php~'      => ['WordPress config backup', 95],
        '/web.config'          => ['IIS web.config', 40],
        '/crossdomain.xml'     => ['Flash cross-domain policy', 20],
        '/clientaccesspolicy.xml' => ['Silverlight access policy', 20],
        '/security.txt'        => ['Security.txt', 5],
        '/.well-known/security.txt' => ['Security.txt (well-known)', 5],
        '/phpinfo.php'         => ['PHP info page', 70],
        '/info.php'            => ['PHP info page', 70],
        '/server-status'       => ['Apache server-status', 60],
        '/server-info'         => ['Apache server-info', 60],
        '/.svn/entries'        => ['SVN repository exposed', 80],
        '/.DS_Store'           => ['macOS DS_Store file', 30],
        '/Thumbs.db'           => ['Windows Thumbs.db', 15],
        '/backup.sql'          => ['SQL backup file', 95],
        '/database.sql'        => ['SQL database file', 95],
        '/dump.sql'            => ['SQL dump file', 95],
        '/config.php.bak'      => ['Config backup file', 80],
        '/readme.html'         => ['Readme file (CMS version)', 15],
        '/license.txt'         => ['License file', 5],
        '/CHANGELOG.md'        => ['Changelog file', 10],
        '/composer.json'       => ['Composer dependencies', 25],
        '/package.json'        => ['NPM package file', 25],
        '/Gruntfile.js'        => ['Grunt build file', 20],
        '/Gulpfile.js'         => ['Gulp build file', 20],
        '/Makefile'            => ['Makefile', 15],
        '/Dockerfile'          => ['Dockerfile', 30],
        '/docker-compose.yml'  => ['Docker Compose', 35],
        '/.dockerenv'          => ['Docker environment', 40],
        '/elmah.axd'           => ['ELMAH error log', 60],
        '/trace.axd'           => ['ASP.NET trace', 60],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $timeBudget = 25; // seconds — break out of curl_multi if exceeded

        $targetUrl = $queryValue;
        if ($queryType === 'domain') {
            $targetUrl = "https://{$queryValue}";
        }
        if (!preg_match('#^https?://#i', $targetUrl)) {
            $targetUrl = "https://{$targetUrl}";
        }
        $targetUrl = rtrim($targetUrl, '/');

        $found = [];
        $checked = 0;
        $maxScore = 0;

        // Build all curl handles up-front for parallel execution
        $mh = curl_multi_init();
        $handleMap = []; // int-cast id => ['ch' => CurlHandle, 'path' => string]

        foreach (self::PATHS as $path => $info) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $targetUrl . $path,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            ]);
            curl_multi_add_handle($mh, $ch);
            $handleMap[(int)$ch] = ['ch' => $ch, 'path' => $path];
        }

        // Execute all requests in parallel with a time budget
        $active = null;
        do {
            $status = curl_multi_exec($mh, $active);
            if ($status > CURLM_OK) {
                break; // curl_multi error
            }

            // Process completed handles as they finish
            while ($done = curl_multi_info_read($mh)) {
                $ch   = $done['handle'];
                $entry = $handleMap[(int)$ch];
                $path  = $entry['path'];
                $checked++;

                $httpCode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);

                if ($httpCode === 200) {
                    $respBody = curl_multi_getcontent($ch);
                    $bodyLen  = is_string($respBody) ? strlen($respBody) : 0;

                    if ($bodyLen > 0 && $bodyLen < 5242880) { // < 5MB
                        $pathInfo = self::PATHS[$path];
                        $weight   = $pathInfo[1];
                        $maxScore = max($maxScore, $weight);
                        $found[]  = [
                            'path'            => $path,
                            'description'     => $pathInfo[0],
                            'severity_weight' => $weight,
                            'http_status'     => $httpCode,
                            'size'            => $bodyLen,
                        ];
                    }
                }

                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($handleMap[(int)$ch]);
            }

            // Enforce time budget
            if ((microtime(true) - $start) >= $timeBudget) {
                break;
            }

            // Wait for activity (max 200 ms) to avoid busy-loop
            if ($active > 0) {
                curl_multi_select($mh, 0.2);
            }
        } while ($active > 0);

        // Clean up any handles still in flight after time budget exceeded
        foreach ($handleMap as $entry) {
            curl_multi_remove_handle($mh, $entry['ch']);
            curl_close($entry['ch']);
        }
        curl_multi_close($mh);

        // Count timed-out / still-in-flight paths as checked
        $checked += count($handleMap);

        $ms = (int)((microtime(true) - $start) * 1000);
        $foundCount = count($found);
        $displayName = $queryType === 'domain' ? $queryValue : $targetUrl;

        if ($foundCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 70,
                responseMs: $ms,
                summary: "{$displayName}: No interesting files found among {$checked} paths checked.",
                tags: [self::API_ID, $queryType, 'clean'],
                rawData: ['found' => [], 'checked' => $checked],
                success: true
            );
        }

        // Separate by risk
        $critical = array_filter($found, function($f) { return $f['severity_weight'] >= 70; });
        $moderate = array_filter($found, function($f) { return $f['severity_weight'] >= 20 && $f['severity_weight'] < 70; });
        $info = array_filter($found, function($f) { return $f['severity_weight'] < 20; });

        $parts = ["{$displayName}: {$foundCount} interesting file(s) found"];
        if (!empty($critical)) {
            $critNames = array_map(function($f) { return $f['path'] . ' (' . $f['description'] . ')'; }, $critical);
            $parts[] = "CRITICAL: " . implode(', ', $critNames);
        }
        if (!empty($moderate)) {
            $modNames = array_map(function($f) { return $f['path']; }, $moderate);
            $parts[] = "Moderate: " . implode(', ', $modNames);
        }
        $infoCount = count($info);
        if ($infoCount > 0) {
            $parts[] = "{$infoCount} informational file(s)";
        }

        $score = min(95, $maxScore);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = 80;
        $tags = [self::API_ID, $queryType, 'interesting_files'];
        if (!empty($critical)) {
            $tags[] = 'sensitive_exposure';
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms, summary: implode('. ', $parts) . '.',
            tags: array_values(array_unique($tags)),
            rawData: [
                'found' => $found,
                'found_count' => $foundCount,
                'checked' => $checked,
                'critical_count' => count($critical),
                'moderate_count' => count($moderate),
                'info_count' => $infoCount,
            ],
            success: true
        );
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $r = HttpClient::get('https://www.google.com/robots.txt', [], 5);
        $ms = (int)((microtime(true) - $start) * 1000);
        if ($r['status'] === 200) {
            return ['status' => 'healthy', 'latency_ms' => $ms, 'error' => null];
        }
        $err = $r['error'] ? $r['error'] : 'HTTP ' . $r['status'];
        return ['status' => 'down', 'latency_ms' => $ms, 'error' => $err];
    }
}
