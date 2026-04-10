<?php
// =============================================================================
//  CTI — Web Spider Module (Expanded)
//  Multi-level recursive web crawler with configurable depth, deduplication,
//  form detection, comment extraction, technology fingerprinting, sensitive
//  path discovery, and email/subdomain harvesting.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class WebSpiderModule extends BaseApiModule
{
    private const API_ID   = 'web-spider';
    private const API_NAME = 'Web Spider';
    private const SUPPORTED = ['domain', 'url'];

    private const MAX_DEPTH     = 3;
    private const MAX_PAGES     = 50;
    private const MAX_LINK_LOG  = 200;

    private const INTERESTING_PATTERNS = [
        'login'     => '/login|signin|sign-in|log-in|auth|sso/i',
        'admin'     => '/admin|administrator|dashboard|panel|manage|backend|cpanel/i',
        'api'       => '/\/api\/|\/api\.|\/graphql|\/swagger|\/openapi|\/v[12]\/|\/rest\//i',
        'upload'    => '/upload|file-upload|attach|dropzone/i',
        'config'    => '/config|settings|setup|install|\.env|\.ini|\.conf/i',
        'backup'    => '/backup|dump|export|download|\.bak|\.sql|\.tar|\.zip/i',
        'debug'     => '/debug|trace|test|dev|staging|phpinfo|\.log/i',
        'database'  => '/phpmyadmin|adminer|db|database|mysql|pgadmin|mongo/i',
        'git'       => '/\.git|\.svn|\.hg|\.bzr/i',
        'ci_cd'     => '/jenkins|gitlab-ci|travis|circleci|\.github/i',
        'docs'      => '/swagger-ui|redoc|api-docs|graphiql|playground/i',
        'user_data' => '/profile|account|user|member|password|reset/i',
    ];

    // Sensitive file probes (checked alongside crawled links)
    private const SENSITIVE_PROBES = [
        '/.env', '/.git/config', '/.git/HEAD', '/robots.txt', '/sitemap.xml',
        '/.well-known/security.txt', '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/server-status', '/server-info', '/wp-config.php.bak', '/web.config',
        '/.htaccess', '/.htpasswd', '/phpinfo.php', '/info.php', '/test.php',
        '/config.php.bak', '/database.yml', '/Gruntfile.js', '/package.json',
        '/composer.json', '/Gemfile', '/requirements.txt', '/Dockerfile',
        '/docker-compose.yml', '/.dockerenv', '/.aws/credentials',
        '/backup.sql', '/dump.sql', '/db.sql', '/.DS_Store',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $start = microtime(true);
        $value = trim($queryValue);

        $targetUrl = $value;
        if ($queryType === 'domain') $targetUrl = 'https://' . $value;
        if (!preg_match('#^https?://#i', $targetUrl)) $targetUrl = 'https://' . $targetUrl;
        $targetUrl = rtrim($targetUrl, '/');

        $parsed   = parse_url($targetUrl);
        $baseHost = strtolower($parsed['host'] ?? $value);
        $baseScheme = $parsed['scheme'] ?? 'https';

        $maxDepth = min(self::MAX_DEPTH, $this->int('spider_depth', 2));
        $maxPages = min(self::MAX_PAGES, $this->int('spider_max_pages', 30));

        // ── BFS Crawl ─────────────────────────────────────────────────────
        $visited   = [];
        $queue     = [['url' => $targetUrl, 'depth' => 0]];
        $allInternal  = [];
        $allExternal  = [];
        $interesting  = [];
        $emails       = [];
        $subdomains   = [];
        $forms        = [];
        $comments     = [];
        $technologies = [];
        $statusCodes  = [];
        $pagesCrawled = 0;

        while (!empty($queue) && $pagesCrawled < $maxPages) {
            $item = array_shift($queue);
            $url   = $item['url'];
            $depth = $item['depth'];

            $normalUrl = $this->normalizeUrl($url);
            if (isset($visited[$normalUrl])) continue;
            $visited[$normalUrl] = true;

            $resp = HttpClient::get($url, ['User-Agent: Mozilla/5.0 (compatible; CTI-Spider/1.0)'], 10, 0);
            if ($resp['error'] || ($resp['status'] ?? 0) >= 400) {
                $statusCodes[$url] = $resp['status'] ?? 0;
                continue;
            }

            $statusCodes[$url] = $resp['status'] ?? 200;
            $pagesCrawled++;
            $body = $resp['body'] ?? '';

            // Extract links
            $links = [];
            if (preg_match_all('/href\s*=\s*["\']([^"\'#]+)/i', $body, $hrefM)) {
                $links = array_merge($links, $hrefM[1]);
            }
            if (preg_match_all('/src\s*=\s*["\']([^"\']+)/i', $body, $srcM)) {
                $links = array_merge($links, $srcM[1]);
            }

            foreach (array_unique($links) as $link) {
                $link = trim($link);
                if (empty($link) || strpos($link, 'javascript:') === 0 || strpos($link, 'data:') === 0) continue;
                if (strpos($link, 'mailto:') === 0) {
                    $email = str_ireplace('mailto:', '', $link);
                    $email = strtok($email, '?');
                    if (filter_var($email, FILTER_VALIDATE_EMAIL)) $emails[$email] = true;
                    continue;
                }
                if (strpos($link, 'tel:') === 0) continue;

                $resolved = $this->resolveUrl($link, $baseScheme, $baseHost, $url);
                if (!$resolved) continue;

                $linkParsed = parse_url($resolved);
                $linkHost = strtolower($linkParsed['host'] ?? '');

                $isInternal = ($linkHost === $baseHost
                    || $linkHost === 'www.' . $baseHost
                    || 'www.' . $linkHost === $baseHost
                    || str_ends_with($linkHost, '.' . $baseHost));

                if ($isInternal) {
                    $allInternal[$resolved] = true;
                    // Track subdomains
                    if ($linkHost !== $baseHost && $linkHost !== 'www.' . $baseHost) {
                        $subdomains[$linkHost] = true;
                    }
                    // Queue for further crawling
                    if ($depth < $maxDepth && !isset($visited[$this->normalizeUrl($resolved)])) {
                        // Only crawl HTML pages
                        if (!preg_match('/\.(jpg|jpeg|png|gif|svg|ico|css|js|woff|woff2|ttf|eot|pdf|zip|tar|gz|mp[34]|avi|mov)$/i', $resolved)) {
                            $queue[] = ['url' => $resolved, 'depth' => $depth + 1];
                        }
                    }
                } else {
                    $allExternal[$resolved] = true;
                }

                // Check interesting patterns
                foreach (self::INTERESTING_PATTERNS as $category => $pattern) {
                    if (preg_match($pattern, $resolved)) {
                        $interesting[] = ['url' => $resolved, 'category' => $category, 'depth' => $depth];
                        break;
                    }
                }
            }

            // Extract emails from body
            if (preg_match_all('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/i', $body, $emailM)) {
                foreach ($emailM[0] as $em) {
                    if (filter_var($em, FILTER_VALIDATE_EMAIL)) $emails[$em] = true;
                }
            }

            // Extract forms
            if (preg_match_all('/<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\']?/i', $body, $formM, PREG_SET_ORDER)) {
                foreach ($formM as $fm) {
                    $forms[] = ['action' => $fm[1], 'method' => strtoupper($fm[2] ?? 'GET'), 'page' => $url];
                }
            } elseif (preg_match_all('/<form[^>]*>/i', $body, $formSimple)) {
                foreach ($formSimple[0] as $fs) {
                    $forms[] = ['action' => '(inline)', 'method' => 'unknown', 'page' => $url];
                }
            }

            // Extract HTML comments (may leak info)
            if (preg_match_all('/<!--(.*?)-->/s', $body, $commentM)) {
                foreach ($commentM[1] as $cm) {
                    $cm = trim($cm);
                    if (strlen($cm) > 10 && strlen($cm) < 500) {
                        // Filter out conditional comments and whitespace
                        if (!preg_match('/^\[if\s/i', $cm) && preg_match('/[a-z]/i', $cm)) {
                            $comments[] = ['comment' => substr($cm, 0, 200), 'page' => $url];
                        }
                    }
                }
            }
        }

        // ── Sensitive file probing ────────────────────────────────────────
        $sensitiveFindings = [];
        $probeBatch = array_slice(self::SENSITIVE_PROBES, 0, 20);
        foreach ($probeBatch as $probe) {
            $probeUrl = "{$baseScheme}://{$baseHost}{$probe}";
            if (isset($visited[$this->normalizeUrl($probeUrl)])) continue;

            $probeResp = HttpClient::get($probeUrl, [], 5, 0);
            if (!($probeResp['error'] ?? true) && ($probeResp['status'] ?? 0) === 200) {
                $probeBody = $probeResp['body'] ?? '';
                $probeLen = strlen($probeBody);
                if ($probeLen > 0 && $probeLen < 500000) {
                    // Verify it's not a generic 404/redirect page
                    if (!preg_match('/404|not found|page not found/i', $probeBody)) {
                        $sensitiveFindings[] = [
                            'path'        => $probe,
                            'status'      => $probeResp['status'],
                            'size'        => $probeLen,
                            'content_hint' => substr(trim(strip_tags($probeBody)), 0, 100),
                        ];
                    }
                }
            }
        }

        $ms = (int)((microtime(true) - $start) * 1000);

        // ── Deduplicate interesting ──────────────────────────────────────
        $seenInteresting = [];
        $uniqueInteresting = [];
        foreach ($interesting as $i) {
            $key = $i['category'] . ':' . $i['url'];
            if (!isset($seenInteresting[$key])) {
                $seenInteresting[$key] = true;
                $uniqueInteresting[] = $i;
            }
        }
        $interesting = $uniqueInteresting;

        // ── Scoring ──────────────────────────────────────────────────────
        $internalCount = count($allInternal);
        $externalCount = count($allExternal);
        $interestingCount = count($interesting);
        $emailCount = count($emails);
        $formCount = count($forms);
        $sensitiveCount = count($sensitiveFindings);
        $commentCount = count($comments);

        $score = 0;
        $findings = [];
        $categories = array_unique(array_column($interesting, 'category'));

        if (in_array('database', $categories))  { $score = max($score, 50); $findings[] = 'Database management exposed'; }
        if (in_array('config', $categories))     { $score = max($score, 40); $findings[] = 'Configuration pages found'; }
        if (in_array('debug', $categories))      { $score = max($score, 35); $findings[] = 'Debug/test pages found'; }
        if (in_array('admin', $categories))      { $score = max($score, 30); $findings[] = 'Admin panel links found'; }
        if (in_array('git', $categories))        { $score = max($score, 55); $findings[] = 'Version control exposed'; }
        if (in_array('api', $categories))        { $score = max($score, 20); $findings[] = 'API endpoints discovered'; }
        if (in_array('backup', $categories))     { $score = max($score, 45); $findings[] = 'Backup files linked'; }

        if ($sensitiveCount > 0) {
            $score = max($score, 40 + $sensitiveCount * 5);
            $findings[] = "{$sensitiveCount} sensitive file(s) accessible";
        }

        if ($emailCount > 5) $findings[] = "{$emailCount} email addresses harvested";
        if ($formCount > 0) $findings[] = "{$formCount} form(s) detected";
        if ($commentCount > 5) $findings[] = "HTML comments may leak info ({$commentCount} found)";

        $score = min(90, $score);
        $severity = OsintResult::scoreToSeverity($score);
        $confidence = min(85, 50 + $pagesCrawled * 2);

        $summaryParts = ["Spider crawled {$pagesCrawled} page(s) on {$value} (depth {$maxDepth}): {$internalCount} internal, {$externalCount} external link(s)"];
        if ($interestingCount > 0) $summaryParts[] = "{$interestingCount} interesting endpoint(s)";
        if ($sensitiveCount > 0) $summaryParts[] = "{$sensitiveCount} sensitive file(s) accessible";
        if (!empty($findings)) $summaryParts[] = implode('; ', array_slice($findings, 0, 4));

        $resultTags = [self::API_ID, $queryType, 'web_spider', 'crawl'];
        if ($interestingCount > 0) $resultTags[] = 'interesting_paths';
        if ($sensitiveCount > 0)   $resultTags[] = 'sensitive_files';
        if ($emailCount > 0)       $resultTags[] = 'email_harvest';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: implode('. ', array_slice($summaryParts, 0, 5)) . '.',
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'target'            => $targetUrl,
                'pages_crawled'     => $pagesCrawled,
                'max_depth'         => $maxDepth,
                'internal_count'    => $internalCount,
                'external_count'    => $externalCount,
                'internal_links'    => array_slice(array_keys($allInternal), 0, self::MAX_LINK_LOG),
                'external_links'    => array_slice(array_keys($allExternal), 0, 50),
                'interesting'       => array_slice($interesting, 0, 50),
                'sensitive_files'   => $sensitiveFindings,
                'emails'            => array_slice(array_keys($emails), 0, 50),
                'subdomains'        => array_keys($subdomains),
                'forms'             => array_slice($forms, 0, 30),
                'comments'          => array_slice($comments, 0, 20),
                'form_count'        => $formCount,
            ],
            success: true
        );
    }

    private function resolveUrl(string $link, string $baseScheme, string $baseHost, string $pageUrl): string
    {
        if (preg_match('#^https?://#i', $link)) return $link;
        if (strpos($link, '//') === 0) return $baseScheme . ':' . $link;
        if (strpos($link, '/') === 0) return $baseScheme . '://' . $baseHost . $link;
        // Relative to current page
        $dir = preg_replace('#/[^/]*$#', '', $pageUrl);
        return $dir . '/' . $link;
    }

    private function normalizeUrl(string $url): string
    {
        $url = rtrim($url, '/');
        $url = preg_replace('/#.*$/', '', $url);
        $url = preg_replace('/\?$/', '', $url);
        return strtolower($url);
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null,
                'max_depth' => self::MAX_DEPTH, 'max_pages' => self::MAX_PAGES,
                'probe_paths' => count(self::SENSITIVE_PROBES)];
    }
}
