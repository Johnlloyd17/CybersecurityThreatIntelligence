<?php
// =============================================================================
//  CTI — Nuclei Module (Expanded)
//  PHP-based vulnerability scanner: security headers, misconfigurations,
//  common vulnerabilities (directory traversal, open redirect, default creds,
//  exposed panels, CORS misconfiguration, HTTP method testing, etc.)
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class NucleiModule extends BaseApiModule
{
    private const API_ID   = 'nuclei';
    private const API_NAME = 'Nuclei Vulnerability Scanner';
    private const SUPPORTED = ['domain', 'url'];

    // Security headers with weights
    private const SECURITY_HEADERS = [
        'x-frame-options'                    => ['name' => 'X-Frame-Options',                    'weight' => 15, 'desc' => 'Prevents clickjacking'],
        'x-content-type-options'             => ['name' => 'X-Content-Type-Options',             'weight' => 10, 'desc' => 'Prevents MIME-type sniffing'],
        'strict-transport-security'          => ['name' => 'Strict-Transport-Security',          'weight' => 20, 'desc' => 'Enforces HTTPS (HSTS)'],
        'content-security-policy'            => ['name' => 'Content-Security-Policy',            'weight' => 20, 'desc' => 'Mitigates XSS/injection'],
        'x-xss-protection'                   => ['name' => 'X-XSS-Protection',                   'weight' => 5,  'desc' => 'Legacy XSS filter'],
        'permissions-policy'                 => ['name' => 'Permissions-Policy',                 'weight' => 10, 'desc' => 'Controls browser features'],
        'referrer-policy'                    => ['name' => 'Referrer-Policy',                    'weight' => 5,  'desc' => 'Controls referrer info'],
        'x-permitted-cross-domain-policies'  => ['name' => 'X-Permitted-Cross-Domain-Policies',  'weight' => 5,  'desc' => 'Restricts Flash/PDF cross-domain'],
        'cross-origin-embedder-policy'       => ['name' => 'Cross-Origin-Embedder-Policy',       'weight' => 5,  'desc' => 'Controls cross-origin embedding'],
        'cross-origin-opener-policy'         => ['name' => 'Cross-Origin-Opener-Policy',         'weight' => 5,  'desc' => 'Controls cross-origin window access'],
        'cross-origin-resource-policy'       => ['name' => 'Cross-Origin-Resource-Policy',       'weight' => 5,  'desc' => 'Controls cross-origin resource loading'],
    ];

    // Vulnerability check templates
    private const VULN_TEMPLATES = [
        // Directory traversal probes
        ['path' => '/..%2f..%2f..%2fetc/passwd', 'confirm' => 'root:', 'severity' => 95, 'name' => 'Path Traversal (etc/passwd)', 'category' => 'lfi'],
        ['path' => '/....//....//....//etc/passwd', 'confirm' => 'root:', 'severity' => 95, 'name' => 'Path Traversal Double Encoding', 'category' => 'lfi'],
        ['path' => '/%2e%2e/%2e%2e/%2e%2e/etc/passwd', 'confirm' => 'root:', 'severity' => 95, 'name' => 'Path Traversal URL-encoded', 'category' => 'lfi'],
        // Open redirect
        ['path' => '/redirect?url=https://evil.com', 'confirm_header' => 'location: https://evil.com', 'severity' => 60, 'name' => 'Open Redirect (redirect param)', 'category' => 'redirect'],
        ['path' => '/login?next=https://evil.com', 'confirm_header' => 'location: https://evil.com', 'severity' => 60, 'name' => 'Open Redirect (next param)', 'category' => 'redirect'],
        ['path' => '/login?return_to=https://evil.com', 'confirm_header' => 'location: https://evil.com', 'severity' => 60, 'name' => 'Open Redirect (return_to param)', 'category' => 'redirect'],
        // Exposed admin panels
        ['path' => '/admin/', 'confirm' => '<form', 'severity' => 55, 'name' => 'Admin Panel Exposed', 'category' => 'exposure'],
        ['path' => '/administrator/', 'confirm' => '<form', 'severity' => 55, 'name' => 'Administrator Panel', 'category' => 'exposure'],
        ['path' => '/wp-admin/', 'confirm' => 'wp-login', 'severity' => 45, 'name' => 'WordPress Admin', 'category' => 'exposure'],
        ['path' => '/phpmyadmin/', 'confirm' => 'phpMyAdmin', 'severity' => 75, 'name' => 'phpMyAdmin Exposed', 'category' => 'exposure'],
        ['path' => '/adminer.php', 'confirm' => 'Adminer', 'severity' => 75, 'name' => 'Adminer Database Tool', 'category' => 'exposure'],
        // Default credentials / debug pages
        ['path' => '/debug', 'confirm' => 'debug', 'severity' => 65, 'name' => 'Debug Page Exposed', 'category' => 'misconfiguration'],
        ['path' => '/trace', 'confirm' => 'trace', 'severity' => 65, 'name' => 'Trace Endpoint', 'category' => 'misconfiguration'],
        ['path' => '/actuator', 'confirm' => 'actuator', 'severity' => 70, 'name' => 'Spring Actuator Exposed', 'category' => 'misconfiguration'],
        ['path' => '/actuator/health', 'confirm' => 'status', 'severity' => 50, 'name' => 'Actuator Health', 'category' => 'misconfiguration'],
        ['path' => '/actuator/env', 'confirm' => 'property', 'severity' => 85, 'name' => 'Actuator Env (secrets)', 'category' => 'misconfiguration'],
        ['path' => '/_config', 'confirm' => null, 'severity' => 60, 'name' => 'Config Endpoint', 'category' => 'misconfiguration'],
        // API documentation
        ['path' => '/swagger-ui.html', 'confirm' => 'swagger', 'severity' => 45, 'name' => 'Swagger UI Exposed', 'category' => 'exposure'],
        ['path' => '/api-docs', 'confirm' => 'swagger', 'severity' => 45, 'name' => 'API Docs Exposed', 'category' => 'exposure'],
        ['path' => '/graphql', 'confirm' => null, 'severity' => 50, 'name' => 'GraphQL Endpoint', 'category' => 'exposure', 'method' => 'POST', 'body' => '{"query":"{__schema{types{name}}}"}'],
        // Server status/info
        ['path' => '/server-status', 'confirm' => 'Apache', 'severity' => 60, 'name' => 'Apache Server Status', 'category' => 'exposure'],
        ['path' => '/nginx_status', 'confirm' => 'Active connections', 'severity' => 55, 'name' => 'Nginx Status', 'category' => 'exposure'],
        // Backup files
        ['path' => '/backup.sql', 'confirm' => 'CREATE', 'severity' => 90, 'name' => 'SQL Backup File', 'category' => 'exposure'],
        ['path' => '/dump.sql', 'confirm' => 'INSERT', 'severity' => 90, 'name' => 'SQL Dump File', 'category' => 'exposure'],
        ['path' => '/database.sql', 'confirm' => 'CREATE', 'severity' => 90, 'name' => 'Database Backup', 'category' => 'exposure'],
        ['path' => '/db.sql', 'confirm' => 'CREATE', 'severity' => 90, 'name' => 'DB SQL File', 'category' => 'exposure'],
        // Error pages with stack traces
        ['path' => '/error', 'confirm' => 'stack trace', 'severity' => 55, 'name' => 'Stack Trace in Error Page', 'category' => 'info_leak'],
        ['path' => '/500', 'confirm' => 'exception', 'severity' => 45, 'name' => 'Exception in Error Page', 'category' => 'info_leak'],
    ];

    // Dangerous HTTP methods to test
    private const DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE', 'CONNECT'];

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
        $targetBase = rtrim($targetUrl, '/');

        $findings = [];

        // ── 1. Security Headers Check ────────────────────────────────────
        $headerFindings = $this->checkSecurityHeaders($targetBase);
        $findings = array_merge($findings, $headerFindings);

        // ── 2. CORS Misconfiguration ─────────────────────────────────────
        $corsFindings = $this->checkCors($targetBase);
        $findings = array_merge($findings, $corsFindings);

        // ── 3. Dangerous HTTP Methods ────────────────────────────────────
        $methodFindings = $this->checkHttpMethods($targetBase);
        $findings = array_merge($findings, $methodFindings);

        // ── 4. Vulnerability Templates ───────────────────────────────────
        $vulnFindings = $this->checkVulnTemplates($targetBase);
        $findings = array_merge($findings, $vulnFindings);

        // ── 5. Information Disclosure Headers ────────────────────────────
        $infoFindings = $this->checkInfoDisclosure($targetBase);
        $findings = array_merge($findings, $infoFindings);

        $ms = (int)((microtime(true) - $start) * 1000);

        // Aggregate results
        $totalChecks = count(self::SECURITY_HEADERS) + count(self::VULN_TEMPLATES) + count(self::DANGEROUS_METHODS) + 3;
        $findingCount = count($findings);

        if ($findingCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 85,
                responseMs: $ms,
                summary: "Nuclei scan of {$value}: {$totalChecks} checks passed, no issues found.",
                tags: [self::API_ID, $queryType, 'clean', 'security_scan'],
                rawData: ['url' => $targetBase, 'total_checks' => $totalChecks, 'findings' => []],
                success: true
            );
        }

        // Score from highest severity finding
        $maxSeverity = 0;
        $categories = [];
        foreach ($findings as $f) {
            $maxSeverity = max($maxSeverity, $f['severity']);
            $categories[$f['category']] = ($categories[$f['category']] ?? 0) + 1;
        }

        $score      = min(95, $maxSeverity);
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 70 + $findingCount * 3);

        // Summary
        $catParts = [];
        arsort($categories);
        foreach ($categories as $cat => $count) $catParts[] = "{$cat}: {$count}";

        $summary = "Nuclei: {$findingCount} issue(s) found on {$value} ({$totalChecks} checks). ";
        $summary .= 'Categories: ' . implode(', ', $catParts) . '.';

        // Top findings for summary
        usort($findings, fn($a, $b) => $b['severity'] <=> $a['severity']);
        $topNames = array_map(fn($f) => $f['name'], array_slice($findings, 0, 3));
        $summary .= ' Top: ' . implode(', ', $topNames) . '.';

        $resultTags = [self::API_ID, $queryType, 'security_scan', 'vulnerability'];
        foreach (array_keys($categories) as $c) $resultTags[] = $c;

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'url'           => $targetBase,
                'total_checks'  => $totalChecks,
                'finding_count' => $findingCount,
                'categories'    => $categories,
                'findings'      => array_slice($findings, 0, 50),
            ],
            success: true
        );
    }

    private function checkSecurityHeaders(string $targetUrl): array
    {
        $findings = [];
        $ch = curl_init($targetUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true, CURLOPT_NOBODY => true,
            CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_SSL_VERIFYPEER => false, CURLOPT_USERAGENT => 'CTI-Platform/1.0',
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        if (!$response) return $findings;

        $headerBlock = strtolower($response);
        foreach (self::SECURITY_HEADERS as $key => $info) {
            if (strpos($headerBlock, $key . ':') === false) {
                $findings[] = [
                    'name'     => "Missing {$info['name']}",
                    'severity' => $info['weight'],
                    'category' => 'missing_header',
                    'detail'   => $info['desc'],
                ];
            }
        }
        return $findings;
    }

    private function checkCors(string $targetUrl): array
    {
        $findings = [];
        $ch = curl_init($targetUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER => ['Origin: https://evil.com'],
            CURLOPT_USERAGENT => 'CTI-Platform/1.0',
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        if (!$response) return $findings;

        $headerLower = strtolower($response);
        if (strpos($headerLower, 'access-control-allow-origin: *') !== false) {
            $findings[] = ['name' => 'CORS Wildcard (*)', 'severity' => 55, 'category' => 'misconfiguration', 'detail' => 'Access-Control-Allow-Origin set to wildcard'];
        }
        if (strpos($headerLower, 'access-control-allow-origin: https://evil.com') !== false) {
            $findings[] = ['name' => 'CORS Origin Reflection', 'severity' => 75, 'category' => 'misconfiguration', 'detail' => 'Server reflects arbitrary Origin header'];
        }
        if (strpos($headerLower, 'access-control-allow-credentials: true') !== false && strpos($headerLower, 'access-control-allow-origin: *') !== false) {
            $findings[] = ['name' => 'CORS Credentials with Wildcard', 'severity' => 80, 'category' => 'misconfiguration', 'detail' => 'Credentials allowed with wildcard origin'];
        }
        return $findings;
    }

    private function checkHttpMethods(string $targetUrl): array
    {
        $findings = [];
        foreach (self::DANGEROUS_METHODS as $method) {
            $ch = curl_init($targetUrl);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
                CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 5,
                CURLOPT_CUSTOMREQUEST => $method, CURLOPT_SSL_VERIFYPEER => false,
            ]);
            $resp = curl_exec($ch);
            $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($status >= 200 && $status < 400 && $status !== 0) {
                $sev = ($method === 'TRACE') ? 55 : (($method === 'PUT' || $method === 'DELETE') ? 65 : 40);
                $findings[] = ['name' => "{$method} Method Allowed", 'severity' => $sev, 'category' => 'misconfiguration', 'detail' => "HTTP {$method} returned {$status}"];
            }
        }
        return $findings;
    }

    private function checkVulnTemplates(string $targetBase): array
    {
        $findings = [];
        foreach (self::VULN_TEMPLATES as $tmpl) {
            $url = $targetBase . $tmpl['path'];
            $resp = HttpClient::get($url, [], 5, 0);

            if ($resp['status'] !== 200 || $resp['error']) continue;

            $body = $resp['body'] ?? '';
            if (strlen($body) < 3) continue;

            // Skip custom 404 pages
            $bodyLower = strtolower($body);
            if (strpos($bodyLower, 'not found') !== false && strpos($bodyLower, '404') !== false) continue;

            // Confirm match
            $confirm = $tmpl['confirm'] ?? null;
            if ($confirm !== null && stripos($body, $confirm) === false) continue;

            // Check header-based confirmation
            if (isset($tmpl['confirm_header'])) {
                $headerStr = strtolower($resp['headers'] ?? '');
                if (strpos($headerStr, $tmpl['confirm_header']) === false) continue;
            }

            $findings[] = [
                'name'     => $tmpl['name'],
                'severity' => $tmpl['severity'],
                'category' => $tmpl['category'],
                'detail'   => "Found at {$tmpl['path']}",
                'path'     => $tmpl['path'],
            ];
        }
        return $findings;
    }

    private function checkInfoDisclosure(string $targetUrl): array
    {
        $findings = [];
        $ch = curl_init($targetUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 8,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        if (!$response) return $findings;

        // Check for server version disclosure
        if (preg_match('/^server:\s*(.+)$/im', $response, $m)) {
            $server = trim($m[1]);
            if (preg_match('/\d+\.\d+/', $server)) {
                $findings[] = ['name' => 'Server Version Disclosure', 'severity' => 25, 'category' => 'info_leak', 'detail' => "Server: {$server}"];
            }
        }

        // X-Powered-By with version
        if (preg_match('/^x-powered-by:\s*(.+)$/im', $response, $m)) {
            $findings[] = ['name' => 'X-Powered-By Disclosure', 'severity' => 20, 'category' => 'info_leak', 'detail' => "X-Powered-By: " . trim($m[1])];
        }

        // ASP.NET version
        if (preg_match('/^x-aspnet-version:\s*(.+)$/im', $response, $m)) {
            $findings[] = ['name' => 'ASP.NET Version Disclosure', 'severity' => 25, 'category' => 'info_leak', 'detail' => "X-AspNet-Version: " . trim($m[1])];
        }

        return $findings;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null,
                'templates' => count(self::VULN_TEMPLATES), 'header_checks' => count(self::SECURITY_HEADERS)];
    }
}
