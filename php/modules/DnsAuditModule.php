<?php
// =============================================================================
//  CTI — DNSAudit Module
//  Integrates the existing local DNSAudit implementation under /DNSAuditAPI.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsAuditModule extends BaseApiModule
{
    private const API_ID = 'dnsaudit';
    private const API_NAME = 'DNSAudit';
    private const SUPPORTED = ['domain', 'url'];
    private const MAX_DISCOVERIES = 100;
    private const ISSUE_DATA_TYPE = 'DNS Security Issue';
    private const ISSUE_DOCS_BASE_URL = 'https://dnsaudit.io/docs';
    private const ISSUE_TEXT_MAX_CHARS = 12000;
    private const ISSUE_CATALOG = [
        'missing-spf-record' => ['title' => 'Missing SPF Record', 'group' => 'Email Authentication Issues'],
        'missing-dmarc-record' => ['title' => 'Missing DMARC Record', 'group' => 'Email Authentication Issues'],
        'missing-dkim-record' => ['title' => 'Missing DKIM Record', 'group' => 'Email Authentication Issues'],
        'enhanced-dmarc-analysis' => ['title' => 'DMARC Policy Issues', 'group' => 'Email Authentication Issues'],
        'wildcard-spf-protection' => ['title' => 'Wildcard SPF Protection', 'group' => 'Email Authentication Issues'],
        'zone-transfer-vulnerability' => ['title' => 'Zone Transfer Vulnerability', 'group' => 'DNS Vulnerabilities'],
        'missing-caa-record' => ['title' => 'Missing CAA Records', 'group' => 'DNS Vulnerabilities'],
        'dns-amplification-risk' => ['title' => 'DNS Amplification Risk', 'group' => 'DNS Vulnerabilities'],
        'subdomain-takeover' => ['title' => 'Subdomain Takeover Vulnerability', 'group' => 'DNS Vulnerabilities'],
        'service-discovery-exposure' => ['title' => 'Service Discovery Information Exposed', 'group' => 'DNS Vulnerabilities'],
        'dnssec-missing' => ['title' => 'DNSSEC Not Implemented', 'group' => 'DNS Vulnerabilities'],
        'dns-rebinding-vulnerability' => ['title' => 'DNS Rebinding Vulnerability', 'group' => 'DNS Vulnerabilities'],
        'dns-server-cve' => ['title' => 'DNS Server Software Vulnerabilities', 'group' => 'DNS Vulnerabilities'],
        'phishing-domain-protection' => ['title' => 'Potential Phishing Domain Protection', 'group' => 'Information Disclosure'],
        'exposed-3rd-party-services-dns' => ['title' => 'Exposed 3rd-Party Services in DNS', 'group' => 'Information Disclosure'],
        'dns-open-recursion' => ['title' => 'DNS Open Recursion', 'group' => 'Advanced DNS Security'],
        'dns-cookies' => ['title' => 'DNS Cookies Not Supported', 'group' => 'Advanced DNS Security'],
        'dns-response-size' => ['title' => 'DNS Response Size Issues', 'group' => 'Advanced DNS Security'],
        'dns-over-tls' => ['title' => 'DNS over TLS Not Supported', 'group' => 'Advanced DNS Security'],
        'dns-response-flags' => ['title' => 'DNS Response Flags Analysis', 'group' => 'Advanced DNS Security'],
        'wildcard-dns-detection' => ['title' => 'Wildcard DNS Detection', 'group' => 'Advanced DNS Security'],
        'ipv6-dns-support' => ['title' => 'IPv6 DNS Support Analysis', 'group' => 'Advanced DNS Security'],
        'dnssec-algorithm' => ['title' => 'DNSSEC Algorithm Analysis', 'group' => 'DNSSEC and Cryptographic Security'],
        'nsec3-parameters' => ['title' => 'NSEC3 Parameters Assessment', 'group' => 'DNSSEC and Cryptographic Security'],
        'dns-ttl-analysis' => ['title' => 'DNS TTL Analysis', 'group' => 'DNS Configuration Issues'],
        'caa-implementation' => ['title' => 'CAA Implementation Issues', 'group' => 'DNS Configuration Issues'],
        'uncommon-dns-records' => ['title' => 'Uncommon DNS Records', 'group' => 'DNS Configuration Issues'],
        'ns-redundancy' => ['title' => 'NS Redundancy Issues', 'group' => 'DNS Configuration Issues'],
        'nameserver-consistency' => ['title' => 'Nameserver Consistency', 'group' => 'DNS Configuration Issues'],
        'dns-delegation-integrity' => ['title' => 'DNS Delegation Integrity', 'group' => 'DNS Configuration Issues'],
        'ns-cname-indirection' => ['title' => 'NS CNAME Indirection', 'group' => 'DNS Configuration Issues'],
        'dangling-ns' => ['title' => 'Dangling NS / Orphaned Nameservers', 'group' => 'DNS Configuration Issues'],
        'caa-drift' => ['title' => 'CAA Drift Check', 'group' => 'DNS Configuration Issues'],
        'dynamic-dns-detection' => ['title' => 'Dynamic DNS Provider Detection', 'group' => 'DNS Configuration Issues'],
        'parked-domain-detection' => ['title' => 'Parked Domain Detection', 'group' => 'DNS Configuration Issues'],
        'dns-waf-detected' => ['title' => 'DNS WAF / Proxy Detected', 'group' => 'DNS Configuration Issues'],
        'missing-mx-records' => ['title' => 'Missing MX Records', 'group' => 'DNS Configuration Issues'],
        'dns-authentication-failure' => ['title' => 'DNS Authentication Failures', 'group' => 'DNS Resolution and Connectivity'],
        'dns-resolution-failure' => ['title' => 'DNS Resolution Failures', 'group' => 'DNS Resolution and Connectivity'],
        'private-ip-resolution' => ['title' => 'Private IP Resolution', 'group' => 'DNS Resolution and Connectivity'],
        'ai-infrastructure-exposure' => ['title' => 'AI Infrastructure Exposure', 'group' => 'Attack Surface Threats'],
        'txt-malware-records' => ['title' => 'TXT Record Malware Detection', 'group' => 'Attack Surface Threats'],
        'dns-tunneling-detection' => ['title' => 'DNS Tunneling Detection', 'group' => 'Attack Surface Threats'],
        'exposed-sensitive-subdomains' => ['title' => 'Sensitive Subdomains Exposed', 'group' => 'Attack Surface Threats'],
        'ip-threat-reputation-status' => ['title' => 'IP Threat Reputation Analysis', 'group' => 'Threat Intelligence & Reputation'],
        'shared-ip-malicious-domains' => ['title' => 'Shared IP with Malicious Domains', 'group' => 'Threat Intelligence & Reputation'],
        'dkim-key-strength' => ['title' => 'DKIM Key Strength Analysis', 'group' => 'Advanced DKIM Security'],
        'dkim-key-format' => ['title' => 'DKIM Key Format Validation', 'group' => 'Advanced DKIM Security'],
        'dkim-key-reuse' => ['title' => 'DKIM Key Reuse Detection', 'group' => 'Advanced DKIM Security'],
        'cname-to-expired-domain' => ['title' => 'CNAME to Expired Domain', 'group' => 'Advanced DKIM Security'],
    ];
    private const ISSUE_ALIASES = [
        'dmarc policy issues' => 'enhanced-dmarc-analysis',
        'dnssec is not enabled' => 'dnssec-missing',
        'dnssec not implemented' => 'dnssec-missing',
        'exposed 3rd-party services in dns' => 'exposed-3rd-party-services-dns',
        'exposed 3rd-party services in txt records' => 'exposed-3rd-party-services-dns',
        'sensitive subdomains exposed' => 'exposed-sensitive-subdomains',
        'dns waf / proxy detected' => 'dns-waf-detected',
        'dkim key strength analysis' => 'dkim-key-strength',
        'dkim key format validation' => 'dkim-key-format',
        'dkim key reuse detection' => 'dkim-key-reuse',
        'shared ip with malicious domains' => 'shared-ip-malicious-domains',
        'ip threat reputation analysis' => 'ip-threat-reputation-status',
    ];
    private const ISSUE_HEURISTICS = [
        'missing-spf-record' => ['spf', 'missing'],
        'missing-dmarc-record' => ['dmarc', 'missing'],
        'missing-dkim-record' => ['dkim', 'missing'],
        'enhanced-dmarc-analysis' => ['dmarc', 'policy'],
        'wildcard-spf-protection' => ['spf', 'wildcard'],
        'zone-transfer-vulnerability' => ['zone transfer'],
        'missing-caa-record' => ['caa', 'missing'],
        'dns-amplification-risk' => ['dns amplification'],
        'subdomain-takeover' => ['subdomain takeover'],
        'service-discovery-exposure' => ['service discovery'],
        'dnssec-missing' => ['dnssec', 'not enabled'],
        'dns-rebinding-vulnerability' => ['dns rebinding'],
        'dns-server-cve' => ['dns server', 'cve'],
        'phishing-domain-protection' => ['phishing'],
        'exposed-3rd-party-services-dns' => ['3rd-party services'],
        'dns-open-recursion' => ['open recursion'],
        'dns-cookies' => ['dns cookies'],
        'dns-response-size' => ['response size'],
        'dns-over-tls' => ['dns over tls'],
        'dns-response-flags' => ['response flags'],
        'wildcard-dns-detection' => ['wildcard dns'],
        'ipv6-dns-support' => ['ipv6'],
        'dnssec-algorithm' => ['dnssec algorithm'],
        'nsec3-parameters' => ['nsec3'],
        'dns-ttl-analysis' => ['ttl'],
        'caa-implementation' => ['caa implementation'],
        'uncommon-dns-records' => ['uncommon dns records'],
        'ns-redundancy' => ['ns redundancy'],
        'nameserver-consistency' => ['nameserver consistency'],
        'dns-delegation-integrity' => ['delegation integrity'],
        'ns-cname-indirection' => ['ns cname'],
        'dangling-ns' => ['dangling ns'],
        'caa-drift' => ['caa drift'],
        'dynamic-dns-detection' => ['dynamic dns'],
        'parked-domain-detection' => ['parked domain'],
        'dns-waf-detected' => ['waf', 'proxy'],
        'missing-mx-records' => ['missing mx'],
        'dns-authentication-failure' => ['authentication failure'],
        'dns-resolution-failure' => ['resolution failure'],
        'private-ip-resolution' => ['private ip'],
        'ai-infrastructure-exposure' => ['ai infrastructure'],
        'txt-malware-records' => ['txt', 'malware'],
        'dns-tunneling-detection' => ['dns tunneling'],
        'exposed-sensitive-subdomains' => ['sensitive subdomains'],
        'ip-threat-reputation-status' => ['threat reputation'],
        'shared-ip-malicious-domains' => ['shared ip', 'malicious domains'],
        'dkim-key-strength' => ['dkim', 'key strength'],
        'dkim-key-format' => ['dkim', 'key format'],
        'dkim-key-reuse' => ['dkim', 'key reuse'],
        'cname-to-expired-domain' => ['cname', 'expired domain'],
    ];
    private const ISSUE_GROUP_BY_CATEGORY = [
        'email authentication' => 'Email Authentication Issues',
        'dns vulnerabilities' => 'DNS Vulnerabilities',
        'dns vulnerability' => 'DNS Vulnerabilities',
        'information disclosure' => 'Information Disclosure',
        'advanced dns security' => 'Advanced DNS Security',
        'dnssec and cryptographic security' => 'DNSSEC and Cryptographic Security',
        'dns configuration issues' => 'DNS Configuration Issues',
        'dns resolution and connectivity' => 'DNS Resolution and Connectivity',
        'attack surface threats' => 'Attack Surface Threats',
        'threat intelligence & reputation' => 'Threat Intelligence & Reputation',
        'advanced dkim security' => 'Advanced DKIM Security',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult|array
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported query type: {$queryType}");
        }

        $domain = $this->normalizeDomain($queryType, $queryValue);
        if ($domain === '') {
            return OsintResult::error(self::API_ID, self::API_NAME, 'Invalid domain/URL target.');
        }

        $startedAt = microtime(true);

        try {
            [$client, $effectiveBaseUrl] = $this->buildClient($apiKey, $baseUrl);

            if (!$client->isConfigured()) {
                return OsintResult::error(
                    self::API_ID,
                    self::API_NAME,
                    'DNSAudit API key is not configured. Set it in CTI API settings or DNSAuditAPI/config.php.'
                );
            }

            $scanResponse = $client->scan($domain);
            $summary = $client->extractSummary($scanResponse, null, $domain);
            $findings = $client->normalizeFindings($scanResponse, null, null, $domain);
            $findings = $this->filterFindings($findings);
            $findings = $this->decorateFindings($findings);

            $historyData = null;
            $historyError = null;
            if ($this->bool('include_history', false)) {
                try {
                    $historyLimit = max(1, min(100, $this->int('history_limit', 10)));
                    $historyData = $client->scanHistory($historyLimit);
                } catch (\Throwable $e) {
                    // Non-fatal: scan still succeeded.
                    $historyError = $e->getMessage();
                }
            }

            $score = $this->resolveScore($summary, $findings);
            $severity = OsintResult::scoreToSeverity($score);
            $confidence = $this->resolveConfidence($summary, $findings);
            $elapsedMs = (int)((microtime(true) - $startedAt) * 1000);

            $summaryText = $this->buildSummaryText($domain, $summary, $findings, $historyData, $historyError, $score);

            $tags = [self::API_ID, 'dns', $queryType];
            $criticalCount = $this->countBySeverity($findings, 'critical');
            $warningCount = $this->countBySeverity($findings, 'warning');
            if ($criticalCount > 0) {
                $tags[] = 'critical_findings';
            } elseif ($warningCount > 0) {
                $tags[] = 'warning_findings';
            } else {
                $tags[] = 'clean';
            }

            $rawData = null;
            if ($this->bool('include_raw_payload', true)) {
                $rawData = [
                    'domain'        => $domain,
                    'base_url'      => $effectiveBaseUrl,
                    'summary'       => $summary,
                    'findings'      => $findings,
                    'scan_response' => $scanResponse,
                ];
                if ($historyData !== null) {
                    $rawData['history'] = $historyData;
                }
                if ($historyError !== null) {
                    $rawData['history_error'] = $historyError;
                }
            }

            $result = new OsintResult(
                api: self::API_ID,
                apiName: self::API_NAME,
                score: $score,
                severity: $severity,
                confidence: $confidence,
                responseMs: $elapsedMs,
                summary: $summaryText,
                tags: array_values(array_unique($tags)),
                rawData: $rawData,
                success: true,
                dataType: 'DNS Security Summary'
            );

            if ($this->bool('emit_subdomain_discoveries', true)) {
                foreach ($this->extractSubdomains($scanResponse, $domain) as $subdomain) {
                    $result->addDiscovery('Internet Name', $subdomain);
                }
            }

            $issueResults = $this->buildIssueResults(
                findings: $findings,
                domain: $domain,
                queryType: $queryType,
                responseMs: $elapsedMs
            );

            if ($this->bool('emit_issue_rows', true) && !empty($issueResults)) {
                return array_merge([$result], $issueResults);
            }

            return $result;
        } catch (\Throwable $e) {
            $elapsedMs = (int)((microtime(true) - $startedAt) * 1000);
            $message = $e->getMessage();
            $lower = strtolower($message);

            if (str_contains($lower, 'rate limit') || str_contains($lower, 'http 429')) {
                return OsintResult::rateLimited(self::API_ID, self::API_NAME, $elapsedMs);
            }
            if (str_contains($lower, 'api key') && (str_contains($lower, 'invalid') || str_contains($lower, 'unauthorized'))) {
                return OsintResult::unauthorized(self::API_ID, self::API_NAME, $elapsedMs);
            }

            return OsintResult::error(self::API_ID, self::API_NAME, $message, $elapsedMs);
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $startedAt = microtime(true);

        try {
            [$client] = $this->buildClient($apiKey, $baseUrl);
            if (!$client->isConfigured()) {
                return [
                    'status' => 'unconfigured',
                    'latency_ms' => 0,
                    'error' => 'API key not configured.',
                ];
            }

            // Light endpoint compared to full scan.
            $client->scanHistory(1);
            return [
                'status' => 'healthy',
                'latency_ms' => (int)((microtime(true) - $startedAt) * 1000),
                'error' => null,
            ];
        } catch (\Throwable $e) {
            return [
                'status' => 'down',
                'latency_ms' => (int)((microtime(true) - $startedAt) * 1000),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * @return array{0: object, 1: string}
     */
    private function buildClient(string $apiKey, string $baseUrl): array
    {
        $rootDir = dirname(__DIR__, 2);
        $clientPath = $rootDir . '/DNSAuditAPI/src/DnsAuditClient.php';
        $configPath = $rootDir . '/DNSAuditAPI/config.php';

        if (!is_file($clientPath)) {
            throw new \RuntimeException('DNSAudit client file not found: ' . $clientPath);
        }
        if (!is_file($configPath)) {
            throw new \RuntimeException('DNSAudit config file not found: ' . $configPath);
        }

        require_once $clientPath;
        if (!class_exists('DnsAuditClient')) {
            throw new \RuntimeException('DnsAuditClient class is missing.');
        }

        $config = require $configPath;
        if (!is_array($config)) {
            throw new \RuntimeException('DNSAudit config.php did not return an array.');
        }
        if (!isset($config['api']) || !is_array($config['api'])) {
            $config['api'] = [];
        }

        if (trim($baseUrl) !== '') {
            $config['api']['base_url'] = rtrim(trim($baseUrl), '/');
        }
        $effectiveBaseUrl = (string)($config['api']['base_url'] ?? 'https://dnsaudit.io/api');

        if (trim($apiKey) !== '') {
            $config['api']['api_key'] = trim($apiKey);
        }

        $timeout = max(5, min(180, $this->int('timeout_seconds', 45)));
        $maxRetries = max(0, min(5, $this->int('max_retries', 2)));
        $config['api']['timeout'] = $timeout;
        $config['api']['max_retries'] = $maxRetries;

        $client = new DnsAuditClient($config, null);
        return [$client, $effectiveBaseUrl];
    }

    private function normalizeDomain(string $queryType, string $queryValue): string
    {
        $value = trim($queryValue);
        if ($value === '') {
            return '';
        }

        if ($queryType === 'url') {
            $host = parse_url($value, PHP_URL_HOST);
            if (!is_string($host) || $host === '') {
                // Accept URLs without scheme by retrying with https:// prefix.
                $host = parse_url('https://' . ltrim($value, '/'), PHP_URL_HOST);
            }
            $value = is_string($host) ? $host : '';
        }

        $value = strtolower(trim($value));
        $value = preg_replace('#^https?://#', '', $value);
        $value = preg_replace('#/.*$#', '', $value);
        $value = rtrim((string)$value, '.');

        if (!preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/', $value)) {
            return '';
        }

        return $value;
    }

    private function filterFindings(array $findings): array
    {
        $minSeverity = strtolower(trim($this->str('min_severity', 'warning')));
        if (!in_array($minSeverity, ['info', 'warning', 'critical'], true)) {
            $minSeverity = 'warning';
        }

        $maxResults = max(1, min(500, $this->int('max_results', 100)));
        $minRank = $this->severityRank($minSeverity);

        $normalized = [];
        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $severity = strtolower(trim((string)($finding['severity'] ?? 'info')));
            if (!in_array($severity, ['info', 'warning', 'critical'], true)) {
                $severity = 'info';
            }
            if ($this->severityRank($severity) < $minRank) {
                continue;
            }

            $normalized[] = [
                'severity' => $severity,
                'category' => (string)($finding['category'] ?? ''),
                'title' => (string)($finding['title'] ?? ''),
                'description' => (string)($finding['description'] ?? ''),
                'recommendation' => (string)($finding['recommendation'] ?? ''),
                'status' => (string)($finding['status'] ?? 'open'),
            ];

            if (count($normalized) >= $maxResults) {
                break;
            }
        }

        return $normalized;
    }

    private function decorateFindings(array $findings): array
    {
        $decorated = [];
        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $title = trim((string)($finding['title'] ?? ''));
            $category = trim((string)($finding['category'] ?? ''));
            $description = trim((string)($finding['description'] ?? ''));

            $slug = $this->classifyIssueSlug($title, $category, $description);
            $catalog = ($slug !== '' && isset(self::ISSUE_CATALOG[$slug])) ? self::ISSUE_CATALOG[$slug] : null;
            $group = $catalog['group'] ?? $this->resolveCategoryGroup($category, $slug);
            $canonicalTitle = $catalog['title'] ?? ($title !== '' ? $title : ucwords(str_replace('-', ' ', $slug)));
            $docsUrl = ($slug !== '' && $this->bool('include_docs_links', true))
                ? self::ISSUE_DOCS_BASE_URL . '/' . $slug
                : '';

            $decorated[] = [
                'severity' => (string)($finding['severity'] ?? 'info'),
                'category' => $category,
                'title' => $canonicalTitle,
                'description' => $description,
                'recommendation' => (string)($finding['recommendation'] ?? ''),
                'status' => (string)($finding['status'] ?? 'open'),
                'issue_slug' => $slug,
                'category_group' => $group,
                'docs_url' => $docsUrl,
            ];
        }

        return $decorated;
    }

    private function classifyIssueSlug(string $title, string $category, string $description): string
    {
        $titleSlug = $this->slugify($title);
        if ($titleSlug !== '' && isset(self::ISSUE_CATALOG[$titleSlug])) {
            return $titleSlug;
        }

        $titleKey = strtolower(trim($title));
        if ($titleKey !== '' && isset(self::ISSUE_ALIASES[$titleKey])) {
            return self::ISSUE_ALIASES[$titleKey];
        }

        $candidate = $this->slugify($category . ' ' . $title);
        if ($candidate !== '' && isset(self::ISSUE_CATALOG[$candidate])) {
            return $candidate;
        }

        $text = strtolower(trim($title . ' ' . $category . ' ' . $description));
        foreach (self::ISSUE_HEURISTICS as $slug => $needles) {
            $allMatch = true;
            foreach ($needles as $needle) {
                if (!str_contains($text, strtolower($needle))) {
                    $allMatch = false;
                    break;
                }
            }
            if ($allMatch && isset(self::ISSUE_CATALOG[$slug])) {
                return $slug;
            }
        }

        return '';
    }

    private function resolveCategoryGroup(string $category, string $slug): string
    {
        if ($slug !== '' && isset(self::ISSUE_CATALOG[$slug]['group'])) {
            return (string)self::ISSUE_CATALOG[$slug]['group'];
        }

        $normalized = strtolower(trim($category));
        if ($normalized !== '' && isset(self::ISSUE_GROUP_BY_CATEGORY[$normalized])) {
            return self::ISSUE_GROUP_BY_CATEGORY[$normalized];
        }

        foreach (self::ISSUE_GROUP_BY_CATEGORY as $needle => $group) {
            if ($normalized !== '' && str_contains($normalized, $needle)) {
                return $group;
            }
        }

        return 'DNS Security Issues';
    }

    private function slugify(string $value): string
    {
        $value = strtolower(trim($value));
        if ($value === '') {
            return '';
        }
        $value = str_replace(['&', '/'], [' and ', ' '], $value);
        $value = preg_replace('/[^a-z0-9]+/', '-', $value);
        return trim((string)$value, '-');
    }

    private function buildIssueResults(array $findings, string $domain, string $queryType, int $responseMs): array
    {
        if (!$this->bool('emit_issue_rows', true)) {
            return [];
        }

        $results = [];
        $seen = [];

        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $severity = strtolower(trim((string)($finding['severity'] ?? 'info')));
            if (!in_array($severity, ['critical', 'warning', 'info'], true)) {
                $severity = 'info';
            }

            $issueSlug = trim((string)($finding['issue_slug'] ?? ''));
            $issueTitle = trim((string)($finding['title'] ?? ''));
            $group = trim((string)($finding['category_group'] ?? 'DNS Security Issues'));
            $description = trim((string)($finding['description'] ?? ''));
            $recommendation = trim((string)($finding['recommendation'] ?? ''));
            $docsUrl = trim((string)($finding['docs_url'] ?? ''));

            $signature = strtolower($issueSlug . '|' . $issueTitle . '|' . $severity . '|' . $description);
            if (isset($seen[$signature])) {
                continue;
            }
            $seen[$signature] = true;

            $payload = [
                'kind' => 'dnsaudit_issue',
                'domain' => $domain,
                'issue_slug' => $issueSlug,
                'issue_title' => $issueTitle,
                'category_group' => $group,
                'category' => (string)($finding['category'] ?? ''),
                'severity' => $severity,
                'description' => $this->clip($description, self::ISSUE_TEXT_MAX_CHARS),
                'recommendation' => $this->clip($recommendation, self::ISSUE_TEXT_MAX_CHARS),
            ];
            if ($docsUrl !== '' && $this->bool('include_docs_links', true)) {
                $payload['docs_url'] = $docsUrl;
            }

            $summary = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($summary) || $summary === '') {
                $summary = "DNSAudit issue ({$severity}): " . ($issueTitle !== '' ? $issueTitle : 'Unnamed issue');
            }

            $result = new OsintResult(
                api: self::API_ID,
                apiName: self::API_NAME,
                score: $this->issueScore($severity),
                severity: $severity,
                confidence: $this->issueConfidence($severity),
                responseMs: $responseMs,
                summary: $summary,
                tags: array_values(array_filter([
                    self::API_ID,
                    'dns_issue',
                    $severity,
                    $issueSlug !== '' ? $issueSlug : null,
                    $group !== '' ? 'group:' . $this->slugify($group) : null,
                ])),
                rawData: [
                    'kind' => 'dnsaudit_issue',
                    'domain' => $domain,
                    'finding' => $finding,
                ],
                success: true,
                dataType: self::ISSUE_DATA_TYPE
            );

            $results[] = $result;
        }

        return $results;
    }

    private function issueScore(string $severity): int
    {
        return match ($severity) {
            'critical' => 92,
            'warning' => 68,
            default => 25,
        };
    }

    private function issueConfidence(string $severity): int
    {
        return match ($severity) {
            'critical' => 90,
            'warning' => 80,
            default => 65,
        };
    }

    private function clip(string $text, int $max): string
    {
        $text = trim($text);
        if ($text === '' || mb_strlen($text, 'UTF-8') <= $max) {
            return $text;
        }
        return mb_substr($text, 0, $max - 1, 'UTF-8') . '...';
    }

    private function resolveScore(array $summary, array $findings): int
    {
        $rawScore = $summary['score'] ?? null;
        if (is_numeric($rawScore)) {
            $score = (int)$rawScore;
            if ($score >= 0 && $score <= 100) {
                return $score;
            }
        }

        $critical = $this->countBySeverity($findings, 'critical');
        $warning = $this->countBySeverity($findings, 'warning');
        $info = $this->countBySeverity($findings, 'info');

        if ($critical === 0 && $warning === 0 && $info === 0) {
            return 5;
        }

        $derived = ($critical * 30) + ($warning * 12) + ($info > 0 ? 5 : 0);
        return max(0, min(95, $derived));
    }

    private function resolveConfidence(array $summary, array $findings): int
    {
        $totalFindings = count($findings);
        if ($totalFindings === 0) {
            return 80;
        }

        $confidence = 70 + min(25, $totalFindings * 3);
        $criticalCount = $this->countBySeverity($findings, 'critical');
        if ($criticalCount > 0) {
            $confidence = min(95, $confidence + 5);
        }

        $summaryTotal = $summary['total_findings'] ?? null;
        if (is_numeric($summaryTotal) && (int)$summaryTotal > $totalFindings) {
            $confidence = min(95, $confidence + 2);
        }

        return max(50, min(95, $confidence));
    }

    private function buildSummaryText(
        string $domain,
        array $summary,
        array $findings,
        mixed $historyData,
        ?string $historyError,
        int $score
    ): string {
        $grade = strtoupper(trim((string)($summary['grade'] ?? '')));
        $criticalCount = $this->countBySeverity($findings, 'critical');
        $warningCount = $this->countBySeverity($findings, 'warning');
        $infoCount = $this->countBySeverity($findings, 'info');
        $total = count($findings);

        $headline = "Domain {$domain}: DNSAudit score {$score}/100";
        if ($grade !== '') {
            $headline .= ", grade {$grade}";
        }
        $headline .= ".";

        $counts = " Findings kept: {$total} (critical: {$criticalCount}, warning: {$warningCount}, info: {$infoCount}).";

        $highlights = '';
        if ($total > 0) {
            $titles = [];
            foreach ($findings as $finding) {
                $title = trim((string)($finding['title'] ?? ''));
                if ($title === '') {
                    continue;
                }
                $titles[] = $title;
                if (count($titles) >= 3) {
                    break;
                }
            }
            if (!empty($titles)) {
                $highlights = ' Top findings: ' . implode('; ', $titles) . '.';
            }
        }

        $historyNote = '';
        if ($historyData !== null) {
            $historyCount = $this->countHistoryItems($historyData);
            $historyNote = " History records fetched: {$historyCount}.";
        } elseif ($historyError !== null) {
            $historyNote = ' History fetch skipped: ' . $historyError . '.';
        }

        return $headline . $counts . $highlights . $historyNote;
    }

    private function countHistoryItems(mixed $historyData): int
    {
        if (!is_array($historyData)) {
            return 0;
        }

        if (isset($historyData['data']) && is_array($historyData['data'])) {
            return count($historyData['data']);
        }

        if ($this->isListArray($historyData)) {
            return count($historyData);
        }

        foreach (['history', 'results', 'items', 'scans'] as $key) {
            if (isset($historyData[$key]) && is_array($historyData[$key])) {
                return count($historyData[$key]);
            }
        }

        return 0;
    }

    private function countBySeverity(array $findings, string $severity): int
    {
        $count = 0;
        foreach ($findings as $finding) {
            if (!is_array($finding)) {
                continue;
            }
            if (strtolower((string)($finding['severity'] ?? '')) === $severity) {
                $count++;
            }
        }
        return $count;
    }

    private function severityRank(string $severity): int
    {
        return match ($severity) {
            'critical' => 3,
            'warning' => 2,
            default => 1,
        };
    }

    private function extractSubdomains(array $scanResponse, string $rootDomain): array
    {
        $found = [];
        $rootDomain = strtolower($rootDomain);

        // Prioritise common containers first.
        $candidates = [
            $scanResponse['subdomains'] ?? null,
            $scanResponse['data']['subdomains'] ?? null,
            $scanResponse['results']['subdomains'] ?? null,
            $scanResponse['data']['results']['subdomains'] ?? null,
            $scanResponse['dns']['subdomains'] ?? null,
        ];

        foreach ($candidates as $candidate) {
            $this->collectSubdomains($candidate, $rootDomain, $found);
            if (count($found) >= self::MAX_DISCOVERIES) {
                break;
            }
        }

        if (count($found) < self::MAX_DISCOVERIES) {
            $this->collectSubdomains($scanResponse, $rootDomain, $found);
        }

        $domains = array_keys($found);
        sort($domains, SORT_STRING | SORT_FLAG_CASE);
        return array_slice($domains, 0, self::MAX_DISCOVERIES);
    }

    private function collectSubdomains(mixed $node, string $rootDomain, array &$found): void
    {
        if ($node === null || count($found) >= self::MAX_DISCOVERIES) {
            return;
        }

        if (is_string($node)) {
            $this->maybeAddSubdomain($node, $rootDomain, $found);
            return;
        }

        if (!is_array($node)) {
            return;
        }

        foreach ($node as $key => $value) {
            if (count($found) >= self::MAX_DISCOVERIES) {
                return;
            }

            if (is_string($key)) {
                $this->maybeAddSubdomain($key, $rootDomain, $found);
            }

            if (is_string($value)) {
                $this->maybeAddSubdomain($value, $rootDomain, $found);
                continue;
            }

            if (is_array($value)) {
                $this->collectSubdomains($value, $rootDomain, $found);
            }
        }
    }

    private function maybeAddSubdomain(string $candidate, string $rootDomain, array &$found): void
    {
        $value = strtolower(trim($candidate));
        if ($value === '' || str_contains($value, ' ')) {
            return;
        }

        $value = preg_replace('#^https?://#', '', $value);
        $value = preg_replace('#/.*$#', '', (string)$value);
        $value = rtrim((string)$value, '.');

        if ($value === '' || $value === $rootDomain) {
            return;
        }

        if (!preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$/', $value)) {
            return;
        }

        if (!str_ends_with($value, '.' . $rootDomain)) {
            return;
        }

        $found[$value] = true;
    }

    private function isListArray(array $array): bool
    {
        if ($array === []) {
            return true;
        }

        return array_keys($array) === range(0, count($array) - 1);
    }
}
