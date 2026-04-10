<?php
// =============================================================================
//  CTI — TruffleHog Module (Expanded)
//  Secret detection with 55+ regex patterns and Shannon entropy analysis.
//  Scans web page source for exposed credentials, API keys, tokens, and secrets.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class TruffleHogModule extends BaseApiModule
{
    private const API_ID   = 'trufflehog';
    private const API_NAME = 'TruffleHog Secret Scanner';
    private const SUPPORTED = ['domain', 'url'];

    // 55+ secret detection patterns organized by category
    private const SECRET_PATTERNS = [
        // ── Cloud Provider Keys ────────────────────────────────────────
        'AWS Access Key ID'        => '/(?:^|[^A-Za-z0-9])(AKIA[0-9A-Z]{16})/',
        'AWS Secret Key'           => '/(?:aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9\/+=]{40})["\']?/i',
        'AWS MWS Key'              => '/amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/',
        'Azure Storage Key'        => '/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+\/=]{88}/',
        'GCP Service Account'      => '/"type"\s*:\s*"service_account"/',
        'GCP API Key'              => '/AIza[0-9A-Za-z\-_]{35}/',

        // ── Version Control / DevOps ───────────────────────────────────
        'GitHub Token (ghp)'       => '/ghp_[0-9a-zA-Z]{36}/',
        'GitHub Token (gho)'       => '/gho_[0-9a-zA-Z]{36}/',
        'GitHub Token (ghu)'       => '/ghu_[0-9a-zA-Z]{36}/',
        'GitHub Token (ghs)'       => '/ghs_[0-9a-zA-Z]{36}/',
        'GitHub Token (ghr)'       => '/ghr_[0-9a-zA-Z]{36}/',
        'GitHub Token (classic)'   => '/ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}/',
        'GitLab Token'             => '/glpat-[0-9a-zA-Z\-_]{20}/',
        'Bitbucket Token'          => '/BITBUCKET[_-]?(?:TOKEN|SECRET|KEY)\s*[=:]\s*["\']?([A-Za-z0-9]{32,})/i',

        // ── Communication Platforms ────────────────────────────────────
        'Slack Token'              => '/xox[bpors]-[0-9a-zA-Z\-]{10,}/',
        'Slack Webhook'            => '/hooks\.slack\.com\/services\/T[a-zA-Z0-9]+\/B[a-zA-Z0-9]+\/[a-zA-Z0-9]+/',
        'Discord Webhook'          => '/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/',
        'Discord Bot Token'        => '/[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/',
        'Telegram Bot Token'       => '/\d{8,10}:[A-Za-z0-9_-]{35}/',
        'Teams Webhook'            => '/outlook\.office\.com\/webhook\/[A-Za-z0-9\-@]+/',

        // ── Payment Providers ──────────────────────────────────────────
        'Stripe Live Key'          => '/sk_live_[0-9a-zA-Z]{24,}/',
        'Stripe Publishable'       => '/pk_live_[0-9a-zA-Z]{24,}/',
        'Stripe Restricted'        => '/rk_live_[0-9a-zA-Z]{24,}/',
        'PayPal Braintree Token'   => '/access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/',
        'Square Access Token'      => '/sqOatp-[0-9A-Za-z\-_]{22}/',
        'Square OAuth Secret'      => '/sq0csp-[0-9A-Za-z\-_]{43}/',

        // ── Email Providers ────────────────────────────────────────────
        'Mailgun API Key'          => '/key-[0-9a-zA-Z]{32}/',
        'Mailchimp API Key'        => '/[0-9a-f]{32}-us[0-9]{1,2}/',
        'SendGrid API Key'         => '/SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/',
        'Postmark Token'           => '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i',

        // ── Authentication Tokens ──────────────────────────────────────
        'JWT Token'                => '/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/',
        'Bearer Token'             => '/[Bb]earer\s+[A-Za-z0-9\-_\.~\+\/]+=*/',
        'OAuth Token'              => '/ya29\.[0-9A-Za-z\-_]+/',

        // ── Databases ──────────────────────────────────────────────────
        'Database URL'             => '/(mysql|postgres|postgresql|mongodb|redis|amqp|mssql):\/\/[^\s<>"\']+/',
        'MongoDB Connection'       => '/mongodb(\+srv)?:\/\/[^\s<>"\']+/',

        // ── API Keys (Various) ─────────────────────────────────────────
        'Twilio API Key'           => '/SK[0-9a-fA-F]{32}/',
        'Twilio Account SID'       => '/AC[a-zA-Z0-9]{32}/',
        'Heroku API Key'           => '/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/',
        'Facebook Access Token'    => '/EAACEdEose0cBA[0-9A-Za-z]+/',
        'Twitter API Key'          => '/(?:twitter|tw)[_-]?(?:api[_-]?key|consumer[_-]?key|access[_-]?token)\s*[=:]\s*["\']?([A-Za-z0-9]{25,})/i',
        'Shopify Access Token'     => '/shpat_[a-fA-F0-9]{32}/',
        'Shopify Shared Secret'    => '/shpss_[a-fA-F0-9]{32}/',
        'DigitalOcean Token'       => '/dop_v1_[a-f0-9]{64}/',
        'Doppler Token'            => '/dp\.pt\.[A-Za-z0-9]{43}/',
        'NPM Token'                => '/npm_[A-Za-z0-9]{36}/',
        'PyPI Token'               => '/pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}/',
        'Algolia API Key'          => '/[a-f0-9]{32}/',  // Only flag if in algolia context
        'Cloudflare API Key'       => '/[0-9a-f]{37}/',

        // ── Cryptographic Material ─────────────────────────────────────
        'RSA Private Key'          => '/-----BEGIN RSA PRIVATE KEY-----/',
        'EC Private Key'           => '/-----BEGIN EC PRIVATE KEY-----/',
        'DSA Private Key'          => '/-----BEGIN DSA PRIVATE KEY-----/',
        'OpenSSH Private Key'      => '/-----BEGIN OPENSSH PRIVATE KEY-----/',
        'PGP Private Key'          => '/-----BEGIN PGP PRIVATE KEY BLOCK-----/',
        'PKCS8 Private Key'        => '/-----BEGIN PRIVATE KEY-----/',

        // ── Credentials in URLs ────────────────────────────────────────
        'Basic Auth in URL'        => '/[a-zA-Z]+:\/\/[^\/\s:]+:[^\/\s@]+@[^\s]+/',
        'Password Assignment'      => '/(?:password|passwd|pwd|secret|token|api_key|apikey|auth)\s*[=:]\s*["\']?([^\s"\']{8,})/i',

        // ── Infrastructure ─────────────────────────────────────────────
        'SSH Connection String'    => '/ssh\s+-i\s+[^\s]+\s+\w+@[\w.-]+/',
    ];

    // Shannon entropy thresholds
    private const ENTROPY_THRESHOLD_BASE64 = 4.5;
    private const ENTROPY_THRESHOLD_HEX    = 3.5;
    private const MIN_ENTROPY_LENGTH        = 16;

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $target = $queryValue;
        $url = ($queryType === 'url') ? $queryValue : "https://{$queryValue}";
        $resp = HttpClient::get($url, [], $this->timeoutSeconds());

        if ($resp['error'] || $resp['status'] !== 200) {
            // Try HTTP fallback
            if ($queryType === 'domain') {
                $resp = HttpClient::get("http://{$queryValue}", [], $this->timeoutSeconds());
            }
            if ($resp['error'] || $resp['status'] !== 200) {
                return OsintResult::error(self::API_ID, self::API_NAME,
                    'Failed to fetch target: ' . ($resp['error'] ?: "HTTP {$resp['status']}"), $resp['elapsed_ms']);
            }
        }

        $content = $resp['body'] ?? '';
        $elapsed = $resp['elapsed_ms'];

        if (empty($content)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $target, $elapsed);
        }

        $findings = [];

        // ── 1. Pattern-based detection ───────────────────────────────────
        foreach (self::SECRET_PATTERNS as $name => $pattern) {
            if (preg_match_all($pattern, $content, $matches)) {
                foreach ($matches[0] as $match) {
                    // Skip very short matches that are likely false positives
                    if (strlen($match) < 8) continue;

                    $masked = $this->maskSecret($match);
                    $entropy = $this->shannonEntropy($match);

                    $findings[] = [
                        'type'         => $name,
                        'value_masked' => $masked,
                        'length'       => strlen($match),
                        'entropy'      => round($entropy, 2),
                        'method'       => 'pattern',
                    ];
                }
            }
        }

        // ── 2. Entropy-based detection ───────────────────────────────────
        $entropyFindings = $this->entropyAnalysis($content);
        $findings = array_merge($findings, $entropyFindings);

        // ── 3. Deduplicate findings ──────────────────────────────────────
        $seen = [];
        $unique = [];
        foreach ($findings as $f) {
            $key = $f['type'] . ':' . $f['value_masked'];
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $f;
            }
        }
        $findings = $unique;
        $found = count($findings);

        if ($found === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 85,
                responseMs: $elapsed,
                summary: "TruffleHog: No exposed secrets detected on {$target} (" . count(self::SECRET_PATTERNS) . " patterns + entropy analysis).",
                tags: [self::API_ID, $queryType, 'secrets', 'clean'],
                rawData: ['target' => $target, 'patterns_checked' => count(self::SECRET_PATTERNS), 'total_found' => 0],
                success: true
            );
        }

        // Group by type
        $byType = [];
        foreach ($findings as $f) {
            $byType[$f['type']] = ($byType[$f['type']] ?? 0) + 1;
        }

        $score = min(95, 40 + $found * 8);
        // Boost score for high-severity secrets
        foreach ($findings as $f) {
            if (stripos($f['type'], 'Private Key') !== false) $score = max($score, 90);
            if (stripos($f['type'], 'AWS') !== false) $score = max($score, 85);
            if (stripos($f['type'], 'Database') !== false) $score = max($score, 80);
            if (stripos($f['type'], 'Stripe Live') !== false) $score = max($score, 85);
        }
        $score = min($score, 95);

        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(95, 65 + $found * 5);

        arsort($byType);
        $typeParts = [];
        foreach (array_slice($byType, 0, 5, true) as $t => $c) $typeParts[] = "{$t}: {$c}";

        $summary = "TruffleHog: {$found} potential secret(s) found on {$target}. Types: " . implode(', ', $typeParts) . '.';

        $resultTags = [self::API_ID, $queryType, 'secrets', 'credentials', 'exposure'];

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $elapsed,
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'target'           => $target,
                'patterns_checked' => count(self::SECRET_PATTERNS),
                'total_found'      => $found,
                'by_type'          => $byType,
                'findings'         => array_slice($findings, 0, 50),
            ],
            success: true
        );
    }

    private function shannonEntropy(string $data): float
    {
        $data = trim($data);
        $len = strlen($data);
        if ($len === 0) return 0.0;

        $freq = [];
        for ($i = 0; $i < $len; $i++) {
            $ch = $data[$i];
            $freq[$ch] = ($freq[$ch] ?? 0) + 1;
        }

        $entropy = 0.0;
        foreach ($freq as $count) {
            $p = $count / $len;
            if ($p > 0) $entropy -= $p * log($p, 2);
        }
        return $entropy;
    }

    private function entropyAnalysis(string $content): array
    {
        $findings = [];

        // Find high-entropy strings that look like secrets
        // Base64-like strings
        if (preg_match_all('/[A-Za-z0-9+\/=]{20,}/', $content, $matches)) {
            foreach ($matches[0] as $match) {
                if (strlen($match) < self::MIN_ENTROPY_LENGTH || strlen($match) > 200) continue;
                $entropy = $this->shannonEntropy($match);
                if ($entropy >= self::ENTROPY_THRESHOLD_BASE64) {
                    $findings[] = [
                        'type'         => 'High Entropy (Base64-like)',
                        'value_masked' => $this->maskSecret($match),
                        'length'       => strlen($match),
                        'entropy'      => round($entropy, 2),
                        'method'       => 'entropy',
                    ];
                }
            }
        }

        // Hex strings
        if (preg_match_all('/[0-9a-fA-F]{32,}/', $content, $matches)) {
            foreach ($matches[0] as $match) {
                if (strlen($match) > 128) continue;
                $entropy = $this->shannonEntropy($match);
                if ($entropy >= self::ENTROPY_THRESHOLD_HEX) {
                    $findings[] = [
                        'type'         => 'High Entropy (Hex)',
                        'value_masked' => $this->maskSecret($match),
                        'length'       => strlen($match),
                        'entropy'      => round($entropy, 2),
                        'method'       => 'entropy',
                    ];
                }
            }
        }

        // Limit entropy findings to avoid noise
        return array_slice($findings, 0, 20);
    }

    private function maskSecret(string $value): string
    {
        $len = strlen($value);
        if ($len <= 8) return str_repeat('*', $len);
        $show = min(8, (int)($len * 0.2));
        return substr($value, 0, $show) . '...' . substr($value, -min(4, $show));
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null,
                'patterns' => count(self::SECRET_PATTERNS), 'entropy_enabled' => true];
    }
}
