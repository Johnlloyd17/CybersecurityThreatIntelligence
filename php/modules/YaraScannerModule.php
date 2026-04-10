<?php
// =============================================================================
//  CTI — YARA Scanner Module
//  PHP-based YARA rule matching against web page content and URLs.
//  Uses pattern matching to detect malware indicators, phishing kits,
//  cryptocurrency miners, webshells, and other threats.
//  Supports: domain, url
// =============================================================================

require_once __DIR__ . '/../HttpClient.php';
require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class YaraScannerModule extends BaseApiModule
{
    private const API_ID   = 'yara-scanner';
    private const API_NAME = 'YARA Scanner';
    private const SUPPORTED = ['domain', 'url'];

    // PHP-based YARA-like rules: name => [pattern => regex, severity => int, description]
    private const RULES = [
        // Webshells
        'webshell_php_generic' => [
            'pattern'     => '/\b(eval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(|(?:shell_exec|passthru|system|exec|popen|proc_open)\s*\(\s*\$)/i',
            'severity'    => 90,
            'description' => 'PHP webshell code detected (eval/exec patterns)',
            'category'    => 'webshell',
        ],
        'webshell_upload' => [
            'pattern'     => '/\b(?:move_uploaded_file|copy\s*\(\s*\$_FILES|file_put_contents\s*\(\s*\$_(?:GET|POST|REQUEST))/i',
            'severity'    => 85,
            'description' => 'File upload webshell pattern detected',
            'category'    => 'webshell',
        ],
        // Cryptocurrency miners
        'cryptominer_coinhive' => [
            'pattern'     => '/(?:coinhive\.min\.js|CoinHive\.Anonymous|cryptonight\.wasm|miner\.start|coin-hive\.com|coinhive\.com)/i',
            'severity'    => 75,
            'description' => 'CoinHive or similar crypto miner detected',
            'category'    => 'cryptominer',
        ],
        'cryptominer_generic' => [
            'pattern'     => '/(?:WebAssembly\.instantiate.*(?:cryptonight|cn\/|randomx)|(?:minero|deepminer|webminerpool|coinimp)\.(?:js|min\.js))/i',
            'severity'    => 75,
            'description' => 'Generic cryptocurrency miner detected',
            'category'    => 'cryptominer',
        ],
        // Phishing kits
        'phishing_login_form' => [
            'pattern'     => '/(?:<form[^>]*action\s*=\s*["\'][^"\']*(?:login|signin|verify|secure|update|confirm)[^"\']*["\'][^>]*>.*(?:password|passwd|pass_word))/is',
            'severity'    => 70,
            'description' => 'Suspicious login/phishing form detected',
            'category'    => 'phishing',
        ],
        'phishing_brand_impersonation' => [
            'pattern'     => '/(?:(?:paypal|apple|microsoft|google|amazon|netflix|facebook|instagram|whatsapp)[\s._-]*(?:security|verify|confirm|update|login|signin|account).*<(?:form|input))/is',
            'severity'    => 80,
            'description' => 'Brand impersonation phishing page detected',
            'category'    => 'phishing',
        ],
        // Malware distribution
        'malware_dropper_js' => [
            'pattern'     => '/(?:document\.write\s*\(\s*unescape\s*\(|eval\s*\(\s*String\.fromCharCode|(?:window\.)?location\s*=\s*["\']data:text\/html;base64)/i',
            'severity'    => 80,
            'description' => 'JavaScript malware dropper pattern detected',
            'category'    => 'malware',
        ],
        'malware_iframe_injection' => [
            'pattern'     => '/<iframe[^>]*(?:style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*[01]px|height\s*:\s*[01]px))[^>]*src\s*=\s*["\']https?:\/\//i',
            'severity'    => 75,
            'description' => 'Hidden iframe injection (malware distribution vector)',
            'category'    => 'malware',
        ],
        // Data exfiltration
        'exfil_keylogger' => [
            'pattern'     => '/(?:addEventListener\s*\(\s*["\']key(?:down|press|up)["\']\s*,.*(?:XMLHttpRequest|fetch|navigator\.sendBeacon|new\s+Image))/is',
            'severity'    => 85,
            'description' => 'JavaScript keylogger pattern detected',
            'category'    => 'exfiltration',
        ],
        'exfil_form_grabber' => [
            'pattern'     => '/(?:addEventListener\s*\(\s*["\']submit["\']\s*,.*(?:XMLHttpRequest|fetch)\s*\(\s*["\']https?:\/\/(?!(?:www\.)?(?:google|facebook|microsoft|apple)\.))/is',
            'severity'    => 70,
            'description' => 'Form data grabber/exfiltrator detected',
            'category'    => 'exfiltration',
        ],
        // Skimmers (Magecart-style)
        'skimmer_cc_harvest' => [
            'pattern'     => '/(?:(?:card[_-]?num|cc[_-]?num|credit[_-]?card|payment[_-]?card|card[_-]?number).*(?:XMLHttpRequest|fetch|navigator\.sendBeacon|new\s+Image\(\)\.src))/is',
            'severity'    => 95,
            'description' => 'Credit card skimmer (Magecart-style) detected',
            'category'    => 'skimmer',
        ],
        'skimmer_payment_overlay' => [
            'pattern'     => '/(?:createElement\s*\(\s*["\'](?:div|form|iframe)["\']\).*(?:checkout|payment|billing).*(?:position\s*:\s*(?:fixed|absolute)|z-index\s*:\s*\d{4,}))/is',
            'severity'    => 85,
            'description' => 'Payment overlay injection detected',
            'category'    => 'skimmer',
        ],
        // SEO spam
        'seo_spam_injection' => [
            'pattern'     => '/(?:(?:viagra|cialis|levitra|pharmacy|payday\s*loan|casino\s*online|buy\s*cheap).*<a\s+href\s*=\s*["\']https?:\/\/)/is',
            'severity'    => 45,
            'description' => 'SEO spam link injection detected',
            'category'    => 'seo_spam',
        ],
        // Suspicious redirects
        'suspicious_redirect' => [
            'pattern'     => '/(?:(?:window\.)?(?:location|top\.location)\s*=\s*(?:decodeURIComponent|atob|unescape)\s*\(|meta\s+http-equiv\s*=\s*["\']refresh["\']\s+content\s*=\s*["\']0\s*;\s*url\s*=)/i',
            'severity'    => 60,
            'description' => 'Suspicious redirect/obfuscation detected',
            'category'    => 'redirect',
        ],
        // Backdoor indicators
        'backdoor_c2_beacon' => [
            'pattern'     => '/(?:setInterval\s*\(\s*function\s*\(\)\s*\{.*(?:XMLHttpRequest|fetch)\s*\(\s*["\']https?:\/\/.*\}\s*,\s*(?:\d{4,}|["\']))/is',
            'severity'    => 80,
            'description' => 'Periodic C2 beacon pattern detected',
            'category'    => 'backdoor',
        ],
        'backdoor_encoded_payload' => [
            'pattern'     => '/(?:eval\s*\(\s*atob\s*\(\s*["\'][A-Za-z0-9+\/=]{50,}["\']\s*\)|(?:var|let|const)\s+\w+\s*=\s*["\'][A-Za-z0-9+\/=]{100,}["\'])/i',
            'severity'    => 75,
            'description' => 'Large encoded/obfuscated payload detected',
            'category'    => 'backdoor',
        ],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);
        $target = ($queryType === 'domain') ? "http://{$queryValue}" : $queryValue;

        // Fetch page content
        $resp = HttpClient::get($target, [], $this->timeoutSeconds());

        if ($resp['error'] || $resp['status'] === 0) {
            return OsintResult::error(self::API_ID, self::API_NAME, $resp['error'] ?? 'Connection failed', $resp['elapsed_ms']);
        }

        $body = $resp['body'] ?? '';
        if (empty($body)) {
            return OsintResult::notFound(self::API_ID, self::API_NAME, $queryValue, $resp['elapsed_ms']);
        }

        // Run all YARA-like rules against the content
        $matches    = [];
        $maxScore   = 0;
        $categories = [];

        foreach (self::RULES as $ruleName => $rule) {
            if (preg_match($rule['pattern'], $body, $m)) {
                $matches[] = [
                    'rule'        => $ruleName,
                    'description' => $rule['description'],
                    'severity'    => $rule['severity'],
                    'category'    => $rule['category'],
                    'match_preview' => substr($m[0], 0, 100),
                ];
                $maxScore = max($maxScore, $rule['severity']);
                $categories[$rule['category']] = true;
            }
        }

        $ms = (int)((microtime(true) - $start) * 1000);
        $matchCount = count($matches);

        if ($matchCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 85,
                responseMs: $ms,
                summary: "YARA scan of {$queryValue}: No malicious patterns detected ({$this->ruleCount()} rules checked).",
                tags: [self::API_ID, $queryType, 'clean'],
                rawData: ['target' => $queryValue, 'rules_checked' => $this->ruleCount(), 'matches' => 0],
                success: true
            );
        }

        $severity   = OsintResult::scoreToSeverity($maxScore);
        $confidence = min(95, 70 + $matchCount * 5);
        $catList    = implode(', ', array_keys($categories));

        $summary = "YARA scan of {$queryValue}: {$matchCount} rule(s) matched (max severity: {$maxScore}). Categories: {$catList}.";

        $resultTags = [self::API_ID, $queryType, 'malware_scan'];
        foreach (array_keys($categories) as $c) {
            $resultTags[] = $c;
        }

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $maxScore, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'target'        => $queryValue,
                'rules_checked' => $this->ruleCount(),
                'match_count'   => $matchCount,
                'matches'       => $matches,
                'categories'    => array_keys($categories),
            ],
            success: true
        );
    }

    private function ruleCount(): int
    {
        return count(self::RULES);
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'up', 'latency_ms' => 0, 'error' => null, 'rules_loaded' => $this->ruleCount()];
    }
}
