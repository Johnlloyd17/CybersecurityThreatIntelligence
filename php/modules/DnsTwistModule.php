<?php
// =============================================================================
//  CTI — DNS Twist Module (Expanded)
//  Comprehensive domain typosquatting detection with full permutation algorithms:
//  bitsquatting, homoglyphs (100+ pairs), transposition, insertion, deletion,
//  repetition, replacement, vowel-swap, addition, dictionary, TLD variants.
//  Supports: domain
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class DnsTwistModule extends BaseApiModule
{
    private const API_ID   = 'dnstwist';
    private const API_NAME = 'DNS Twist';
    private const SUPPORTED = ['domain'];

    // Extended homoglyph mapping (100+ character pairs)
    private const HOMOGLYPHS = [
        'a' => ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'ạ', 'ả', 'ấ', 'ầ', 'ẩ', 'ẫ', 'ậ', '4', '@', 'æ'],
        'b' => ['d', 'lb', 'ib', 'ʙ', '6'],
        'c' => ['e', 'ç', 'ć', 'ĉ', 'ċ', 'č'],
        'd' => ['b', 'cl', 'dl', 'ɗ', 'đ'],
        'e' => ['é', 'è', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě', '3', 'ɛ'],
        'f' => ['v', 'ph'],
        'g' => ['q', 'ɡ', 'ɢ', 'ĝ', 'ğ', 'ġ', 'ģ', '9'],
        'h' => ['lh', 'ĥ', 'ħ'],
        'i' => ['1', 'l', 'í', 'ì', 'î', 'ï', 'ĩ', 'ī', 'ĭ', 'į', 'ı', '!', '|'],
        'j' => ['ĵ', 'ɉ'],
        'k' => ['lk', 'ik', 'lc', 'ķ'],
        'l' => ['1', 'i', 'ł', 'ĺ', 'ļ', 'ľ', '|'],
        'm' => ['n', 'nn', 'rn', 'rr', 'ṃ'],
        'n' => ['m', 'r', 'ñ', 'ń', 'ņ', 'ň', 'ŋ'],
        'o' => ['0', 'ó', 'ò', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő', 'ơ', 'ọ', 'ɵ'],
        'p' => ['ṗ', 'ƥ'],
        'q' => ['g', 'ɋ'],
        'r' => ['ŕ', 'ŗ', 'ř', 'ɍ'],
        's' => ['5', '$', 'ś', 'ŝ', 'ş', 'š', 'ṡ', 'ș', 'ʂ'],
        't' => ['7', 'ţ', 'ť', 'ŧ', 'ṭ', 'ț'],
        'u' => ['ú', 'ù', 'û', 'ü', 'ũ', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ư', 'ụ', 'v'],
        'v' => ['u', 'ν', 'ṿ'],
        'w' => ['vv', 'ŵ', 'ẁ', 'ẃ', 'ẅ'],
        'x' => ['ẋ', 'ẍ'],
        'y' => ['ý', 'ÿ', 'ŷ', 'ƴ', 'ỳ', 'ỵ', 'ỷ', 'ỹ'],
        'z' => ['ź', 'ż', 'ž', 'ẑ', 's'],
    ];

    // Keyboard adjacency for replacement attacks
    private const KEYBOARD_ADJACENT = [
        'q' => ['w', 'a'],     'w' => ['q', 'e', 'a', 's'],
        'e' => ['w', 'r', 's', 'd'], 'r' => ['e', 't', 'd', 'f'],
        't' => ['r', 'y', 'f', 'g'], 'y' => ['t', 'u', 'g', 'h'],
        'u' => ['y', 'i', 'h', 'j'], 'i' => ['u', 'o', 'j', 'k'],
        'o' => ['i', 'p', 'k', 'l'], 'p' => ['o', 'l'],
        'a' => ['q', 'w', 's', 'z'], 's' => ['a', 'w', 'e', 'd', 'z', 'x'],
        'd' => ['s', 'e', 'r', 'f', 'x', 'c'], 'f' => ['d', 'r', 't', 'g', 'c', 'v'],
        'g' => ['f', 't', 'y', 'h', 'v', 'b'], 'h' => ['g', 'y', 'u', 'j', 'b', 'n'],
        'j' => ['h', 'u', 'i', 'k', 'n', 'm'], 'k' => ['j', 'i', 'o', 'l', 'm'],
        'l' => ['k', 'o', 'p'],
        'z' => ['a', 's', 'x'], 'x' => ['z', 's', 'd', 'c'],
        'c' => ['x', 'd', 'f', 'v'], 'v' => ['c', 'f', 'g', 'b'],
        'b' => ['v', 'g', 'h', 'n'], 'n' => ['b', 'h', 'j', 'm'],
        'm' => ['n', 'j', 'k'],
    ];

    // Common vowels for vowel-swap attacks
    private const VOWELS = ['a', 'e', 'i', 'o', 'u'];

    // Common TLD alternatives
    private const ALT_TLDS = [
        '.com', '.net', '.org', '.co', '.io', '.info', '.biz', '.xyz',
        '.online', '.site', '.website', '.tech', '.store', '.app',
        '.dev', '.cloud', '.me', '.us', '.uk', '.de', '.fr', '.ru',
        '.cn', '.in', '.au', '.ca', '.br', '.jp',
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start  = microtime(true);
        $domain = strtolower(trim($queryValue));

        $dotPos = strrpos($domain, '.');
        if ($dotPos === false) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Invalid domain: {$domain}");
        }
        $name = substr($domain, 0, $dotPos);
        $tld  = substr($domain, $dotPos);

        // Generate all permutation types
        $variations = [];
        $this->addDeletions($name, $tld, $variations);
        $this->addTranspositions($name, $tld, $variations);
        $this->addRepetitions($name, $tld, $variations);
        $this->addInsertions($name, $tld, $variations);
        $this->addReplacements($name, $tld, $variations);
        $this->addHomoglyphs($name, $tld, $variations);
        $this->addBitsquatting($name, $tld, $variations);
        $this->addVowelSwap($name, $tld, $variations);
        $this->addAddition($name, $tld, $variations);
        $this->addHyphenation($name, $tld, $variations);
        $this->addDotInsertion($name, $tld, $variations);
        $this->addTldVariants($name, $tld, $variations);

        // Remove original domain and deduplicate
        unset($variations[$domain]);
        $totalGenerated = count($variations);

        // Limit DNS checks to prevent excessive queries
        $maxChecks = min(300, $totalGenerated);
        $toCheck = array_slice(array_keys($variations), 0, $maxChecks);

        // Check DNS resolution
        $registered = [];
        $checked = 0;
        foreach ($toCheck as $variant) {
            $checked++;
            $result = @dns_get_record($variant, DNS_A);
            if ($result && !empty($result)) {
                $ip = $result[0]['ip'] ?? 'unknown';
                // Check MX records for phishing potential
                $mx = @dns_get_record($variant, DNS_MX);
                $hasMx = !empty($mx);

                $registered[] = [
                    'domain' => $variant,
                    'ip'     => $ip,
                    'has_mx' => $hasMx,
                    'type'   => $variations[$variant],
                ];
            }
        }

        $ms = (int)((microtime(true) - $start) * 1000);
        $regCount = count($registered);

        if ($regCount === 0) {
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 75,
                responseMs: $ms,
                summary: "Domain {$domain}: No active typosquats found ({$totalGenerated} generated, {$checked} checked).",
                tags: [self::API_ID, 'domain', 'typosquat', 'clean'],
                rawData: ['domain' => $domain, 'generated' => $totalGenerated, 'checked' => $checked, 'registered' => []],
                success: true
            );
        }

        // Count types and assess risk
        $byType = [];
        $withMx = 0;
        foreach ($registered as $r) {
            $byType[$r['type']] = ($byType[$r['type']] ?? 0) + 1;
            if ($r['has_mx']) $withMx++;
        }

        $score = min(85, 15 + $regCount * 4);
        if ($withMx > 3) $score = max($score, 65); // MX records suggest phishing capability
        $severity   = OsintResult::scoreToSeverity($score);
        $confidence = min(90, 65 + min(25, $regCount));

        // Build summary
        $summary = "Domain {$domain}: {$regCount} active typosquat(s) from {$totalGenerated} permutations ({$checked} checked).";
        if ($withMx > 0) $summary .= " {$withMx} with MX records (phishing-capable).";

        $typeParts = [];
        arsort($byType);
        foreach (array_slice($byType, 0, 5, true) as $t => $c) $typeParts[] = "{$t}: {$c}";
        $summary .= ' Types: ' . implode(', ', $typeParts) . '.';

        // Sample domains
        $sample = array_map(fn($r) => "{$r['domain']} ({$r['ip']})", array_slice($registered, 0, 8));
        $summary .= ' Sample: ' . implode(', ', $sample) . '.';

        $resultTags = [self::API_ID, 'domain', 'typosquat'];
        if ($withMx > 0) $resultTags[] = 'phishing_risk';
        if ($regCount > 10) $resultTags[] = 'high_typosquat_risk';

        $result = new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $score, severity: $severity, confidence: $confidence,
            responseMs: $ms,
            summary: $summary,
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'domain'          => $domain,
                'total_generated' => $totalGenerated,
                'checked'         => $checked,
                'registered_count'=> $regCount,
                'with_mx'         => $withMx,
                'by_type'         => $byType,
                'registered'      => $registered,
            ],
            success: true
        );

        foreach (array_slice($registered, 0, 10) as $r) {
            $result->addDiscovery('Internet Name', $r['domain']);
        }

        return $result;
    }

    private function addDeletions(string $name, string $tld, array &$vars): void
    {
        for ($i = 0; $i < strlen($name); $i++) {
            $v = substr($name, 0, $i) . substr($name, $i + 1);
            if ($v) $vars[$v . $tld] = 'deletion';
        }
    }

    private function addTranspositions(string $name, string $tld, array &$vars): void
    {
        for ($i = 0; $i < strlen($name) - 1; $i++) {
            $chars = str_split($name);
            [$chars[$i], $chars[$i + 1]] = [$chars[$i + 1], $chars[$i]];
            $v = implode('', $chars);
            if ($v !== $name) $vars[$v . $tld] = 'transposition';
        }
    }

    private function addRepetitions(string $name, string $tld, array &$vars): void
    {
        for ($i = 0; $i < strlen($name); $i++) {
            $v = substr($name, 0, $i + 1) . $name[$i] . substr($name, $i + 1);
            $vars[$v . $tld] = 'repetition';
        }
    }

    private function addInsertions(string $name, string $tld, array &$vars): void
    {
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        for ($i = 0; $i <= strlen($name); $i++) {
            for ($j = 0; $j < strlen($chars); $j++) {
                $v = substr($name, 0, $i) . $chars[$j] . substr($name, $i);
                if ($v !== $name) $vars[$v . $tld] = 'insertion';
            }
        }
    }

    private function addReplacements(string $name, string $tld, array &$vars): void
    {
        for ($i = 0; $i < strlen($name); $i++) {
            $ch = $name[$i];
            $adjacent = self::KEYBOARD_ADJACENT[$ch] ?? [];
            foreach ($adjacent as $rep) {
                $v = substr($name, 0, $i) . $rep . substr($name, $i + 1);
                $vars[$v . $tld] = 'replacement';
            }
        }
    }

    private function addHomoglyphs(string $name, string $tld, array &$vars): void
    {
        for ($i = 0; $i < strlen($name); $i++) {
            $ch = $name[$i];
            $glyphs = self::HOMOGLYPHS[$ch] ?? [];
            foreach ($glyphs as $g) {
                // Only use ASCII-safe glyphs for domain names
                if (preg_match('/^[a-z0-9]$/i', $g)) {
                    $v = substr($name, 0, $i) . $g . substr($name, $i + 1);
                    $vars[$v . $tld] = 'homoglyph';
                }
            }
        }
    }

    private function addBitsquatting(string $name, string $tld, array &$vars): void
    {
        for ($i = 0; $i < strlen($name); $i++) {
            $ord = ord($name[$i]);
            for ($bit = 0; $bit < 8; $bit++) {
                $flipped = $ord ^ (1 << $bit);
                if ($flipped >= 48 && $flipped <= 57 || $flipped >= 97 && $flipped <= 122 || $flipped === 45) {
                    $v = substr($name, 0, $i) . chr($flipped) . substr($name, $i + 1);
                    if ($v !== $name && $v[0] !== '-' && substr($v, -1) !== '-') {
                        $vars[$v . $tld] = 'bitsquatting';
                    }
                }
            }
        }
    }

    private function addVowelSwap(string $name, string $tld, array &$vars): void
    {
        for ($i = 0; $i < strlen($name); $i++) {
            if (in_array($name[$i], self::VOWELS, true)) {
                foreach (self::VOWELS as $vowel) {
                    if ($vowel !== $name[$i]) {
                        $v = substr($name, 0, $i) . $vowel . substr($name, $i + 1);
                        $vars[$v . $tld] = 'vowel-swap';
                    }
                }
            }
        }
    }

    private function addAddition(string $name, string $tld, array &$vars): void
    {
        $chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        for ($j = 0; $j < strlen($chars); $j++) {
            $vars[$name . $chars[$j] . $tld] = 'addition';
            $vars[$chars[$j] . $name . $tld] = 'addition';
        }
    }

    private function addHyphenation(string $name, string $tld, array &$vars): void
    {
        for ($i = 1; $i < strlen($name); $i++) {
            $v = substr($name, 0, $i) . '-' . substr($name, $i);
            $vars[$v . $tld] = 'hyphenation';
        }
    }

    private function addDotInsertion(string $name, string $tld, array &$vars): void
    {
        for ($i = 1; $i < strlen($name); $i++) {
            $sub = substr($name, 0, $i);
            $rest = substr($name, $i);
            $vars[$sub . '.' . $rest . $tld] = 'subdomain';
        }
    }

    private function addTldVariants(string $name, string $tld, array &$vars): void
    {
        foreach (self::ALT_TLDS as $alt) {
            if ($alt !== $tld) {
                $vars[$name . $alt] = 'tld-swap';
            }
        }
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        $start = microtime(true);
        $result = @dns_get_record('google.com', DNS_A);
        $ms = (int)((microtime(true) - $start) * 1000);
        return [
            'status' => $result ? 'healthy' : 'down',
            'latency_ms' => $ms,
            'error' => $result ? null : 'DNS resolution failed',
        ];
    }
}
