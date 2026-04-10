<?php
// =============================================================================
//  CTI — Cross-Referencer Module (Expanded)
//  Actual cross-correlation engine. Aggregates results from prior module runs,
//  computes composite threat score, identifies corroborating/contradicting
//  signals, and produces an intelligence summary with confidence weighting.
//  Supports: ip, domain, email, hash
// =============================================================================

require_once __DIR__ . '/../OsintResult.php';
require_once __DIR__ . '/BaseApiModule.php';

class CrossReferencerModule extends BaseApiModule
{
    private const API_ID   = 'cross-referencer';
    private const API_NAME = 'Cross-Referencer';
    private const SUPPORTED = ['ip', 'domain', 'email', 'hash'];

    // Module relevance map: which modules matter for each query type
    private const MODULE_MAP = [
        'ip' => [
            'abuseipdb'          => ['weight' => 1.0, 'category' => 'reputation'],
            'shodan'             => ['weight' => 0.9, 'category' => 'infrastructure'],
            'greynoise'          => ['weight' => 0.8, 'category' => 'reputation'],
            'virustotal'         => ['weight' => 1.0, 'category' => 'reputation'],
            'ipinfo'             => ['weight' => 0.4, 'category' => 'context'],
            'port-scanner-tcp'   => ['weight' => 0.7, 'category' => 'infrastructure'],
            'nmap-scanner'       => ['weight' => 0.8, 'category' => 'infrastructure'],
            'botscout'           => ['weight' => 0.6, 'category' => 'reputation'],
            'cleantalk'          => ['weight' => 0.6, 'category' => 'reputation'],
            'fortiguard'         => ['weight' => 0.7, 'category' => 'reputation'],
            'dns-resolver'       => ['weight' => 0.3, 'category' => 'context'],
            'bgpview'            => ['weight' => 0.5, 'category' => 'context'],
            'ip2location'        => ['weight' => 0.4, 'category' => 'context'],
            'maxmind'            => ['weight' => 0.5, 'category' => 'context'],
            'onionoo'            => ['weight' => 0.7, 'category' => 'reputation'],
            'threatfox'          => ['weight' => 0.9, 'category' => 'threat_intel'],
            'misp'               => ['weight' => 1.0, 'category' => 'threat_intel'],
            'opencti'            => ['weight' => 1.0, 'category' => 'threat_intel'],
        ],
        'domain' => [
            'virustotal'         => ['weight' => 1.0, 'category' => 'reputation'],
            'dns-resolver'       => ['weight' => 0.5, 'category' => 'infrastructure'],
            'ssl-analyzer'       => ['weight' => 0.6, 'category' => 'infrastructure'],
            'testssl'            => ['weight' => 0.7, 'category' => 'infrastructure'],
            'wappalyzer'         => ['weight' => 0.5, 'category' => 'fingerprint'],
            'whatweb'            => ['weight' => 0.5, 'category' => 'fingerprint'],
            'cmseek'             => ['weight' => 0.6, 'category' => 'fingerprint'],
            'wafw00f'            => ['weight' => 0.4, 'category' => 'infrastructure'],
            'dnstwist'           => ['weight' => 0.7, 'category' => 'brand_protection'],
            'retire-js'          => ['weight' => 0.7, 'category' => 'vulnerability'],
            'nuclei'             => ['weight' => 0.9, 'category' => 'vulnerability'],
            'snallygaster'       => ['weight' => 0.8, 'category' => 'vulnerability'],
            'trufflehog'         => ['weight' => 0.9, 'category' => 'vulnerability'],
            'yara-scanner'       => ['weight' => 0.8, 'category' => 'threat_intel'],
            'web-spider'         => ['weight' => 0.4, 'category' => 'recon'],
            'crt-sh'             => ['weight' => 0.5, 'category' => 'infrastructure'],
            'dnsdumpster'        => ['weight' => 0.5, 'category' => 'infrastructure'],
            'domaintools'        => ['weight' => 0.6, 'category' => 'context'],
            'passivedns'         => ['weight' => 0.6, 'category' => 'infrastructure'],
            'misp'               => ['weight' => 1.0, 'category' => 'threat_intel'],
            'opencti'            => ['weight' => 1.0, 'category' => 'threat_intel'],
        ],
        'email' => [
            'haveibeenpwned'     => ['weight' => 1.0, 'category' => 'breach'],
            'emailrep'           => ['weight' => 0.8, 'category' => 'reputation'],
            'hunter'             => ['weight' => 0.5, 'category' => 'context'],
            'leakcheck'          => ['weight' => 0.9, 'category' => 'breach'],
            'snusbase'           => ['weight' => 0.8, 'category' => 'breach'],
            'botscout'           => ['weight' => 0.6, 'category' => 'reputation'],
            'cleantalk'          => ['weight' => 0.5, 'category' => 'reputation'],
            'phonebook'          => ['weight' => 0.4, 'category' => 'recon'],
            'skymem'             => ['weight' => 0.4, 'category' => 'recon'],
            'misp'               => ['weight' => 0.9, 'category' => 'threat_intel'],
        ],
        'hash' => [
            'virustotal'         => ['weight' => 1.0, 'category' => 'reputation'],
            'hybrid-analysis'    => ['weight' => 0.9, 'category' => 'sandbox'],
            'malwarebazaar'      => ['weight' => 0.9, 'category' => 'threat_intel'],
            'threatfox'          => ['weight' => 0.8, 'category' => 'threat_intel'],
            'misp'               => ['weight' => 1.0, 'category' => 'threat_intel'],
            'opencti'            => ['weight' => 0.9, 'category' => 'threat_intel'],
            'intelx'             => ['weight' => 0.7, 'category' => 'threat_intel'],
        ],
    ];

    // Severity thresholds for composite score
    private const CORRELATION_RULES = [
        // If multiple reputation sources agree on high score => boost confidence
        'multi_reputation_agreement' => [
            'description' => 'Multiple reputation sources report high threat',
            'min_sources' => 2,
            'min_avg_score' => 60,
            'confidence_boost' => 15,
        ],
        // If infrastructure + reputation both flag => strong signal
        'infra_reputation_combo' => [
            'description' => 'Infrastructure exposure confirmed by reputation data',
            'requires' => ['infrastructure', 'reputation'],
            'min_score_each' => 40,
            'score_boost' => 10,
        ],
        // Threat intel confirmation
        'threat_intel_confirmed' => [
            'description' => 'Threat intelligence platform confirmed IOC',
            'category' => 'threat_intel',
            'min_score' => 50,
            'confidence_boost' => 20,
            'score_boost' => 15,
        ],
        // Contradicting signals (e.g., VT clean but AbuseIPDB dirty)
        'contradicting_signals' => [
            'description' => 'Sources disagree on threat level',
            'score_spread' => 40,
            'confidence_penalty' => 15,
        ],
    ];

    public function execute(string $queryType, string $queryValue, string $apiKey, string $baseUrl): OsintResult
    {
        if (!in_array($queryType, self::SUPPORTED, true)) {
            return OsintResult::error(self::API_ID, self::API_NAME, "Unsupported: {$queryType}");
        }

        $start = microtime(true);

        // Get prior results from settings (injected by OsintEngine)
        $priorResults = $this->getPriorResults();
        $moduleMap = self::MODULE_MAP[$queryType] ?? [];

        if (empty($priorResults)) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 100,
                responseMs: $ms,
                summary: "Cross-reference: No prior module results available for {$queryType} '{$queryValue}'. Run other modules first, then cross-reference.",
                tags: [self::API_ID, $queryType, 'informational', 'no_data'],
                rawData: [
                    'query_type'          => $queryType,
                    'recommended_modules' => array_keys($moduleMap),
                    'module_count'        => count($moduleMap),
                    'results_analyzed'    => 0,
                ],
                success: true
            );
        }

        // ── 1. Categorize and score prior results ─────────────────────────
        $byCategory  = [];
        $allScores   = [];
        $moduleStats = [];
        $tagCloud    = [];

        foreach ($priorResults as $r) {
            $api = $r['api'] ?? '';
            $score = $r['score'] ?? 0;
            $severity = $r['severity'] ?? 'info';
            $tags = $r['tags'] ?? [];
            $success = $r['success'] ?? false;

            if (!$success || $api === self::API_ID) continue;

            $info = $moduleMap[$api] ?? ['weight' => 0.5, 'category' => 'other'];
            $cat = $info['category'];
            $weight = $info['weight'];

            $byCategory[$cat][] = [
                'api' => $api,
                'score' => $score,
                'weight' => $weight,
                'weighted_score' => $score * $weight,
                'severity' => $severity,
            ];

            $allScores[] = $score;
            $moduleStats[$api] = ['score' => $score, 'severity' => $severity, 'category' => $cat, 'weight' => $weight];

            foreach ($tags as $t) {
                $tagCloud[$t] = ($tagCloud[$t] ?? 0) + 1;
            }
        }

        $analyzedCount = count($moduleStats);
        if ($analyzedCount === 0) {
            $ms = (int)((microtime(true) - $start) * 1000);
            return new OsintResult(
                api: self::API_ID, apiName: self::API_NAME,
                score: 0, severity: 'info', confidence: 50,
                responseMs: $ms,
                summary: "Cross-reference: No successful module results to correlate for '{$queryValue}'.",
                tags: [self::API_ID, $queryType, 'informational'],
                rawData: ['query_type' => $queryType, 'results_analyzed' => 0],
                success: true
            );
        }

        // ── 2. Composite weighted score ───────────────────────────────────
        $totalWeight = 0;
        $weightedSum = 0;
        foreach ($moduleStats as $stat) {
            $weightedSum += $stat['score'] * $stat['weight'];
            $totalWeight += $stat['weight'];
        }
        $compositeScore = $totalWeight > 0 ? (int)round($weightedSum / $totalWeight) : 0;

        // ── 3. Apply correlation rules ────────────────────────────────────
        $correlations = [];
        $confidenceAdj = 0;
        $scoreAdj = 0;

        // Multi-reputation agreement
        $repSources = $byCategory['reputation'] ?? [];
        if (count($repSources) >= 2) {
            $repAvg = array_sum(array_column($repSources, 'score')) / count($repSources);
            if ($repAvg >= 60) {
                $confidenceAdj += 15;
                $correlations[] = [
                    'rule' => 'multi_reputation_agreement',
                    'detail' => count($repSources) . " reputation sources agree (avg score: " . round($repAvg) . ")",
                    'impact' => '+15 confidence',
                ];
            }
        }

        // Infrastructure + reputation combo
        $infraScores = array_column($byCategory['infrastructure'] ?? [], 'score');
        $repScores   = array_column($byCategory['reputation'] ?? [], 'score');
        if (!empty($infraScores) && !empty($repScores)) {
            $maxInfra = max($infraScores);
            $maxRep   = max($repScores);
            if ($maxInfra >= 40 && $maxRep >= 40) {
                $scoreAdj += 10;
                $correlations[] = [
                    'rule' => 'infra_reputation_combo',
                    'detail' => "Infrastructure issues (score {$maxInfra}) corroborated by reputation data (score {$maxRep})",
                    'impact' => '+10 composite score',
                ];
            }
        }

        // Threat intel confirmation
        $tiSources = $byCategory['threat_intel'] ?? [];
        foreach ($tiSources as $ti) {
            if ($ti['score'] >= 50) {
                $confidenceAdj += 20;
                $scoreAdj += 15;
                $correlations[] = [
                    'rule' => 'threat_intel_confirmed',
                    'detail' => "{$ti['api']} confirmed IOC with score {$ti['score']}",
                    'impact' => '+15 score, +20 confidence',
                ];
                break; // one TI confirmation is enough
            }
        }

        // Contradicting signals
        if (count($allScores) >= 2) {
            $spread = max($allScores) - min($allScores);
            if ($spread >= 40) {
                $confidenceAdj -= 15;
                // Find the contradicting modules
                $highest = $lowest = null;
                foreach ($moduleStats as $api => $stat) {
                    if ($stat['score'] === max($allScores) && !$highest) $highest = $api;
                    if ($stat['score'] === min($allScores) && !$lowest) $lowest = $api;
                }
                $correlations[] = [
                    'rule' => 'contradicting_signals',
                    'detail' => "Score spread of {$spread} between {$highest} (" . max($allScores) . ") and {$lowest} (" . min($allScores) . ")",
                    'impact' => '-15 confidence',
                ];
            }
        }

        // ── 4. Final score & confidence ───────────────────────────────────
        $finalScore = min(95, max(0, $compositeScore + $scoreAdj));
        $baseConfidence = min(90, 40 + $analyzedCount * 8);
        $finalConfidence = min(95, max(20, $baseConfidence + $confidenceAdj));

        // ── 5. Category breakdown ─────────────────────────────────────────
        $categoryBreakdown = [];
        foreach ($byCategory as $cat => $entries) {
            $catScores = array_column($entries, 'score');
            $categoryBreakdown[$cat] = [
                'sources' => count($entries),
                'avg_score' => round(array_sum($catScores) / count($catScores)),
                'max_score' => max($catScores),
                'modules' => array_column($entries, 'api'),
            ];
        }

        // ── 6. Top tags ──────────────────────────────────────────────────
        arsort($tagCloud);
        $topTags = array_slice($tagCloud, 0, 10, true);

        // ── 7. Threat assessment ──────────────────────────────────────────
        $assessment = $this->generateAssessment($finalScore, $categoryBreakdown, $correlations, $queryType, $queryValue);

        $ms = (int)((microtime(true) - $start) * 1000);
        $severity = OsintResult::scoreToSeverity($finalScore);

        $summaryParts = ["Cross-reference for {$queryType} '{$queryValue}': {$analyzedCount} modules correlated"];
        $summaryParts[] = "Composite threat score: {$finalScore}/100 ({$severity})";
        if (!empty($correlations)) {
            $summaryParts[] = count($correlations) . " correlation rule(s) triggered";
        }
        $summaryParts[] = $assessment;

        $resultTags = [self::API_ID, $queryType, 'cross_reference', 'correlation'];
        if ($finalScore >= 60) $resultTags[] = 'high_threat';
        elseif ($finalScore >= 30) $resultTags[] = 'moderate_threat';

        return new OsintResult(
            api: self::API_ID, apiName: self::API_NAME,
            score: $finalScore, severity: $severity, confidence: $finalConfidence,
            responseMs: $ms,
            summary: implode('. ', array_slice($summaryParts, 0, 5)) . '.',
            tags: array_values(array_unique($resultTags)),
            rawData: [
                'query_type'         => $queryType,
                'results_analyzed'   => $analyzedCount,
                'composite_score'    => $compositeScore,
                'score_adjustment'   => $scoreAdj,
                'final_score'        => $finalScore,
                'confidence'         => $finalConfidence,
                'module_scores'      => $moduleStats,
                'category_breakdown' => $categoryBreakdown,
                'correlations'       => $correlations,
                'top_tags'           => $topTags,
                'assessment'         => $assessment,
            ],
            success: true
        );
    }

    private function getPriorResults(): array
    {
        // Prior results are injected via settings by OsintEngine
        $json = $this->str('prior_results', '[]');
        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }

    private function generateAssessment(int $score, array $cats, array $correlations, string $type, string $value): string
    {
        if ($score >= 75) {
            $verdict = "HIGH THREAT";
            $action  = "immediate investigation recommended";
        } elseif ($score >= 50) {
            $verdict = "MODERATE THREAT";
            $action  = "further analysis recommended";
        } elseif ($score >= 25) {
            $verdict = "LOW THREAT";
            $action  = "monitor and reassess";
        } else {
            $verdict = "MINIMAL THREAT";
            $action  = "no immediate action required";
        }

        $insights = [];
        if (isset($cats['threat_intel']) && $cats['threat_intel']['max_score'] >= 50) {
            $insights[] = "confirmed in threat intelligence databases";
        }
        if (isset($cats['reputation']) && $cats['reputation']['max_score'] >= 60) {
            $insights[] = "flagged by reputation services";
        }
        if (isset($cats['vulnerability']) && $cats['vulnerability']['max_score'] >= 50) {
            $insights[] = "active vulnerabilities detected";
        }
        if (isset($cats['breach']) && $cats['breach']['max_score'] >= 40) {
            $insights[] = "found in data breaches";
        }

        $msg = "{$verdict} — {$action}";
        if (!empty($insights)) {
            $msg .= ". Key findings: " . implode(', ', $insights);
        }
        return $msg;
    }

    public function healthCheck(string $apiKey, string $baseUrl): array
    {
        return ['status' => 'healthy', 'latency_ms' => 0, 'error' => null,
                'supported_types' => self::SUPPORTED,
                'correlation_rules' => count(self::CORRELATION_RULES)];
    }
}
