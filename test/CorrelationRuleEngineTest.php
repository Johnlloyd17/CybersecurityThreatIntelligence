<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/php/CorrelationRuleEngine.php';

return static function (): void {
    $engine = new CorrelationRuleEngine(dirname(__DIR__) . '/correlations');
    $rules = $engine->loadRules();

    if (count($rules) < 6) {
        throw new RuntimeException('Expected correlation rule files to be loaded from correlations/.');
    }

    $rows = [
        [
            'id' => 1,
            'api_source' => 'virustotal',
            'api_name' => 'VirusTotal',
            'query_type' => 'domain',
            'query_value' => 'gmail.com',
            'result_summary' => 'VirusTotal reported malicious indicators for gmail.com',
            'risk_score' => 90,
            'status' => 'completed',
            'enrichment_pass' => 0,
        ],
        [
            'id' => 2,
            'api_source' => 'shodan',
            'api_name' => 'Shodan',
            'query_type' => 'domain',
            'query_value' => 'gmail.com',
            'result_summary' => 'Shodan also reported suspicious exposure for gmail.com',
            'risk_score' => 82,
            'status' => 'completed',
            'enrichment_pass' => 0,
        ],
        [
            'id' => 3,
            'api_source' => 'alienvault',
            'api_name' => 'AlienVault',
            'query_type' => 'domain',
            'query_value' => 'gmail.com',
            'result_summary' => 'AlienVault enrichment chain discovered related infrastructure',
            'risk_score' => 40,
            'enriched_from' => 'gmail.com',
            'enrichment_pass' => 2,
        ],
    ];

    $findings = $engine->evaluate($rows, 'domain', 'gmail.com');
    if ($findings === []) {
        throw new RuntimeException('Expected at least one correlation finding.');
    }

    $thresholdFinding = null;
    foreach ($findings as $finding) {
        if (($finding['rule_name'] ?? '') === 'SpiderFoot-Style Cross-Source Threshold') {
            $thresholdFinding = $finding;
            break;
        }
    }

    if (!is_array($thresholdFinding)) {
        throw new RuntimeException('Expected SpiderFoot-style threshold rule to emit a finding.');
    }

    $linked = $thresholdFinding['linked_result_ids'] ?? [];
    sort($linked);
    if ($linked !== [1, 2]) {
        throw new RuntimeException('Threshold finding did not preserve linked source result IDs.');
    }
};
