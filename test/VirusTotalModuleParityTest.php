<?php

declare(strict_types=1);

if (!isset($_SERVER['HTTP_HOST'])) {
    $_SERVER['HTTP_HOST'] = 'localhost';
}
if (!isset($_SERVER['SERVER_NAME'])) {
    $_SERVER['SERVER_NAME'] = 'localhost';
}

require_once dirname(__DIR__) . '/php/config.php';
require_once dirname(__DIR__) . '/php/db.php';
require_once dirname(__DIR__) . '/php/GlobalSettings.php';
require_once dirname(__DIR__) . '/php/modules/VirusTotalModule.php';

return static function (): void {
    $module = new VirusTotalModule();
    $module->setSettings([
        'verify_hostnames' => '0',
        '__root_query_type' => 'domain',
        '__root_query_value' => 'gmail.com',
    ]);

    $reflection = new ReflectionClass($module);

    $looksMalicious = $reflection->getMethod('domainReportLooksMalicious');
    $primaryType = $reflection->getMethod('primaryDataType');
    $matchesRootTarget = $reflection->getMethod('matchesRootTarget');
    $buildDomainElements = $reflection->getMethod('buildDomainElementsFromV2Report');
    foreach ([$looksMalicious, $primaryType, $matchesRootTarget, $buildDomainElements] as $method) {
        $method->setAccessible(true);
    }

    $report = [
        'detected_urls' => [
            ['url' => 'https://malicious.example.test/path'],
        ],
        'domain_siblings' => [
            'example.org',
        ],
        'subdomains' => [
            'imap.gmail.com',
            'smtp.gmail.com',
        ],
    ];

    if ($looksMalicious->invoke($module, $report) !== true) {
        throw new RuntimeException('Expected legacy VT domain report to mark the root domain as malicious when detected_urls are present.');
    }

    $rootType = $primaryType->invoke($module, 'domain', 0, true);
    if ($rootType !== EventTypes::MALICIOUS_INTERNET_NAME) {
        throw new RuntimeException('Expected malicious domain primary type to map to Malicious Internet Name.');
    }

    if ($matchesRootTarget->invoke($module, 'imap.gmail.com') !== true) {
        throw new RuntimeException('Expected imap.gmail.com to be treated as part of the gmail.com target.');
    }
    if ($matchesRootTarget->invoke($module, 'example.org') !== false) {
        throw new RuntimeException('Expected example.org to be treated as an affiliate domain.');
    }

    /** @var array<int, OsintResult> $elements */
    $elements = $buildDomainElements->invoke($module, $report, 'gmail.com');
    if (count($elements) < 4) {
        throw new RuntimeException('Expected VT legacy domain expansion to emit both same-target and affiliate domain findings.');
    }

    $byType = [];
    foreach ($elements as $element) {
        $byType[$element->dataType ?? ''][] = strtolower((string)($element->rawData['host'] ?? ''));
    }

    if (!in_array('imap.gmail.com', $byType[EventTypes::INTERNET_NAME] ?? [], true)) {
        throw new RuntimeException('Expected subdomains to emit Internet Name findings.');
    }

    if (!in_array('example.org', $byType[EventTypes::AFFILIATE_INTERNET_NAME] ?? [], true)) {
        throw new RuntimeException('Expected external sibling domains to emit Affiliate - Internet Name findings.');
    }

    if (!in_array('example.org', $byType[EventTypes::AFFILIATE_DOMAIN_NAME] ?? [], true)) {
        throw new RuntimeException('Expected registrable affiliate domains to emit Affiliate - Domain Name findings.');
    }
};
