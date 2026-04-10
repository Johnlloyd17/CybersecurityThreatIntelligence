<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/php/OsintEngine.php';
require_once dirname(__DIR__) . '/php/SpiderFootModuleMapper.php';

return static function (): void {
    $reflection = new ReflectionClass(OsintEngine::class);
    $handlerMapProperty = $reflection->getProperty('handlerMap');
    $handlerMapProperty->setAccessible(true);
    $handlerMap = $handlerMapProperty->getValue();

    if (!is_array($handlerMap) || $handlerMap === []) {
        throw new RuntimeException('OsintEngine handler map is empty.');
    }

    foreach ($handlerMap as $slug => $file) {
        $path = dirname(__DIR__) . '/php/modules/' . $file;
        if (!is_file($path)) {
            throw new RuntimeException("Mapped module file missing for {$slug}: {$file}");
        }
    }

    $sorted = OsintEngine::sortSlugsByPriority(
        ['github', 'testssl', 'dns-zone-transfer', 'virustotal'],
        [
            ['slug' => 'github', 'category' => 'osint'],
            ['slug' => 'testssl', 'category' => 'tools'],
            ['slug' => 'dns-zone-transfer', 'category' => 'dns'],
            ['slug' => 'virustotal', 'category' => 'threat'],
        ]
    );

    if (($sorted[0] ?? null) !== 'virustotal') {
        throw new RuntimeException('Priority sorting did not schedule virustotal first.');
    }

    $displayMap = SpiderFootModuleMapper::getDisplaySlugMap();
    if (($displayMap['virustotal'] ?? null) !== 'sfp_virustotal') {
        throw new RuntimeException('SpiderFoot display slug mapping for virustotal is incorrect.');
    }

    $ordered = SpiderFootModuleMapper::sortCtiSlugs(['virustotal', 'abstractapi', '_storage', 'abuse-ch']);
    if ($ordered !== ['_storage', 'abstractapi', 'abuse-ch', 'virustotal']) {
        throw new RuntimeException('SpiderFoot workbook order sorting is incorrect.');
    }
};
