<?php

declare(strict_types=1);

$files = glob(__DIR__ . DIRECTORY_SEPARATOR . '*Test.php') ?: [];
sort($files, SORT_NATURAL | SORT_FLAG_CASE);

$failures = 0;
foreach ($files as $file) {
    $runner = require $file;
    $label = basename($file);

    if (!is_callable($runner)) {
        fwrite(STDERR, "[FAIL] {$label}: test file did not return a callable." . PHP_EOL);
        $failures++;
        continue;
    }

    try {
        $runner();
        fwrite(STDOUT, "[PASS] {$label}" . PHP_EOL);
    } catch (Throwable $e) {
        fwrite(STDERR, "[FAIL] {$label}: {$e->getMessage()}" . PHP_EOL);
        $failures++;
    }
}

exit($failures > 0 ? 1 : 0);
