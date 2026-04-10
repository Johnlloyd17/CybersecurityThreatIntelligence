<?php
// Temporary script to fix encoding issues in ScanExecutor.php
$file = __DIR__ . '/ScanExecutor.php';
$content = file_get_contents($file);

// Fix all common mojibake patterns with safe ASCII equivalents
$replacements = [
    "\xc3\xa2\xe2\x82\xac\xe2\x80\x9c" => '--',  // em dash mojibake variant 1
    "\xc3\xa2\xe2\x82\xac\xe2\x80\x9d" => '--',  // em dash mojibake variant 2
    "\xc3\xa2\xe2\x82\xac\xe2\x80\x98" => "'",    // left single quote mojibake
    "\xc3\xa2\xe2\x82\xac\xe2\x80\x99" => "'",    // right single quote mojibake
    "\xc3\xa2\xe2\x82\xac\xe2\x80\xa2" => '*',    // bullet mojibake
];

foreach ($replacements as $bad => $good) {
    $content = str_replace($bad, $good, $content);
}

// Also fix remaining raw mojibake sequences that PHP can't handle in strings
// Search for â€" (3 byte mojibake for em dash: c3a2 c280 c293)
$content = preg_replace('/\xc3\xa2\x80[\x90-\x9f]/u', '--', $content);

file_put_contents($file, $content);
echo "Fixed.\n";
