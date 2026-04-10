<?php
// =============================================================================
//  PHASE 4 OPS - SPIDERFOOT COMPARISON RUNNER
//  Imports SpiderFoot CSV/JSON export and computes parity against a CTI scan.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';
require_once __DIR__ . '/../SpiderFootDiffValidator.php';

$usage = <<<TXT
Usage:
  php php/ops/phase4_spiderfoot_compare.php --scan-id=123 --file=spiderfoot.csv [--format=csv|json] [--strict] [--min-score=70]

Options:
  --scan-id=...   CTI scan ID to compare against
  --file=...      SpiderFoot export file path (CSV or JSON)
  --format=...    Optional explicit format override (csv|json)
  --strict        Exit non-zero if parity score is below --min-score
  --min-score=... Minimum parity score when strict mode is enabled (default: 70)
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$scanId = ops_int($args, 'scan-id', 0);
$fileArg = ops_str($args, 'file', '');
$formatArg = strtolower(ops_str($args, 'format', ''));
$strict = ops_bool($args, 'strict', false);
$minScore = (float)ops_int($args, 'min-score', 70);

if ($scanId <= 0 || $fileArg === '') {
    ops_print_usage($usage);
    exit(1);
}

if (!preg_match('/^[A-Za-z]:[\\\\\\/]/', $fileArg)) {
    $filePath = realpath(getcwd() . DIRECTORY_SEPARATOR . $fileArg) ?: realpath($fileArg);
} else {
    $filePath = realpath($fileArg);
}

if ($filePath === false || !is_file($filePath)) {
    fwrite(STDERR, "[phase4] File not found: {$fileArg}\n");
    exit(1);
}

$format = $formatArg;
if ($format === '') {
    $ext = strtolower((string)pathinfo($filePath, PATHINFO_EXTENSION));
    $format = $ext === 'json' ? 'json' : 'csv';
}

if (!in_array($format, ['csv', 'json'], true)) {
    fwrite(STDERR, "[phase4] Unsupported format: {$format}\n");
    exit(1);
}

$scan = DB::queryOne("SELECT id, name, target, target_type FROM scans WHERE id = :id", [':id' => $scanId]);
if ($scan === null) {
    fwrite(STDERR, "[phase4] Scan not found: {$scanId}\n");
    exit(1);
}

$payload = (string)file_get_contents($filePath);
$validator = new SpiderFootDiffValidator($scanId);

if ($format === 'json') {
    $import = $validator->importJson($payload, basename($filePath));
} else {
    $import = $validator->importCsv($payload, basename($filePath));
}

if (!($import['success'] ?? false)) {
    $error = (string)($import['error'] ?? 'SpiderFoot import failed.');
    fwrite(STDERR, "[phase4] {$error}\n");
    exit(2);
}

$diff = $validator->compare();
$parityScore = (float)($diff['parity_score'] ?? 0.0);

$report = [
    'generated_at_utc' => gmdate('c'),
    'scan' => [
        'id' => (int)$scan['id'],
        'name' => (string)($scan['name'] ?? ''),
        'target' => (string)($scan['target'] ?? ''),
        'target_type' => (string)($scan['target_type'] ?? ''),
    ],
    'source_file' => $filePath,
    'format' => $format,
    'import' => $import,
    'diff' => $diff,
];

$reportPath = ops_write_json_report($report, 'phase4_spiderfoot_diff');

fwrite(STDOUT, "SpiderFoot Diff Complete\n");
fwrite(STDOUT, "Scan ID      : {$scanId}\n");
fwrite(STDOUT, "Source File  : {$filePath}\n");
fwrite(STDOUT, "Parity Score : {$parityScore}\n");
fwrite(STDOUT, "Report       : {$reportPath}\n");

if ($strict && $parityScore < $minScore) {
    fwrite(STDERR, "[phase4] Parity score {$parityScore} is below required threshold {$minScore}.\n");
    exit(3);
}

exit(0);

