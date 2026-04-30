<?php

require_once __DIR__ . '/EventTypes.php';
require_once __DIR__ . '/SpiderFootModuleMapper.php';

final class ScanExportFormatter
{
    /** @var array<string,string>|null */
    private static ?array $labelToSpiderFootCode = null;

    /**
     * @param array<int,array<string,mixed>> $scans
     * @param array<int,array<string,mixed>> $results
     */
    public static function buildCsv(array $scans, array $results): string
    {
        $rows = self::buildFindingRows($scans, $results);

        $handle = fopen('php://temp', 'r+');
        if ($handle === false) {
            throw new RuntimeException('Unable to open temporary export stream.');
        }

        // BOM helps Excel open UTF-8 CSVs cleanly on Windows.
        fwrite($handle, "\xEF\xBB\xBF");
        fputcsv($handle, ['Scan Name', 'Updated', 'Type', 'Module', 'Source', 'F/P', 'Data']);

        foreach ($rows as $row) {
            fputcsv($handle, [
                $row['scan_name'],
                $row['updated'],
                $row['type'],
                $row['module'],
                $row['source'],
                $row['false_positive'],
                $row['data'],
            ]);
        }

        rewind($handle);
        $csv = stream_get_contents($handle);
        fclose($handle);

        return $csv === false ? '' : $csv;
    }

    /**
     * @param array<int,array<string,mixed>> $scans
     * @param array<int,array<string,mixed>> $results
     */
    public static function buildPdf(array $scans, array $results, string $exportedAt): string
    {
        $rows = self::buildFindingRows($scans, $results);
        $scanIndex = self::indexScans($scans);

        $lines = [
            'CTI Scan Export Report',
            'Exported at: ' . $exportedAt,
            'Total scans: ' . count($scans),
            'Total exported findings: ' . count($rows),
            '',
            'Scan Summary',
            '------------',
        ];

        foreach ($scans as $scan) {
            $scanId = (int)($scan['id'] ?? 0);
            $findingCount = 0;
            foreach ($rows as $row) {
                if ((int)($row['scan_id'] ?? 0) === $scanId) {
                    $findingCount++;
                }
            }

            $lines[] = sprintf(
                '[#%d] %s | Target: %s (%s) | Status: %s | Started: %s | Finished: %s | Findings: %d',
                $scanId,
                self::plainText((string)($scan['name'] ?? 'Untitled Scan')),
                self::plainText((string)($scan['target'] ?? '')),
                self::plainText((string)($scan['target_type'] ?? 'unknown')),
                strtoupper(self::plainText((string)($scan['status'] ?? 'unknown'))),
                self::plainText((string)($scan['started_at'] ?? '')),
                self::plainText((string)($scan['finished_at'] ?? '')),
                $findingCount
            );
        }

        $lines[] = '';
        $lines[] = 'Findings';
        $lines[] = '--------';

        if (!$rows) {
            $lines[] = 'No exported findings were available for the selected scan(s).';
        } else {
            foreach ($rows as $row) {
                $lines[] = sprintf(
                    '[%s] %s | %s | %s | FP: %s',
                    self::plainText($row['scan_name']),
                    self::plainText($row['updated']),
                    self::plainText($row['type']),
                    self::plainText($row['module']),
                    self::plainText($row['false_positive'])
                );
                $lines[] = '  Source: ' . self::plainText($row['source']);
                $lines[] = '  Data: ' . self::plainText($row['data']);
                $lines[] = '';
            }
        }

        return self::renderSimplePdf($lines);
    }

    /**
     * @param array<int,array<string,mixed>> $scans
     * @param array<int,array<string,mixed>> $events
     */
    public static function buildSpiderFootJson(array $scans, array $events): string
    {
        return json_encode(
            self::buildSpiderFootJsonRows($scans, $events),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        ) ?: '[]';
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    public static function sanitizePayload(array $payload): array
    {
        return self::sanitizeValue($payload);
    }

    /**
     * @param array<int,array<string,mixed>> $scans
     */
    public static function buildFilename(array $scans, string $extension): string
    {
        $extension = strtolower(trim($extension, '.'));
        if ($extension === '') {
            $extension = 'dat';
        }

        if (count($scans) === 1) {
            $name = trim((string)($scans[0]['name'] ?? 'CTI-Scan-Export'));
            $base = $name !== '' ? $name . '-CTI-export' : 'CTI-Scan-Export';
        } else {
            $base = 'CTI-scans-export-' . gmdate('Ymd-His');
        }

        $safe = preg_replace('/[^A-Za-z0-9._-]+/', '-', $base);
        $safe = trim((string)$safe, '-.');
        if ($safe === '') {
            $safe = 'CTI-export';
        }

        return $safe . '.' . $extension;
    }

    /**
     * @param array<int,array<string,mixed>> $scans
     */
    public static function buildSpiderFootJsonFilename(array $scans): string
    {
        return 'CTI.json';
    }

    /**
     * @param array<int,array<string,mixed>> $scans
     * @return array<int,array<string,mixed>>
     */
    private static function indexScans(array $scans): array
    {
        $index = [];
        foreach ($scans as $scan) {
            $index[(int)($scan['id'] ?? 0)] = $scan;
        }
        return $index;
    }

    /**
     * @param array<int,array<string,mixed>> $scans
     * @param array<int,array<string,mixed>> $events
     * @return array<int,array<string,mixed>>
     */
    private static function buildSpiderFootJsonRows(array $scans, array $events): array
    {
        $scanIndex = self::indexScans($scans);
        $rows = [];

        foreach ($events as $event) {
            $typeLabel = trim((string)($event['event_type'] ?? ''));
            if ($typeLabel === '' || strtoupper($typeLabel) === 'ROOT') {
                continue;
            }

            $scanId = (int)($event['scan_id'] ?? 0);
            $scan = $scanIndex[$scanId] ?? null;
            if (!$scan) {
                continue;
            }

            $moduleSlug = trim((string)($event['module_slug'] ?? ''));
            $module = self::moduleNameForSpiderFootJson($moduleSlug);
            $sourceData = trim((string)($event['source_data'] ?? ''));
            if ($sourceData === '') {
                $sourceData = trim((string)($scan['target'] ?? ''));
            }

            $rows[] = [
                'data' => (string)($event['event_data'] ?? ''),
                'event_type' => self::toSpiderFootEventCode($typeLabel),
                'module' => $module,
                'source_data' => $sourceData,
                'false_positive' => !empty($event['false_positive']) ? 1 : 0,
                'last_seen' => (string)($event['created_at'] ?? ''),
                'scan_name' => (string)($scan['name'] ?? ''),
                'scan_target' => (string)($scan['target'] ?? ''),
            ];
        }

        return $rows;
    }

    /**
     * @param array<int,array<string,mixed>> $scans
     * @param array<int,array<string,mixed>> $results
     * @return array<int,array<string,mixed>>
     */
    private static function buildFindingRows(array $scans, array $results): array
    {
        $scanIndex = self::indexScans($scans);
        $rows = [];

        foreach ($results as $result) {
            if (strtolower((string)($result['status'] ?? '')) === 'failed') {
                continue;
            }

            $scanId = (int)($result['scan_id'] ?? 0);
            $scan = $scanIndex[$scanId] ?? null;
            if (!$scan) {
                continue;
            }

            $rows[] = [
                'scan_id' => $scanId,
                'scan_name' => (string)($scan['name'] ?? ''),
                'updated' => (string)($result['queried_at'] ?? ''),
                'type' => self::displayType($result),
                'module' => (string)($result['api_source'] ?? ''),
                'source' => self::displaySource($result),
                'false_positive' => !empty($result['false_positive']) ? 'Y' : 'N',
                'data' => self::displayData($result),
            ];
        }

        return $rows;
    }

    /**
     * @param array<string,mixed> $result
     */
    private static function displayType(array $result): string
    {
        $type = trim((string)($result['data_type'] ?? ''));
        if ($type !== '') {
            return $type;
        }

        $queryType = trim((string)($result['query_type'] ?? 'unknown'));
        return ucwords(str_replace(['_', '-'], ' ', $queryType));
    }

    /**
     * @param array<string,mixed> $result
     */
    private static function displaySource(array $result): string
    {
        $source = trim((string)($result['query_value'] ?? ''));
        if ($source !== '') {
            return $source;
        }

        $source = trim((string)($result['enriched_from'] ?? ''));
        if ($source !== '') {
            return $source;
        }

        $source = trim((string)($result['source_ref'] ?? ''));
        return $source !== '' ? $source : 'ROOT';
    }

    /**
     * @param array<string,mixed> $result
     */
    private static function displayData(array $result): string
    {
        $data = trim((string)($result['result_summary'] ?? ''));
        if ($data !== '') {
            return $data;
        }

        $queryValue = trim((string)($result['query_value'] ?? ''));
        return $queryValue !== '' ? $queryValue : '(no data)';
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private static function sanitizeValue(mixed $value): mixed
    {
        if (is_array($value)) {
            $sanitized = [];
            foreach ($value as $key => $item) {
                $keyString = is_string($key) ? $key : (string)$key;
                if (self::isSensitiveKey($keyString)) {
                    $sanitized[$key] = '[REDACTED]';
                    continue;
                }
                $sanitized[$key] = self::sanitizeValue($item);
            }
            return $sanitized;
        }

        if (is_string($value)) {
            return self::sanitizeString($value);
        }

        return $value;
    }

    private static function isSensitiveKey(string $key): bool
    {
        return (bool)preg_match('/(?:^|_)(api_?key|secret|token|password|passphrase|auth_?token|authorization|credentials?)(?:$|_)/i', $key);
    }

    private static function sanitizeString(string $value): string
    {
        if ($value === '') {
            return $value;
        }

        $trimmed = ltrim($value);
        if ($trimmed !== '' && ($trimmed[0] === '{' || $trimmed[0] === '[')) {
            $decoded = json_decode($value, true);
            if (is_array($decoded)) {
                $reencoded = json_encode(
                    self::sanitizeValue($decoded),
                    JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                );
                if (is_string($reencoded)) {
                    return $reencoded;
                }
            }
        }

        $patterns = [
            '/([?&](?:api_?key|apikey|token|access_token|secret|password)=)([^&]+)/i',
            '/((?:api_?key|apikey|token|access_token|secret|password)"?\s*[:=]\s*"?)([^",\s}]+)/i',
            '/(\bAuthorization:\s*Bearer\s+)([A-Za-z0-9._\-]+)/i',
        ];

        $replacements = [
            '$1[REDACTED]',
            '$1[REDACTED]',
            '$1[REDACTED]',
        ];

        return (string)preg_replace($patterns, $replacements, $value);
    }

    private static function moduleNameForSpiderFootJson(string $moduleSlug): string
    {
        $normalized = strtolower(trim($moduleSlug));
        if ($normalized === '' || in_array($normalized, ['seed', 'engine', 'cti-python'], true)) {
            return 'CTI UI';
        }

        return SpiderFootModuleMapper::toSfpName($normalized) ?? $moduleSlug;
    }

    private static function toSpiderFootEventCode(string $typeLabel): string
    {
        $map = self::labelToSpiderFootCode();
        return $map[$typeLabel] ?? strtoupper((string)preg_replace('/[^A-Za-z0-9]+/', '_', trim($typeLabel)));
    }

    /**
     * @return array<string,string>
     */
    private static function labelToSpiderFootCode(): array
    {
        if (self::$labelToSpiderFootCode !== null) {
            return self::$labelToSpiderFootCode;
        }

        $map = [];
        $ref = new ReflectionClass(EventTypes::class);
        foreach ($ref->getConstants() as $name => $value) {
            if (is_string($value)) {
                $map[$value] = $name;
            }
        }

        $manual = [
            'Similar Domain' => 'SIMILARDOMAIN',
            'Leak Site URL' => 'LEAKSITE_URL',
            'Leak Site Content' => 'LEAKSITE_CONTENT',
            'Public Code Repository' => 'PUBLIC_CODE_REPO',
            'Email Address - Generic' => 'EMAILADDR_GENERIC',
            'Affiliate - Email Address' => 'AFFILIATE_EMAILADDR',
            'Internet Name - Unresolved' => 'INTERNET_NAME_UNRESOLVED',
            'Affiliate - Internet Name - Unresolved' => 'AFFILIATE_INTERNET_NAME_UNRESOLVED',
            'Linked URL - Internal' => 'LINKED_URL_INTERNAL',
            'Linked URL - External' => 'LINKED_URL_EXTERNAL',
            'Darknet Mention URL' => 'DARKNET_MENTION_URL',
            'Darknet Mention Web Content' => 'DARKNET_MENTION_CONTENT',
            'Wikipedia Page Edit' => 'WIKIPEDIA_PAGE_EDIT',
            'App Store Entry' => 'APPSTORE_ENTRY',
            'Search Engine Web Content' => 'SEARCH_ENGINE_WEB_CONTENT',
            'Raw DNS Records' => 'RAW_DNS_RECORDS',
            'Description - Abstract' => 'DESCRIPTION_ABSTRACT',
            'Description - Category' => 'DESCRIPTION_CATEGORY',
            'Physical Coordinates' => 'GEOINFO',
            'Physical Address' => 'PHYSICAL_ADDRESS',
            'Domain Name (Parent)' => 'PARENT_DOMAIN',
        ];

        self::$labelToSpiderFootCode = array_merge($map, $manual);
        return self::$labelToSpiderFootCode;
    }

    private static function plainText(string $value): string
    {
        $value = preg_replace('/\s+/', ' ', trim($value)) ?? '';
        $value = preg_replace('/[^\x20-\x7E]/', '?', $value) ?? '';
        return $value;
    }

    /**
     * @param array<int,string> $lines
     */
    private static function renderSimplePdf(array $lines): string
    {
        $pages = [];
        $pageLines = [];
        $lineCount = 0;
        $maxLinesPerPage = 44;

        foreach ($lines as $line) {
            $wrapped = self::wrapLine($line, 92);
            foreach ($wrapped as $wrappedLine) {
                $pageLines[] = $wrappedLine;
                $lineCount++;
                if ($lineCount >= $maxLinesPerPage) {
                    $pages[] = $pageLines;
                    $pageLines = [];
                    $lineCount = 0;
                }
            }
        }

        if ($pageLines || !$pages) {
            $pages[] = $pageLines;
        }

        $objects = [];

        $objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
        $objects[2] = ''; // Filled after page objects exist.
        $objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

        $pageObjectNumbers = [];
        $contentObjectNumbers = [];
        $nextObject = 4;

        foreach ($pages as $pageIndex => $pageLinesForPdf) {
            $pageObjectNumbers[$pageIndex] = $nextObject++;
            $contentObjectNumbers[$pageIndex] = $nextObject++;
        }

        foreach ($pages as $pageIndex => $pageLinesForPdf) {
            $contentStream = self::buildPageContentStream($pageLinesForPdf);
            $contentObject = $contentObjectNumbers[$pageIndex];
            $pageObject = $pageObjectNumbers[$pageIndex];

            $objects[$contentObject] = "<< /Length " . strlen($contentStream) . " >>\nstream\n"
                . $contentStream
                . "\nendstream";
            $objects[$pageObject] = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                . "/Resources << /Font << /F1 3 0 R >> >> /Contents {$contentObject} 0 R >>";
        }

        $kids = implode(' ', array_map(static fn(int $objNum): string => $objNum . ' 0 R', $pageObjectNumbers));
        $objects[2] = "<< /Type /Pages /Kids [ {$kids} ] /Count " . count($pageObjectNumbers) . " >>";

        ksort($objects);

        $pdf = "%PDF-1.4\n";
        $offsets = [0];

        foreach ($objects as $objectNumber => $body) {
            $offsets[$objectNumber] = strlen($pdf);
            $pdf .= $objectNumber . " 0 obj\n" . $body . "\nendobj\n";
        }

        $xrefOffset = strlen($pdf);
        $pdf .= "xref\n0 " . (count($objects) + 1) . "\n";
        $pdf .= "0000000000 65535 f \n";

        $maxObject = max(array_keys($objects));
        for ($i = 1; $i <= $maxObject; $i++) {
            $offset = $offsets[$i] ?? 0;
            $pdf .= sprintf("%010d 00000 n \n", $offset);
        }

        $pdf .= "trailer\n<< /Size " . (count($objects) + 1) . " /Root 1 0 R >>\n";
        $pdf .= "startxref\n{$xrefOffset}\n%%EOF";

        return $pdf;
    }

    /**
     * @param array<int,string> $lines
     */
    private static function buildPageContentStream(array $lines): string
    {
        $stream = "BT\n/F1 10 Tf\n14 TL\n50 760 Td\n";

        foreach ($lines as $index => $line) {
            if ($index > 0) {
                $stream .= "T*\n";
            }
            $stream .= '(' . self::escapePdfText(self::plainText($line)) . ") Tj\n";
        }

        $stream .= "ET";
        return $stream;
    }

    /**
     * @return array<int,string>
     */
    private static function wrapLine(string $line, int $width): array
    {
        $clean = self::plainText($line);
        if ($clean === '') {
            return [''];
        }

        $wrapped = wordwrap($clean, $width, "\n", true);
        return explode("\n", $wrapped);
    }

    private static function escapePdfText(string $value): string
    {
        return str_replace(
            ['\\', '(', ')'],
            ['\\\\', '\\(', '\\)'],
            $value
        );
    }
}
