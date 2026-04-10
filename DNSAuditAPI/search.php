<?php
/**
 * DNSAudit API Integration - AJAX handler
 *
 * Actions:
 *   scan          - Run /v1/scan and store results
 *   export        - Fetch /export/json/:domain
 *   export_pdf    - Download /export/pdf/:domain
 *   history       - Fetch /v1/scan-history
 *   summaries     - Browse stored scan summaries from DB
 *   findings      - Browse stored findings from DB
 *   add_asset     - Add a domain to monitored assets
 *   update_status - Change finding status
 *   logs          - View API request logs
 *   categories    - Category list for filters
 */

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('html_errors', '0');
header('Content-Type: application/json; charset=utf-8');
ob_start();

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

set_exception_handler(static function (Throwable $e): void {
    sendJson(['error' => $e->getMessage()], 500);
});

register_shutdown_function(static function (): void {
    $last = error_get_last();
    if ($last === null) {
        return;
    }

    $fatalTypes = [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR];
    if (!in_array($last['type'], $fatalTypes, true)) {
        return;
    }

    sendJson(['error' => 'Fatal error: ' . $last['message']], 500);
});

require_once __DIR__ . '/src/Database.php';
require_once __DIR__ . '/src/DnsAuditClient.php';

$config = require __DIR__ . '/config.php';

try {
    $db = Database::connect($config['db']);
} catch (Throwable $e) {
    sendJson(['error' => 'Database connection failed: ' . $e->getMessage()], 500);
}

$client = new DnsAuditClient($config, $db);
$action = $_GET['action'] ?? 'scan';

switch ($action) {
    // -----------------------------------------------------------------
    // Run a DNS security scan via /v1/scan
    // -----------------------------------------------------------------
    case 'search':
    case 'scan':
        $domain = trim((string) ($_GET['domain'] ?? $_GET['term'] ?? ''));
        $save = ($_GET['save'] ?? '1') === '1';

        if ($domain === '') {
            sendJson(['error' => 'Domain is required'], 400);
        }
        if (!$client->isConfigured()) {
            sendJson(['error' => 'DNSAudit API key is not configured. Set your key in config.php (request access at https://dnsaudit.io/api).'], 400);
        }

        $dailyUsage = Database::getDailyApiUsage($db);
        $dailyLimit = (int) ($config['rate_limits']['daily_scans'] ?? 20);
        if ($dailyUsage >= $dailyLimit) {
            sendJson(['error' => "Daily scan limit reached ({$dailyUsage}/{$dailyLimit}). Resets at midnight UTC."], 429);
        }

        try {
            $scanResponse = $client->scan($domain);
        } catch (Throwable $e) {
            sendJson(['error' => 'Scan failed: ' . $e->getMessage()], 502);
        }

        $savedFindings = 0;
        $summaryId = null;

        if ($save) {
            try {
                $assetType = looksLikeHost($domain) ? 'host' : 'domain';
                $assetId = Database::addAsset($db, $domain, $assetType);

                $summaryData = $client->extractSummary($scanResponse, $assetId, $domain);
                $summaryId = Database::insertSummary($db, $summaryData);

                $findingRows = $client->normalizeFindings($scanResponse, $summaryId, $assetId, $domain);
                foreach ($findingRows as $row) {
                    if (Database::insertFinding($db, $row)) {
                        $savedFindings++;
                    }
                }
            } catch (Throwable $e) {
                sendJson(['error' => 'Scan succeeded but saving to database failed: ' . $e->getMessage()], 500);
            }
        }

        sendJson([
            'scan' => $scanResponse,
            'saved' => $savedFindings,
            'summary_id' => $summaryId,
            'daily_usage' => $dailyUsage + 1,
            'daily_limit' => $dailyLimit,
        ]);
        break;

    // -----------------------------------------------------------------
    // Export full results via /export/json/:domain
    // -----------------------------------------------------------------
    case 'export':
        $domain = trim((string) ($_GET['domain'] ?? ''));
        if ($domain === '') {
            sendJson(['error' => 'Domain is required'], 400);
        }
        if (!$client->isConfigured()) {
            sendJson(['error' => 'API key not configured.'], 400);
        }

        try {
            $exportData = $client->export($domain);
        } catch (Throwable $e) {
            sendJson(['error' => 'Export failed: ' . $e->getMessage()], 502);
        }

        sendJson(['export' => $exportData]);
        break;

    // -----------------------------------------------------------------
    // Export PDF report via /export/pdf/:domain
    // -----------------------------------------------------------------
    case 'export_pdf':
        $domain = trim((string) ($_GET['domain'] ?? ''));
        $pdfFormat = trim((string) ($_GET['pdf_format'] ?? 'detailed'));

        if ($domain === '') {
            sendJson(['error' => 'Domain is required'], 400);
        }
        if (!$client->isConfigured()) {
            sendJson(['error' => 'API key not configured.'], 400);
        }

        try {
            $pdfData = $client->exportPdf($domain, $pdfFormat);
        } catch (Throwable $e) {
            sendJson(['error' => 'PDF export failed: ' . $e->getMessage()], 502);
        }

        sendBinary(
            $pdfData['content'],
            $pdfData['content_type'] ?? 'application/pdf',
            $pdfData['filename'] ?? ($domain . '-dns-report.pdf')
        );
        break;

    // -----------------------------------------------------------------
    // Scan history via /v1/scan-history
    // -----------------------------------------------------------------
    case 'history':
        if (!$client->isConfigured()) {
            sendJson(['error' => 'API key not configured.'], 400);
        }

        $limit = max(1, min(100, (int) ($_GET['limit'] ?? 10)));

        try {
            $historyData = $client->scanHistory($limit);
        } catch (Throwable $e) {
            sendJson(['error' => 'History request failed: ' . $e->getMessage()], 502);
        }

        sendJson(['history' => $historyData]);
        break;

    // -----------------------------------------------------------------
    // Browse stored scan summaries from DB
    // -----------------------------------------------------------------
    case 'summaries':
        $filters = [
            'domain' => trim((string) ($_GET['domain'] ?? '')),
            'grade' => trim((string) ($_GET['grade'] ?? '')),
        ];
        $filters = array_filter($filters, static fn ($v): bool => $v !== '');
        $limit = max(1, min(100, (int) ($_GET['limit'] ?? 20)));

        $summaries = Database::getSummaries($db, $filters, $limit);
        sendJson(['summaries' => $summaries]);
        break;

    // -----------------------------------------------------------------
    // Browse stored findings from DB
    // -----------------------------------------------------------------
    case 'findings':
    case 'results':
        $filters = [
            'search' => trim((string) ($_GET['search'] ?? '')),
            'severity' => trim((string) ($_GET['severity'] ?? '')),
            'category' => trim((string) ($_GET['category'] ?? '')),
            'status' => trim((string) ($_GET['status'] ?? '')),
        ];
        $filters = array_filter($filters, static fn ($v): bool => $v !== '');

        $limit = max(1, min(500, (int) ($_GET['limit'] ?? 100)));
        $results = Database::getFindings($db, $filters, $limit, 0);
        sendJson(['findings' => $results]);
        break;

    // -----------------------------------------------------------------
    // Add monitored asset
    // -----------------------------------------------------------------
    case 'add_asset':
        $asset = trim((string) ($_GET['asset'] ?? ''));
        $type = trim((string) ($_GET['type'] ?? 'domain'));

        if ($asset === '') {
            sendJson(['error' => 'Asset value is required'], 400);
        }
        if (!in_array($type, ['domain', 'host'], true)) {
            sendJson(['error' => 'Invalid asset type'], 400);
        }

        $id = Database::addAsset($db, $asset, $type);
        sendJson(['success' => true, 'id' => $id]);
        break;

    // -----------------------------------------------------------------
    // Update finding status
    // -----------------------------------------------------------------
    case 'update_status':
        $id = (int) ($_GET['id'] ?? 0);
        $status = trim((string) ($_GET['status'] ?? ''));

        if ($id <= 0) {
            sendJson(['error' => 'Invalid finding ID'], 400);
        }
        if (!in_array($status, ['open', 'triaged', 'resolved', 'ignored'], true)) {
            sendJson(['error' => 'Invalid status'], 400);
        }

        Database::updateFindingStatus($db, $id, $status);
        sendJson(['success' => true]);
        break;

    // -----------------------------------------------------------------
    // API request logs
    // -----------------------------------------------------------------
    case 'logs':
        $logs = $db->query(
            'SELECT * FROM api_logs ORDER BY created_at DESC LIMIT 100'
        )->fetchAll();
        sendJson(['logs' => $logs]);
        break;

    // -----------------------------------------------------------------
    // Categories for filter dropdown
    // -----------------------------------------------------------------
    case 'categories':
        $categories = Database::getCategories($db);
        sendJson(['categories' => $categories]);
        break;

    default:
        sendJson(['error' => 'Unknown action: ' . $action], 400);
}

function looksLikeHost(string $input): bool
{
    return preg_match('/^[a-z0-9-]+(\.[a-z0-9-]+){2,}$/i', $input) === 1;
}

function sendJson(array $payload, int $statusCode = 200)
{
    if (!headers_sent()) {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
    }

    // Remove stray output (warnings/notices) that would break JSON parsing.
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function sendBinary(string $content, string $contentType, string $filename)
{
    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    $safeFilename = preg_replace('/[^A-Za-z0-9._-]/', '_', $filename);
    if (!is_string($safeFilename) || $safeFilename === '') {
        $safeFilename = 'dns-report.pdf';
    }

    if (!headers_sent()) {
        http_response_code(200);
        header('Content-Type: ' . $contentType);
        header('Content-Disposition: attachment; filename="' . $safeFilename . '"');
        header('Content-Length: ' . strlen($content));
        header('Cache-Control: no-store, no-cache, must-revalidate');
    }

    echo $content;
    exit;
}
