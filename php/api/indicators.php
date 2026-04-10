<?php
// =============================================================================
//  CTI — THREAT INDICATORS API
//  php/api/indicators.php
//
//  GET  ?action=list    — Paginated list of threat indicators
//  GET  ?action=stats   — Severity breakdown counts
//  POST ?action=delete  — Remove an indicator (admin only)
// =============================================================================

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../security-headers.php';
require_once __DIR__ . '/../db.php';

SecurityHeaders::init();
header('Content-Type: application/json; charset=utf-8');

// Auth gate
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
$userId   = $_SESSION['user_id']   ?? null;
$userRole = $_SESSION['user_role'] ?? null;
if (!$userId) {
    jsonInd(401, ['error' => 'Authentication required.']);
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'list':   handleList();                     break;
    case 'stats':  handleStats();                    break;
    case 'delete':
        if (strtolower($userRole ?? '') !== 'admin') jsonInd(403, ['error' => 'Administrator access required.']);
        handleDelete();
        break;
    case 'delete_batch':
        if (strtolower($userRole ?? '') !== 'admin') jsonInd(403, ['error' => 'Administrator access required.']);
        handleDeleteBatch();
        break;
    default:       jsonInd(400, ['error' => 'Unknown action.']);
}

// =============================================================================
//  HANDLERS
// =============================================================================

function handleList(): void
{
    $page    = max(1, (int)($_GET['page']     ?? 1));
    $limit   = min(100, max(1, (int)($_GET['limit']  ?? 25)));
    $offset  = ($page - 1) * $limit;
    $search  = trim($_GET['search']   ?? '');
    $type    = trim($_GET['type']     ?? '');
    $sev     = trim($_GET['severity'] ?? '');

    $where   = [];
    $params  = [];

    if ($search !== '') {
        $where[]  = 'indicator_value LIKE :search';
        $params[':search'] = '%' . $search . '%';
    }
    if ($type !== '' && in_array($type, ['domain','ip','url','hash','email','cve'], true)) {
        $where[]  = 'indicator_type = :type';
        $params[':type'] = $type;
    }
    if ($sev !== '' && in_array($sev, ['critical','high','medium','low','info','unknown'], true)) {
        $where[]  = 'severity = :sev';
        $params[':sev'] = $sev;
    }

    $whereClause = $where ? 'WHERE ' . implode(' AND ', $where) : '';

    try {
        $total = (int)(DB::queryOne(
            "SELECT COUNT(*) AS n FROM threat_indicators {$whereClause}",
            $params
        )['n'] ?? 0);

        $pdo  = DB::connect();
        $stmt = $pdo->prepare(
            "SELECT id, indicator_type, indicator_value, source, severity, confidence,
                    tags, first_seen, last_seen, updated_at
               FROM threat_indicators {$whereClause}
              ORDER BY FIELD(severity,'critical','high','medium','low','info','unknown'), last_seen DESC
              LIMIT :limit OFFSET :offset"
        );
        foreach ($params as $k => $v) $stmt->bindValue($k, $v);
        $stmt->bindValue(':limit',  $limit,  PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll();

        // Decode JSON tags column
        foreach ($rows as &$row) {
            $row['tags'] = $row['tags'] ? json_decode($row['tags'], true) : [];
        }

        jsonInd(200, [
            'indicators'  => $rows,
            'total'       => $total,
            'page'        => $page,
            'limit'       => $limit,
            'total_pages' => (int)ceil($total / $limit),
        ]);
    } catch (Exception $e) {
        error_log('[indicators/list] ' . $e->getMessage());
        jsonInd(500, ['error' => 'Failed to load indicators.']);
    }
}

function handleStats(): void
{
    try {
        $total = (int)(DB::queryOne('SELECT COUNT(*) AS n FROM threat_indicators')['n'] ?? 0);

        $bySeverity = DB::query(
            "SELECT severity, COUNT(*) AS cnt
               FROM threat_indicators
              GROUP BY severity
              ORDER BY FIELD(severity,'critical','high','medium','low','info','unknown')"
        );

        $byType = DB::query(
            "SELECT indicator_type AS type, COUNT(*) AS cnt
               FROM threat_indicators
              GROUP BY indicator_type
              ORDER BY cnt DESC"
        );

        jsonInd(200, [
            'total'      => $total,
            'by_severity'=> $bySeverity,
            'by_type'    => $byType,
        ]);
    } catch (Exception $e) {
        error_log('[indicators/stats] ' . $e->getMessage());
        jsonInd(500, ['error' => 'Failed to load indicator stats.']);
    }
}

function handleDelete(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonInd(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];

    $csrf = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonInd(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $id = (int)($input['id'] ?? 0);
    if ($id <= 0) jsonInd(422, ['error' => 'Invalid indicator ID.']);

    try {
        $affected = DB::execute('DELETE FROM threat_indicators WHERE id = :id', [':id' => $id]);
        if ($affected === 0) jsonInd(404, ['error' => 'Indicator not found.']);
        jsonInd(200, ['message' => 'Indicator deleted.']);
    } catch (Exception $e) {
        error_log('[indicators/delete] ' . $e->getMessage());
        jsonInd(500, ['error' => 'Failed to delete indicator.']);
    }
}

function handleDeleteBatch(): void
{
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        jsonInd(405, ['error' => 'Method not allowed.']);
    }

    $input = json_decode(file_get_contents('php://input'), true) ?? [];
    $csrf  = $input[CSRF_TOKEN_NAME] ?? '';
    if (!SecurityHeaders::validateCsrf($csrf)) {
        jsonInd(403, ['error' => 'Invalid or expired CSRF token.']);
    }

    $ids = $input['ids'] ?? [];
    if (!is_array($ids) || empty($ids)) {
        jsonInd(422, ['error' => 'No indicators selected.']);
    }

    $deleted = 0;
    foreach ($ids as $id) {
        $id = (int)$id;
        if ($id <= 0) continue;
        $deleted += DB::execute('DELETE FROM threat_indicators WHERE id = :id', [':id' => $id]);
    }

    jsonInd(200, ['deleted' => $deleted, 'message' => "{$deleted} indicator(s) deleted."]);
}

// ── Helper ────────────────────────────────────────────────────────────────────

function jsonInd(int $status, array $data): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
