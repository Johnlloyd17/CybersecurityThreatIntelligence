<?php
// =============================================================================
//  CTI — DASHBOARD STATISTICS API
//  php/api/stats.php
//
//  GET  ?action=overview   — Summary counters for the dashboard overview cards
//  GET  ?action=severity   — Severity distribution counts from threat_indicators
//  GET  ?action=query_types— Query type distribution from query_history
//  GET  ?action=api_status — Enabled/disabled state of all configured APIs
//  GET  ?action=recent     — Last 10 query history rows for the activity table
// =============================================================================

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../security-headers.php';
require_once __DIR__ . '/../db.php';

SecurityHeaders::init();
header('Content-Type: application/json; charset=utf-8');

// Auth gate
if (session_status() !== PHP_SESSION_ACTIVE) session_start();
if (empty($_SESSION['user_id'])) {
    jsonStats(401, ['error' => 'Authentication required.']);
}

$action = $_GET['action'] ?? '';

switch ($action) {
    case 'overview':    handleOverview();   break;
    case 'severity':    handleSeverity();   break;
    case 'query_types': handleQueryTypes(); break;
    case 'api_status':  handleApiStatus();  break;
    case 'recent':      handleRecent();     break;
    default:            jsonStats(400, ['error' => 'Unknown action.']);
}

// ── Handlers ──────────────────────────────────────────────────────────────────

function handleOverview(): void
{
    try {
        // Total queries
        $totalQueries = DB::queryOne('SELECT COUNT(*) AS n FROM query_history')['n'] ?? 0;

        // Queries in the current week (Mon–now)
        $weekQueries = DB::queryOne(
            "SELECT COUNT(*) AS n FROM query_history
              WHERE queried_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        )['n'] ?? 0;

        // Threats found = queries that came back with risk_score >= 50
        $threatsFound = DB::queryOne(
            "SELECT COUNT(*) AS n FROM query_history WHERE risk_score >= 50"
        )['n'] ?? 0;

        $detectionRate = $totalQueries > 0
            ? round(($threatsFound / $totalQueries) * 100)
            : 0;

        // APIs active
        $apiRows   = DB::queryOne('SELECT COUNT(*) AS total,
                                          SUM(is_enabled) AS active
                                     FROM api_configs')
                     ?? ['total' => 0, 'active' => 0];

        // Average response time (ms) across completed queries
        $avgResp = DB::queryOne(
            "SELECT ROUND(AVG(response_time) / 1000, 1) AS sec
               FROM query_history
              WHERE status = 'completed' AND response_time IS NOT NULL"
        )['sec'] ?? 0;

        jsonStats(200, [
            'total_queries'  => (int)$totalQueries,
            'week_queries'   => (int)$weekQueries,
            'threats_found'  => (int)$threatsFound,
            'detection_rate' => (int)$detectionRate,
            'apis_active'    => (int)($apiRows['active'] ?? 0),
            'apis_total'     => (int)($apiRows['total'] ?? 0),
            'avg_response'   => $avgResp ? $avgResp . 's' : '—',
        ]);
    } catch (Exception $e) {
        error_log('[stats/overview] ' . $e->getMessage());
        jsonStats(500, ['error' => 'Failed to load overview stats.']);
    }
}

function handleSeverity(): void
{
    try {
        $rows = DB::query(
            "SELECT severity, COUNT(*) AS cnt
               FROM threat_indicators
              GROUP BY severity
              ORDER BY FIELD(severity,'critical','high','medium','low','info','unknown')"
        );
        jsonStats(200, ['severity' => $rows]);
    } catch (Exception $e) {
        error_log('[stats/severity] ' . $e->getMessage());
        jsonStats(500, ['error' => 'Failed to load severity distribution.']);
    }
}

function handleQueryTypes(): void
{
    try {
        $total = (int)(DB::queryOne('SELECT COUNT(*) AS n FROM query_history')['n'] ?? 1);
        $rows  = DB::query(
            "SELECT query_type AS type, COUNT(*) AS cnt
               FROM query_history
              GROUP BY query_type
              ORDER BY cnt DESC"
        );
        // Add percentage
        foreach ($rows as &$row) {
            $row['pct'] = $total > 0 ? round(($row['cnt'] / $total) * 100) : 0;
        }
        jsonStats(200, ['query_types' => $rows]);
    } catch (Exception $e) {
        error_log('[stats/query_types] ' . $e->getMessage());
        jsonStats(500, ['error' => 'Failed to load query type stats.']);
    }
}

function handleApiStatus(): void
{
    try {
        $rows = DB::query(
            'SELECT name, slug, is_enabled,
                    (api_key IS NOT NULL AND api_key != "") AS has_key
               FROM api_configs ORDER BY id ASC'
        );
        jsonStats(200, ['apis' => $rows]);
    } catch (Exception $e) {
        error_log('[stats/api_status] ' . $e->getMessage());
        jsonStats(500, ['error' => 'Failed to load API status.']);
    }
}

function handleRecent(): void
{
    try {
        $rows = DB::query(
            "SELECT qh.id, qh.query_type, qh.query_value, qh.api_source,
                    qh.risk_score, qh.status, qh.response_time, qh.queried_at,
                    u.full_name AS user_name
               FROM query_history qh
               JOIN users u ON u.id = qh.user_id
              ORDER BY qh.queried_at DESC
              LIMIT 10"
        );
        jsonStats(200, ['recent' => $rows]);
    } catch (Exception $e) {
        error_log('[stats/recent] ' . $e->getMessage());
        jsonStats(500, ['error' => 'Failed to load recent queries.']);
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

function jsonStats(int $status, array $data): void
{
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
