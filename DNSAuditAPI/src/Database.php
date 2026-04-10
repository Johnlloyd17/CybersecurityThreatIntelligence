<?php
/**
 * PDO database wrapper for DNSAudit API integration.
 *
 * Tables: assets, scan_summaries, scan_findings, api_logs
 */
class Database
{
    private static ?PDO $instance = null;

    public static function connect(array $config): PDO
    {
        if (self::$instance === null) {
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ];

            $dsnWithPort = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                $config['host'],
                $config['port'],
                $config['database'],
                $config['charset']
            );
            $dsnWithoutPort = sprintf(
                'mysql:host=%s;dbname=%s;charset=%s',
                $config['host'],
                $config['database'],
                $config['charset']
            );

            try {
                self::$instance = new PDO($dsnWithPort, $config['username'], $config['password'], $options);
            } catch (PDOException $withPortEx) {
                if (!self::shouldTryWithoutPort($withPortEx)) {
                    throw $withPortEx;
                }
                try {
                    self::$instance = new PDO($dsnWithoutPort, $config['username'], $config['password'], $options);
                } catch (PDOException $withoutPortEx) {
                    throw new PDOException(
                        "DB connection failed. Port {$config['port']}: {$withPortEx->getMessage()} | Default port: {$withoutPortEx->getMessage()}",
                        (int) $withoutPortEx->getCode(),
                        $withoutPortEx
                    );
                }
            }
        }

        return self::$instance;
    }

    private static function shouldTryWithoutPort(PDOException $e): bool
    {
        $msg = strtolower($e->getMessage());
        return str_contains($msg, '[2002]') ||
            str_contains($msg, 'connection refused') ||
            str_contains($msg, "can't connect");
    }

    // -- Assets -----------------------------------------------------------

    public static function addAsset(PDO $db, string $asset, string $type = 'domain'): int
    {
        $stmt = $db->prepare(
            'INSERT INTO assets (asset, type) VALUES (:asset, :type)
             ON DUPLICATE KEY UPDATE is_active = 1, updated_at = NOW()'
        );
        $stmt->execute(['asset' => $asset, 'type' => $type]);

        $id = (int) $db->lastInsertId();
        return $id > 0 ? $id : (int) self::getAssetId($db, $asset);
    }

    public static function getAssetId(PDO $db, string $asset): ?int
    {
        $stmt = $db->prepare('SELECT id FROM assets WHERE asset = :asset LIMIT 1');
        $stmt->execute(['asset' => $asset]);
        $row = $stmt->fetch();
        return $row ? (int) $row['id'] : null;
    }

    public static function listAssets(PDO $db, bool $activeOnly = true): array
    {
        $sql = 'SELECT * FROM assets';
        if ($activeOnly) {
            $sql .= ' WHERE is_active = 1';
        }
        $sql .= ' ORDER BY created_at DESC';
        return $db->query($sql)->fetchAll();
    }

    // -- Scan Summaries ---------------------------------------------------

    public static function insertSummary(PDO $db, array $data): int
    {
        $stmt = $db->prepare(
            'INSERT INTO scan_summaries
             (asset_id, domain, grade, score, subdomain_count, total_findings,
              critical_count, warning_count, info_count, scanned_at, raw_response)
             VALUES
             (:asset_id, :domain, :grade, :score, :subdomain_count, :total_findings,
              :critical_count, :warning_count, :info_count, :scanned_at, :raw_response)'
        );
        $stmt->execute($data);
        return (int) $db->lastInsertId();
    }

    public static function getSummaries(PDO $db, array $filters = [], int $limit = 50): array
    {
        $where = [];
        $params = [];

        if (!empty($filters['domain'])) {
            $where[] = 's.domain LIKE :domain';
            $params['domain'] = '%' . $filters['domain'] . '%';
        }
        if (!empty($filters['grade'])) {
            $where[] = 's.grade = :grade';
            $params['grade'] = $filters['grade'];
        }

        $sql = 'SELECT s.*, a.asset AS asset_name
                FROM scan_summaries s
                LEFT JOIN assets a ON s.asset_id = a.id';
        if (!empty($where)) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }
        $sql .= ' ORDER BY s.scanned_at DESC LIMIT :limit';

        $stmt = $db->prepare($sql);
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll();
    }

    // -- Scan Findings ----------------------------------------------------

    public static function insertFinding(PDO $db, array $data): bool
    {
        $stmt = $db->prepare(
            'INSERT IGNORE INTO scan_findings
             (result_hash, summary_id, asset_id, domain, severity, category,
              title, description, recommendation, status, scanned_at, raw_payload)
             VALUES
             (:result_hash, :summary_id, :asset_id, :domain, :severity, :category,
              :title, :description, :recommendation, :status, :scanned_at, :raw_payload)'
        );
        return $stmt->execute($data);
    }

    public static function getFindings(PDO $db, array $filters = [], int $limit = 100, int $offset = 0): array
    {
        $where = [];
        $params = [];

        if (!empty($filters['severity'])) {
            $where[] = 'f.severity = :severity';
            $params['severity'] = $filters['severity'];
        }
        if (!empty($filters['category'])) {
            $where[] = 'f.category = :category';
            $params['category'] = $filters['category'];
        }
        if (!empty($filters['status'])) {
            $where[] = 'f.status = :status';
            $params['status'] = $filters['status'];
        }
        if (!empty($filters['search'])) {
            $where[] = '(f.domain LIKE :search OR f.title LIKE :search OR f.description LIKE :search OR f.category LIKE :search)';
            $params['search'] = '%' . $filters['search'] . '%';
        }

        $sql = 'SELECT f.*, a.asset AS asset_name
                FROM scan_findings f
                LEFT JOIN assets a ON f.asset_id = a.id';
        if (!empty($where)) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }
        $sql .= ' ORDER BY f.scanned_at DESC, f.created_at DESC LIMIT :limit OFFSET :offset';

        $stmt = $db->prepare($sql);
        foreach ($params as $k => $v) {
            $stmt->bindValue($k, $v);
        }
        $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue('offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        return $stmt->fetchAll();
    }

    public static function updateFindingStatus(PDO $db, int $id, string $status): bool
    {
        $stmt = $db->prepare('UPDATE scan_findings SET status = :status WHERE id = :id');
        return $stmt->execute(['status' => $status, 'id' => $id]);
    }

    public static function getCategories(PDO $db): array
    {
        return $db->query(
            'SELECT DISTINCT category FROM scan_findings WHERE category IS NOT NULL ORDER BY category'
        )->fetchAll(PDO::FETCH_COLUMN);
    }

    // -- Dashboard Stats --------------------------------------------------

    public static function getDashboardStats(PDO $db): array
    {
        $stats = [];

        $stats['total_assets'] = (int) $db->query(
            'SELECT COUNT(*) FROM assets WHERE is_active = 1'
        )->fetchColumn();

        $stats['total_scans'] = (int) $db->query(
            'SELECT COUNT(*) FROM scan_summaries'
        )->fetchColumn();

        $stats['total_findings'] = (int) $db->query(
            'SELECT COUNT(*) FROM scan_findings'
        )->fetchColumn();

        // Severity counts
        $rows = $db->query(
            'SELECT severity, COUNT(*) AS cnt FROM scan_findings GROUP BY severity'
        )->fetchAll();
        $stats['by_severity'] = array_column($rows, 'cnt', 'severity');

        // Status counts
        $rows = $db->query(
            'SELECT status, COUNT(*) AS cnt FROM scan_findings GROUP BY status'
        )->fetchAll();
        $stats['by_status'] = array_column($rows, 'cnt', 'status');

        // Recent scans with grade/score
        $stats['recent_scans'] = $db->query(
            'SELECT s.*, a.asset AS asset_name
             FROM scan_summaries s
             LEFT JOIN assets a ON s.asset_id = a.id
             ORDER BY s.scanned_at DESC
             LIMIT 10'
        )->fetchAll();

        // Recent findings
        $stats['recent_findings'] = $db->query(
            'SELECT f.*, a.asset AS asset_name
             FROM scan_findings f
             LEFT JOIN assets a ON f.asset_id = a.id
             ORDER BY f.scanned_at DESC, f.created_at DESC
             LIMIT 10'
        )->fetchAll();

        // Average score
        $stats['avg_score'] = $db->query(
            'SELECT ROUND(AVG(score)) FROM scan_summaries WHERE score IS NOT NULL'
        )->fetchColumn() ?: 0;

        return $stats;
    }

    // -- API Log ----------------------------------------------------------

    public static function logApiCall(PDO $db, array $data): void
    {
        $stmt = $db->prepare(
            'INSERT INTO api_logs (endpoint, domain, http_status, finding_count, response_time_ms)
             VALUES (:endpoint, :domain, :http_status, :finding_count, :response_time_ms)'
        );
        $stmt->execute($data);
    }

    public static function getDailyApiUsage(PDO $db): int
    {
        return (int) $db->query(
            "SELECT COUNT(*) FROM api_logs
             WHERE endpoint = 'scan' AND DATE(created_at) = CURDATE()"
        )->fetchColumn();
    }
}
