-- =============================================================================
--  CTI PLATFORM — MIGRATION 002: SCANS TABLE
--  sql/migration_002_scans_table.sql
--
--  Adds a `scans` table to group query_history rows into logical scans
--  (like SpiderFoot's scan concept). Also adds scan_id FK to query_history,
--  and extends the query_type ENUM to cover all supported input types.
-- =============================================================================

USE `cti_platform`;

-- ─── SCANS TABLE ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `scans` (
    `id`              INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `user_id`         INT UNSIGNED    NOT NULL,
    `name`            VARCHAR(200)    NOT NULL DEFAULT 'Untitled Scan',
    `target`          VARCHAR(500)    NOT NULL,
    `target_type`     VARCHAR(20)     NOT NULL DEFAULT 'domain',
    `status`          ENUM('starting','running','finished','failed','aborted') NOT NULL DEFAULT 'starting',
    `use_case`        VARCHAR(30)     DEFAULT NULL COMMENT 'all, footprint, investigate, passive',
    `selected_modules` JSON           DEFAULT NULL COMMENT 'Array of module slugs selected for this scan',
    `total_elements`  INT UNSIGNED    NOT NULL DEFAULT 0,
    `unique_elements` INT UNSIGNED    NOT NULL DEFAULT 0,
    `error_count`     INT UNSIGNED    NOT NULL DEFAULT 0,
    `started_at`      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `finished_at`     TIMESTAMP       NULL DEFAULT NULL,
    `created_at`      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_scans_user` (`user_id`),
    KEY `idx_scans_status` (`status`),
    KEY `idx_scans_started` (`started_at`),
    CONSTRAINT `fk_scans_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── SCAN LOG TABLE ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `scan_logs` (
    `id`        INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `scan_id`   INT UNSIGNED    NOT NULL,
    `level`     ENUM('info','warning','error','debug') NOT NULL DEFAULT 'info',
    `module`    VARCHAR(100)    DEFAULT NULL,
    `message`   TEXT            NOT NULL,
    `logged_at` TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_sl_scan` (`scan_id`),
    CONSTRAINT `fk_sl_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── ADD scan_id TO query_history ───────────────────────────────────────────
ALTER TABLE `query_history`
    ADD COLUMN `scan_id` INT UNSIGNED NULL AFTER `user_id`,
    ADD KEY `idx_qh_scan` (`scan_id`),
    ADD CONSTRAINT `fk_qh_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
        ON UPDATE CASCADE ON DELETE SET NULL;

-- ─── EXTEND query_type ENUM to cover all input types ────────────────────────
ALTER TABLE `query_history`
    MODIFY COLUMN `query_type` VARCHAR(20) NOT NULL DEFAULT 'domain';

ALTER TABLE `threat_indicators`
    MODIFY COLUMN `indicator_type` VARCHAR(20) NOT NULL DEFAULT 'domain';

-- ─── SCAN CORRELATIONS TABLE ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `scan_correlations` (
    `id`        INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `scan_id`   INT UNSIGNED    NOT NULL,
    `rule_name` VARCHAR(200)    NOT NULL,
    `severity`  ENUM('high','medium','low','info') NOT NULL DEFAULT 'info',
    `title`     VARCHAR(500)    NOT NULL,
    `detail`    TEXT            DEFAULT NULL,
    `created_at` TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_sc_scan` (`scan_id`),
    KEY `idx_sc_severity` (`severity`),
    CONSTRAINT `fk_sc_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
