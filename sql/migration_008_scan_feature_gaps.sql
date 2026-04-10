-- =============================================================================
--  CTI PLATFORM - Migration 008
--  Fill key SpiderFoot-style scan feature gaps
--
--  Adds:
--   - query_history.false_positive tracking
--   - query_history.false-positive audit metadata
--   - scans.config_snapshot JSON payload for per-scan configuration snapshots
--
--  Run:
--    mysql -u root -p cti_platform < sql/migration_008_scan_feature_gaps.sql
-- =============================================================================

USE `cti_platform`;

ALTER TABLE `query_history`
    ADD COLUMN `false_positive` TINYINT(1) NOT NULL DEFAULT 0
        COMMENT 'Whether the result has been marked as a false positive'
        AFTER `enriched_from`,
    ADD COLUMN `fp_marked_by` INT UNSIGNED DEFAULT NULL
        COMMENT 'User who last changed the false-positive state'
        AFTER `false_positive`,
    ADD COLUMN `fp_marked_at` TIMESTAMP NULL DEFAULT NULL
        COMMENT 'When the false-positive state was last changed'
        AFTER `fp_marked_by`,
    ADD KEY `idx_qh_scan_fp` (`scan_id`, `false_positive`);

ALTER TABLE `query_history`
    ADD CONSTRAINT `fk_qh_fp_marked_by` FOREIGN KEY (`fp_marked_by`) REFERENCES `users` (`id`)
        ON UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE `scans`
    ADD COLUMN `config_snapshot` JSON DEFAULT NULL
        COMMENT 'JSON snapshot of target, use case, and selected modules at scan start'
        AFTER `selected_modules`;
