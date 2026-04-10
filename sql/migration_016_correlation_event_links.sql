-- =============================================================================
--  CTI PLATFORM — MIGRATION 016: CORRELATION EVENT LINKS
--  sql/migration_016_correlation_event_links.sql
--
--  Adds a SpiderFoot-style junction table linking correlation findings back to
--  the individual query_history result rows that triggered them.
-- =============================================================================

USE `cti_platform`;

CREATE TABLE IF NOT EXISTS `scan_correlation_events` (
    `id`               INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `correlation_id`   INT UNSIGNED NOT NULL,
    `query_history_id` INT UNSIGNED NOT NULL,
    `created_at`       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_sce_corr_result` (`correlation_id`, `query_history_id`),
    KEY `idx_sce_corr` (`correlation_id`),
    KEY `idx_sce_qh` (`query_history_id`),
    CONSTRAINT `fk_sce_corr`
        FOREIGN KEY (`correlation_id`) REFERENCES `scan_correlations` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT `fk_sce_qh`
        FOREIGN KEY (`query_history_id`) REFERENCES `query_history` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
