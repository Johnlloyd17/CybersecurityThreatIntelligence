-- =============================================================================
--  Migration 007 — API daily‐usage tracking table
--  Tracks per‐module API call counts per day so modules like VirusTotal can
--  enforce a daily quota (free tier = 500 lookups/day).
-- =============================================================================

CREATE TABLE IF NOT EXISTS `api_daily_usage` (
    `id`          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `module_slug` VARCHAR(60)     NOT NULL,
    `usage_date`  DATE            NOT NULL,
    `call_count`  INT UNSIGNED    NOT NULL DEFAULT 0,
    `updated_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_module_date` (`module_slug`, `usage_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
