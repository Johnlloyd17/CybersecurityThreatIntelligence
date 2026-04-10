-- =============================================================================
--  CTI PLATFORM - Migration 012
--  Phase 5 Production Hardening: API key rotation schedule table
--
--  Purpose:
--   - Track rotation ownership and due dates for key-required modules
--   - Provide an auditable lifecycle for API keys
--
--  Run:
--    mysql -u root -p cti_platform < sql/migration_012_api_key_rotation_schedule.sql
-- =============================================================================

USE `cti_platform`;

CREATE TABLE IF NOT EXISTS `api_key_rotation_schedule` (
    `id`                INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `module_slug`       VARCHAR(50)  NOT NULL,
    `owner_contact`     VARCHAR(255) DEFAULT NULL,
    `rotation_days`     SMALLINT UNSIGNED NOT NULL DEFAULT 90,
    `last_rotated_at`   DATE DEFAULT NULL,
    `next_rotation_due` DATE DEFAULT NULL,
    `is_active`         TINYINT(1) NOT NULL DEFAULT 1,
    `notes`             VARCHAR(500) DEFAULT NULL,
    `created_at`        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_akrs_module` (`module_slug`),
    KEY `idx_akrs_due` (`next_rotation_due`),
    KEY `idx_akrs_active_due` (`is_active`, `next_rotation_due`),
    CONSTRAINT `fk_akrs_module_slug`
        FOREIGN KEY (`module_slug`) REFERENCES `api_configs` (`slug`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Operational schedule for API key rotation';

-- Seed rows for all key-required modules (non-destructive upsert)
INSERT INTO `api_key_rotation_schedule`
    (`module_slug`, `owner_contact`, `rotation_days`, `last_rotated_at`, `next_rotation_due`, `is_active`, `notes`)
SELECT
    `slug` AS module_slug,
    'secops@local' AS owner_contact,
    90 AS rotation_days,
    NULL AS last_rotated_at,
    DATE_ADD(CURDATE(), INTERVAL 90 DAY) AS next_rotation_due,
    1 AS is_active,
    'Seeded by migration_012_api_key_rotation_schedule.sql' AS notes
FROM `api_configs`
WHERE `requires_key` = 1
ON DUPLICATE KEY UPDATE
    `owner_contact` = VALUES(`owner_contact`),
    `rotation_days` = VALUES(`rotation_days`),
    `is_active` = VALUES(`is_active`),
    `notes` = VALUES(`notes`);

-- Verification:
-- SELECT module_slug, owner_contact, rotation_days, next_rotation_due
-- FROM api_key_rotation_schedule ORDER BY module_slug;
