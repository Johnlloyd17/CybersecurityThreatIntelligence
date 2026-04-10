-- =============================================================================
--  CTI PLATFORM — DATABASE SCHEMA
--  sql/schema.sql
--
--  Database: cti_platform
--  Engine:   InnoDB (transactional, FK support)
--  Charset:  utf8mb4 (full Unicode)
--
--  Roles: Admin, Analyst
--  Tables: roles, users, login_attempts, query_history, api_configs,
--          threat_indicators, dashboards, dashboard_widgets
--
--  Run this file once to set up the database:
--    mysql -u root -p < sql/schema.sql
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `cti_platform`
    DEFAULT CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `cti_platform`;

-- ─── ROLES ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `roles` (
    `id`          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `name`        VARCHAR(50)     NOT NULL,
    `description` VARCHAR(255)    DEFAULT NULL,
    `created_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_roles_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed roles
INSERT INTO `roles` (`name`, `description`) VALUES
    ('admin',   'Full access — manage users, APIs, and system settings'),
    ('analyst', 'Query threat intelligence sources and view dashboards')
ON DUPLICATE KEY UPDATE `description` = VALUES(`description`);

-- ─── USERS ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `users` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `full_name`     VARCHAR(100)    NOT NULL,
    `email`         VARCHAR(255)    NOT NULL,
    `password_hash` VARCHAR(255)    NOT NULL,
    `role_id`       INT UNSIGNED    NOT NULL,
    `organisation`  VARCHAR(150)    DEFAULT NULL,
    `is_active`     TINYINT(1)      NOT NULL DEFAULT 1,
    `last_login_at` TIMESTAMP       NULL DEFAULT NULL,
    `created_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_users_email` (`email`),
    KEY `idx_users_role` (`role_id`),
    CONSTRAINT `fk_users_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`)
        ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default users (password: Admin@1234)
-- bcrypt hash for "Admin@1234" with cost 12
INSERT INTO `users` (`full_name`, `email`, `password_hash`, `role_id`, `organisation`) VALUES
    ('CTI Admin',   'admin@cti.local',   '$2y$12$8G2sQeOYGgPGr/RNqnDRguWN385alfeErHr1kGaMmEgccWLDVZHWW', 1, 'CTI Platform'),
    ('CTI Analyst', 'analyst@cti.local', '$2y$12$8G2sQeOYGgPGr/RNqnDRguWN385alfeErHr1kGaMmEgccWLDVZHWW', 2, 'CTI Platform')
ON DUPLICATE KEY UPDATE `full_name` = VALUES(`full_name`);

-- ─── LOGIN ATTEMPTS (rate limiting) ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `login_attempts` (
    `attempt_key`      VARCHAR(64)     NOT NULL,
    `attempts`         INT UNSIGNED    NOT NULL DEFAULT 1,
    `first_attempt_at` TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_attempt_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`attempt_key`),
    KEY `idx_login_first_attempt` (`first_attempt_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── API CONFIGURATIONS ──────────────────────────────────────────────────────
-- Stores external threat intelligence API keys and endpoints.
CREATE TABLE IF NOT EXISTS `api_configs` (
    `id`          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `name`        VARCHAR(100)    NOT NULL,
    `slug`        VARCHAR(50)     NOT NULL,
    `base_url`    VARCHAR(500)    NOT NULL,
    `api_key`     VARCHAR(500)    DEFAULT NULL,
    `is_enabled`  TINYINT(1)      NOT NULL DEFAULT 1,
    `rate_limit`  INT UNSIGNED    DEFAULT NULL COMMENT 'Max requests per minute',
    `description` TEXT            DEFAULT NULL,
    `created_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_api_slug` (`slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default API sources
INSERT INTO `api_configs` (`name`, `slug`, `base_url`, `rate_limit`, `description`) VALUES
    ('VirusTotal',     'virustotal',    'https://www.virustotal.com/api/v3',        4,   'Obtain information from VirusTotal about identified IP addresses. Analyze suspicious files and URLs to detect malware, and automatically share findings with the security community.'),
    ('AbuseIPDB',      'abuseipdb',     'https://api.abuseipdb.com/api/v2',         60,  'Check if an IP address is malicious according to AbuseIPDB.com blacklist. AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It provides a central blacklist where webmasters, system administrators, and other interested parties can report and find IP addresses associated with malicious activity online.'),
    ('Shodan',         'shodan',        'https://api.shodan.io',                    1,   'Obtain information from SHODAN about identified IP addresses. Shodan is the world''s first search engine for Internet-connected devices. Use Shodan to discover which devices are connected to the internet, where they are located, and who is using them so you can understand your digital footprint.'),
    ('AlienVault OTX', 'alienvault',    'https://otx.alienvault.com/api/v1',        100, 'Obtain information from AlienVault Open Threat Exchange (OTX). OTX is an open threat intelligence community where private companies, independent security researchers, and government agencies collaborate and share information about emerging threats, attack methods, and malicious actors. Community-generated OTX threat data can be integrated into security products to keep detection defenses up to date.'),
    ('GreyNoise',      'greynoise',     'https://api.greynoise.io/v3',              30,  'Internet background noise and mass scanner detection'),
    ('URLScan.io',     'urlscan',       'https://urlscan.io/api/v1',                60,  'Website screenshot, DOM, and resource analysis')
ON DUPLICATE KEY UPDATE `base_url` = VALUES(`base_url`);

-- ─── QUERY HISTORY ───────────────────────────────────────────────────────────
-- Logs every threat intelligence query made by users.
CREATE TABLE IF NOT EXISTS `query_history` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `user_id`       INT UNSIGNED    NOT NULL,
    `query_type`    ENUM('domain','ip','url','hash','email','cve') NOT NULL,
    `query_value`   VARCHAR(500)    NOT NULL,
    `api_source`    VARCHAR(50)     DEFAULT NULL COMMENT 'Which API was queried',
    `result_summary`TEXT            DEFAULT NULL COMMENT 'Truncated result for display',
    `risk_score`    DECIMAL(5,2)    DEFAULT NULL COMMENT '0-100 risk score',
    `status`        ENUM('pending','completed','failed','timeout') NOT NULL DEFAULT 'pending',
    `response_time` INT UNSIGNED    DEFAULT NULL COMMENT 'Response time in ms',
    `queried_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_qh_user` (`user_id`),
    KEY `idx_qh_type_value` (`query_type`, `query_value`(100)),
    KEY `idx_qh_queried_at` (`queried_at`),
    CONSTRAINT `fk_qh_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── THREAT INDICATORS ──────────────────────────────────────────────────────
-- Cached/aggregated threat data from APIs.
CREATE TABLE IF NOT EXISTS `threat_indicators` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `indicator_type` ENUM('domain','ip','url','hash','email','cve') NOT NULL,
    `indicator_value` VARCHAR(500)  NOT NULL,
    `source`        VARCHAR(50)     NOT NULL COMMENT 'API source slug',
    `severity`      ENUM('critical','high','medium','low','info','unknown') NOT NULL DEFAULT 'unknown',
    `confidence`    DECIMAL(5,2)    DEFAULT NULL COMMENT '0-100 confidence score',
    `tags`          JSON            DEFAULT NULL COMMENT 'Associated tags/categories',
    `raw_data`      JSON            DEFAULT NULL COMMENT 'Full API response (cached)',
    `first_seen`    TIMESTAMP       NULL DEFAULT NULL,
    `last_seen`     TIMESTAMP       NULL DEFAULT NULL,
    `created_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_ti_type_value` (`indicator_type`, `indicator_value`(100)),
    KEY `idx_ti_severity` (`severity`),
    KEY `idx_ti_source` (`source`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── DASHBOARDS ──────────────────────────────────────────────────────────────
-- User-configurable dashboards (inspired by OpenCTI).
CREATE TABLE IF NOT EXISTS `dashboards` (
    `id`          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `user_id`     INT UNSIGNED    NOT NULL,
    `name`        VARCHAR(150)    NOT NULL,
    `description` TEXT            DEFAULT NULL,
    `is_default`  TINYINT(1)      NOT NULL DEFAULT 0,
    `layout`      JSON            DEFAULT NULL COMMENT 'Widget positions and sizes',
    `created_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_dash_user` (`user_id`),
    CONSTRAINT `fk_dash_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── DASHBOARD WIDGETS ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `dashboard_widgets` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `dashboard_id`  INT UNSIGNED    NOT NULL,
    `widget_type`   ENUM('threat_map','recent_queries','severity_chart','top_indicators','api_status','stats_counter') NOT NULL,
    `title`         VARCHAR(150)    NOT NULL,
    `config`        JSON            DEFAULT NULL COMMENT 'Widget-specific configuration',
    `position_x`    INT UNSIGNED    NOT NULL DEFAULT 0,
    `position_y`    INT UNSIGNED    NOT NULL DEFAULT 0,
    `width`         INT UNSIGNED    NOT NULL DEFAULT 4,
    `height`        INT UNSIGNED    NOT NULL DEFAULT 3,
    `created_at`    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_dw_dashboard` (`dashboard_id`),
    CONSTRAINT `fk_dw_dashboard` FOREIGN KEY (`dashboard_id`) REFERENCES `dashboards` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
