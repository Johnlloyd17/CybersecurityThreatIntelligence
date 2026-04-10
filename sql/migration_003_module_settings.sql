-- ============================================================================
-- Migration 003 — Module Settings + Platform Settings
-- ============================================================================

-- Per-module setting overrides (schema definitions live in PHP code)
CREATE TABLE IF NOT EXISTS `module_settings` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `module_slug`   VARCHAR(50)     NOT NULL,
    `setting_key`   VARCHAR(100)    NOT NULL,
    `setting_value` TEXT            DEFAULT NULL,
    `updated_at`    TIMESTAMP       DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_module_setting` (`module_slug`, `setting_key`),
    KEY `idx_module_slug` (`module_slug`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Platform-level settings (Global + Storage)
CREATE TABLE IF NOT EXISTS `platform_settings` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `setting_key`   VARCHAR(100)    NOT NULL,
    `setting_value` TEXT            DEFAULT NULL,
    `updated_at`    TIMESTAMP       DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_platform_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed Global defaults
INSERT INTO `platform_settings` (`setting_key`, `setting_value`) VALUES
('debug',                   'false'),
('dns_resolver',            ''),
('http_timeout',            '15'),
('generic_usernames',       'abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,'),
('tld_list_url',            'https://publicsuffix.org/list/effective_tld_names.dat'),
('tld_cache_hours',         '72'),
('max_concurrent_modules',  '3'),
('socks_type',              ''),
('socks_host',              ''),
('socks_port',              ''),
('socks_username',          ''),
('socks_password',          ''),
('user_agent',              'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'),
('max_bytes_per_element',   '1024')
ON DUPLICATE KEY UPDATE `setting_key` = `setting_key`;
