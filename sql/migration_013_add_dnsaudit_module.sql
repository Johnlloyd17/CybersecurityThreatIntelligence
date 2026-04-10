-- =============================================================================
--  CTI PLATFORM — MIGRATION 013: Add DNSAudit Module Registration
-- =============================================================================

USE `cti_platform`;

INSERT INTO `api_configs`
    (`name`, `slug`, `base_url`, `rate_limit`, `description`, `category`,
     `auth_type`, `supported_types`, `docs_url`, `env_key`, `requires_key`, `is_enabled`)
VALUES
    (
        'DNSAudit',
        'dnsaudit',
        'https://dnsaudit.io/api',
        10,
        'DNS security scan API (DNSSEC, SPF, DKIM, DMARC, zone transfer and related checks).',
        'dns',
        'api_key',
        '["domain","url"]',
        'https://dnsaudit.io/docs/api',
        'DNSAUDIT_KEY',
        1,
        1
    )
ON DUPLICATE KEY UPDATE
    `name` = VALUES(`name`),
    `base_url` = VALUES(`base_url`),
    `rate_limit` = VALUES(`rate_limit`),
    `description` = VALUES(`description`),
    `category` = VALUES(`category`),
    `auth_type` = VALUES(`auth_type`),
    `supported_types` = VALUES(`supported_types`),
    `docs_url` = VALUES(`docs_url`),
    `env_key` = VALUES(`env_key`),
    `requires_key` = VALUES(`requires_key`);

