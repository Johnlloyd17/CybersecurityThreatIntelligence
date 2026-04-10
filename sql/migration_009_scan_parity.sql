-- =============================================================================
--  CTI PLATFORM - Migration 009
--  Scan Parity System: evidence storage, replay, and SpiderFoot diff validation
--
--  Adds:
--   - scan_evidence: raw API call evidence (endpoint, params, response hash, body)
--   - scan_parity_config: frozen scan configuration snapshot for deterministic replay
--   - scans.parity_mode: track whether scan ran in live or replay mode
--   - scans.scan_start_ts: precise microsecond scan start timestamp
--   - scan_sf_diff: SpiderFoot comparison results
--
--  Run:
--    mysql -u root -p cti_platform < sql/migration_009_scan_parity.sql
-- =============================================================================

;
-- The leading semicolon above safely terminates any leftover query text in
-- phpMyAdmin SQL editor before running this migration block.

USE `cti_platform`;

-- Raw evidence for every outbound API call
CREATE TABLE IF NOT EXISTS `scan_evidence` (
    `id`                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `scan_id`           INT UNSIGNED NOT NULL,
    `module_slug`       VARCHAR(100) NOT NULL,
    `call_order`        INT UNSIGNED NOT NULL DEFAULT 0
        COMMENT 'Sequential call number within this scan (deterministic ordering)',
    `http_method`       VARCHAR(10) NOT NULL DEFAULT 'GET',
    `endpoint_url`      TEXT NOT NULL
        COMMENT 'Full request URL (query params included)',
    `request_params`    JSON DEFAULT NULL
        COMMENT 'POST body or structured query params',
    `request_headers`   JSON DEFAULT NULL
        COMMENT 'Outbound headers (API keys redacted)',
    `http_status`       SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    `response_hash`     VARCHAR(64) NOT NULL DEFAULT ''
        COMMENT 'SHA-256 of raw response body',
    `response_body`     LONGTEXT DEFAULT NULL
        COMMENT 'Full raw response body (compressed if large)',
    `response_size`     INT UNSIGNED NOT NULL DEFAULT 0
        COMMENT 'Response body size in bytes',
    `elapsed_ms`        INT UNSIGNED NOT NULL DEFAULT 0,
    `error_message`     TEXT DEFAULT NULL,
    `pagination_cursor` VARCHAR(500) DEFAULT NULL
        COMMENT 'Pagination cursor/token used for this page',
    `page_number`       SMALLINT UNSIGNED DEFAULT NULL
        COMMENT 'Page number in paginated results',
    `enrichment_pass`   TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `source_ref`        VARCHAR(500) DEFAULT 'ROOT',
    `dns_resolver`      VARCHAR(100) DEFAULT NULL
        COMMENT 'DNS resolver used for this call',
    `dns_response`      JSON DEFAULT NULL
        COMMENT 'DNS resolution result and TTL for the endpoint host',
    `called_at`         TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        COMMENT 'Precise timestamp of the API call',
    `created_at`        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    KEY `idx_evidence_scan` (`scan_id`),
    KEY `idx_evidence_module` (`scan_id`, `module_slug`),
    KEY `idx_evidence_order` (`scan_id`, `call_order`),
    CONSTRAINT `fk_evidence_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Raw evidence for every outbound API call per scan';

-- Frozen parity configuration per scan
CREATE TABLE IF NOT EXISTS `scan_parity_config` (
    `id`                     INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `scan_id`                INT UNSIGNED NOT NULL,
    `frozen_at`              TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    -- Module version and endpoint locking
    `module_versions`        JSON NOT NULL
        COMMENT 'Map of slug -> handler file hash at scan time',
    `endpoint_versions`      JSON NOT NULL
        COMMENT 'Map of slug -> base_url and endpoint paths at scan time',
    `api_configs_snapshot`   JSON NOT NULL
        COMMENT 'Full api_configs rows for selected modules',

    -- Global settings frozen
    `global_settings`        JSON NOT NULL
        COMMENT 'All platform_settings key/value pairs at scan time',

    -- DNS strategy
    `dns_strategy`           VARCHAR(50) NOT NULL DEFAULT 'system'
        COMMENT 'DNS resolver strategy: system, pinned, doh',
    `dns_resolver_ip`        VARCHAR(100) DEFAULT NULL
        COMMENT 'Pinned DNS resolver IP (if strategy=pinned)',
    `dns_cache`              JSON DEFAULT NULL
        COMMENT 'DNS resolution cache: hostname -> {ip, ttl, resolved_at}',

    -- Processing order
    `module_execution_order` JSON NOT NULL
        COMMENT 'Deterministic module execution order (sorted slug list)',

    -- Type mapping table
    `type_mapping_table`     JSON NOT NULL
        COMMENT 'Canonical EventTypes mapping frozen at scan time',

    -- Dedupe and transform rules
    `dedupe_keys`            JSON NOT NULL
        COMMENT 'Deduplication key generation rules',
    `normalization_rules`    JSON NOT NULL
        COMMENT 'Data normalization rules (sort, trim, case)',

    -- Time window
    `scan_window_start`      TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        COMMENT 'Strict collection window start',
    `scan_window_end`        TIMESTAMP(6) NULL DEFAULT NULL
        COMMENT 'Strict collection window end (set at finish)',

    UNIQUE KEY `uk_parity_scan` (`scan_id`),
    CONSTRAINT `fk_parity_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Frozen parity configuration for deterministic scan replay';

-- SpiderFoot diff comparison results
CREATE TABLE IF NOT EXISTS `scan_sf_diff` (
    `id`              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    `scan_id`         INT UNSIGNED NOT NULL
        COMMENT 'Our scan that was compared',
    `sf_import_id`    VARCHAR(100) DEFAULT NULL
        COMMENT 'SpiderFoot scan ID from imported data',
    `sf_filename`     VARCHAR(500) DEFAULT NULL
        COMMENT 'Imported SpiderFoot CSV/log filename',
    `imported_at`     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Summary counts
    `sf_total_types`  INT UNSIGNED NOT NULL DEFAULT 0,
    `cti_total_types` INT UNSIGNED NOT NULL DEFAULT 0,
    `matched_types`   INT UNSIGNED NOT NULL DEFAULT 0,
    `sf_only_types`   INT UNSIGNED NOT NULL DEFAULT 0,
    `cti_only_types`  INT UNSIGNED NOT NULL DEFAULT 0,

    -- Per-type diff detail
    `type_diff`       JSON NOT NULL
        COMMENT 'Array of {type, sf_count, cti_count, sf_unique, cti_unique, matched, sf_only_values, cti_only_values, diff_reason}',

    -- Overall match score
    `parity_score`    DECIMAL(5,2) NOT NULL DEFAULT 0.00
        COMMENT 'Percentage match (0-100)',
    `diff_reasons`    JSON DEFAULT NULL
        COMMENT 'Array of reasons for differences: data_source, dns, time_window, mapping',

    KEY `idx_sfdiff_scan` (`scan_id`),
    CONSTRAINT `fk_sfdiff_scan` FOREIGN KEY (`scan_id`) REFERENCES `scans` (`id`)
        ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='SpiderFoot scan comparison/diff results';

-- Add parity columns to scans/query_history (idempotent for MariaDB/MySQL that
-- support ADD COLUMN IF NOT EXISTS).
ALTER TABLE `scans`
    ADD COLUMN IF NOT EXISTS `parity_mode` ENUM('live','replay') NOT NULL DEFAULT 'live'
        COMMENT 'Whether this scan used live API calls or replayed from evidence'
        AFTER `config_snapshot`;

ALTER TABLE `scans`
    ADD COLUMN IF NOT EXISTS `scan_start_ts` TIMESTAMP(6) NULL DEFAULT NULL
        COMMENT 'Microsecond-precision scan start timestamp for time-lock'
        AFTER `parity_mode`;

ALTER TABLE `scans`
    ADD COLUMN IF NOT EXISTS `replay_source_scan_id` INT UNSIGNED DEFAULT NULL
        COMMENT 'If parity_mode=replay, the original scan whose evidence was replayed'
        AFTER `scan_start_ts`;

ALTER TABLE `query_history`
    ADD COLUMN IF NOT EXISTS `evidence_id` BIGINT UNSIGNED DEFAULT NULL
        COMMENT 'Link to the scan_evidence row that produced this result'
        AFTER `fp_marked_at`;

