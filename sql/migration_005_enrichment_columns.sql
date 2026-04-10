-- =============================================================================
--  CTI PLATFORM — Migration 005
--  Add enrichment-tracking columns to `query_history`
--
--  Supports SpiderFoot-style multi-pass enrichment:
--   - enrichment_pass : which pass produced this result (0 = initial query)
--   - source_ref      : parent event reference that triggered this result
--   - enriched_from   : the actual query value used in enrichment passes
--                       (e.g. an IP discovered from the original domain)
--
--  Run:  mysql -u root -p cti_platform < sql/migration_005_enrichment_columns.sql
-- =============================================================================

USE `cti_platform`;

ALTER TABLE `query_history`
    ADD COLUMN `enrichment_pass` TINYINT UNSIGNED NOT NULL DEFAULT 0
        COMMENT 'Enrichment depth: 0 = initial query, 1+ = enrichment pass'
        AFTER `response_time`,
    ADD COLUMN `source_ref` VARCHAR(500) DEFAULT 'ROOT'
        COMMENT 'Parent event reference (ROOT for initial query)'
        AFTER `enrichment_pass`,
    ADD COLUMN `enriched_from` VARCHAR(500) DEFAULT NULL
        COMMENT 'Discovered sub-entity value that was queried in this enrichment pass'
        AFTER `source_ref`;

-- Index for fast enrichment-chain retrieval per scan
ALTER TABLE `query_history`
    ADD KEY `idx_qh_enrichment` (`scan_id`, `enrichment_pass`);
