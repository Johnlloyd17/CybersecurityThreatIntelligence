-- =============================================================================
--  CTI PLATFORM — Migration 004
--  Add `data_type` column to `query_history`
--
--  Stores the SpiderFoot-compatible data type label for each result element,
--  e.g. "Internet Name", "Affiliate - Internet Name", "IP Address",
--       "Malware", "Linked URL - Internal", "Netblock Owner", etc.
--
--  Also adds `scan_id` index if not already present (used by scan_detail).
--
--  Run:  mysql -u root -p cti_platform < sql/migration_004_query_history_data_type.sql
-- =============================================================================

USE `cti_platform`;

ALTER TABLE `query_history`
    ADD COLUMN `data_type` VARCHAR(100) DEFAULT NULL
        COMMENT 'SpiderFoot-style data type label (e.g. "Internet Name", "Malware")'
        AFTER `api_source`;
