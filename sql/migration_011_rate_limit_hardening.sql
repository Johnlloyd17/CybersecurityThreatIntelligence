-- =============================================================================
--  CTI PLATFORM - Migration 011
--  Phase 5 Production Hardening: baseline per-module rate limits
--
--  Purpose:
--   - Normalize api_configs.rate_limit values to production-safe defaults
--   - Keep stricter limits on high-cost APIs
--   - Allow higher limits for local:// modules
--
--  Run:
--    mysql -u root -p cti_platform < sql/migration_011_rate_limit_hardening.sql
-- =============================================================================

USE `cti_platform`;

UPDATE `api_configs`
SET `rate_limit` = CASE
    -- Critical paid/public APIs (explicit overrides)
    WHEN `slug` = 'virustotal'       THEN 4
    WHEN `slug` = 'shodan'           THEN 1
    WHEN `slug` = 'abuseipdb'        THEN 10
    WHEN `slug` = 'greynoise'        THEN 5
    WHEN `slug` = 'urlscan'          THEN 8
    WHEN `slug` = 'alienvault'       THEN 12
    WHEN `slug` = 'securitytrails'   THEN 5
    WHEN `slug` = 'censys'           THEN 5
    WHEN `slug` = 'hybrid-analysis'  THEN 4
    WHEN `slug` = 'abuse-ch'         THEN 20
    WHEN `slug` = 'threatfox'        THEN 20
    WHEN `slug` = 'ipinfo'           THEN 30
    WHEN `slug` = 'hunter'           THEN 2
    WHEN `slug` = 'haveibeenpwned'   THEN 5
    WHEN `slug` = 'whoisxml'         THEN 5
    WHEN `slug` = 'binaryedge'       THEN 5
    WHEN `slug` = 'fullhunt'         THEN 5
    WHEN `slug` = 'leakix'           THEN 5
    WHEN `slug` = 'networksdb'       THEN 5
    WHEN `slug` = 'threatminer'      THEN 12
    WHEN `slug` = 'threatcrowd'      THEN 12
    WHEN `slug` = 'crt-sh'           THEN 12
    WHEN `slug` = 'dnsgrep'          THEN 12

    -- Local modules: safe to run at higher throughput
    WHEN `base_url` LIKE 'local://%' THEN 240

    -- Category defaults
    WHEN `category` = 'network'      THEN 40
    WHEN `category` = 'dns'          THEN 40
    WHEN `category` = 'threat'       THEN 40
    WHEN `category` = 'infra'        THEN 35
    WHEN `category` = 'identity'     THEN 25
    WHEN `category` = 'leaks'        THEN 20
    WHEN `category` = 'osint'        THEN 30
    WHEN `category` = 'blocklist'    THEN 30

    -- Fallbacks
    WHEN `requires_key` = 1          THEN 30
    ELSE 60
END;

-- Verification:
-- SELECT slug, rate_limit FROM api_configs ORDER BY slug;
