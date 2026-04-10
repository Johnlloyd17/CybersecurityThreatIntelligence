-- ============================================================================
-- Migration 006 — Performance Defaults
--
-- Reduces http_timeout from 15 s to 10 s and disables the VirusTotal
-- public_key throttle (sleep 15 s per query) by default.
--
-- Apply with:
--   mysql -u root -p cti_platform < sql/migration_006_perf_defaults.sql
-- ============================================================================

-- Reduce per-request HTTP timeout from 15 s to 10 s.
-- Cuts worst-case per-module wait from ~30 s to ~10 s (no-retry-on-timeout
-- change in HttpClient.php means timeouts now fail fast on the first attempt).
INSERT INTO `platform_settings` (`setting_key`, `setting_value`)
VALUES ('http_timeout', '10')
ON DUPLICATE KEY UPDATE `setting_value` = '10';

-- Disable VirusTotal public-key throttle by default.
-- The sleep(15) guard is now opt-in: users with free-tier VT keys should
-- enable it in Settings → Module Settings → VirusTotal → "Using Public API Key?".
INSERT INTO `module_settings` (`module_slug`, `setting_key`, `setting_value`)
VALUES ('virustotal', 'public_key', '0')
ON DUPLICATE KEY UPDATE `setting_value` = '0';
