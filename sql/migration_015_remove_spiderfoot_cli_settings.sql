-- =============================================================================
--  CTI PLATFORM - Migration 015
--  Remove SpiderFoot CLI engine settings added during the rolled-back
--  sidecar integration attempt.
--
--  Run:
--    mysql -u root -p cti_platform < sql/migration_015_remove_spiderfoot_cli_settings.sql
-- =============================================================================

USE `cti_platform`;

DELETE FROM `platform_settings`
WHERE `setting_key` IN (
    'spiderfoot_enabled',
    'spiderfoot_root_path',
    'spiderfoot_python_path',
    'spiderfoot_timeout_seconds',
    'spiderfoot_output_format',
    'spiderfoot_extra_args'
);

