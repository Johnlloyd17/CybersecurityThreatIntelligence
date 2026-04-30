# CTI Ops Scripts

Operational scripts for roadmap completion and production hardening.

## Phase 2

- `phase2_import_keys.php`  
  Import API keys from a JSON manifest into `api_configs`.
- `phase2_health_check.php`  
  Run module health checks for Top-20 (or custom slug list).
- `phase2_scan_smoke.php`  
  Run individual and batch smoke tests for selected modules.

## Phase 4

- `phase4_validate_local_modules.php`  
  Validate upgraded local modules against known targets from `phase4_targets.json`.
- `phase4_spiderfoot_compare.php`  
  Import SpiderFoot CSV/JSON and compute parity score against a CTI scan.

## Phase 5

- `phase5_apply_rate_limits.php`  
  Apply rate-limit profile from `phase5_rate_limits_profile.json`.
- `phase5_key_rotation_schedule.php`  
  Seed/update `api_key_rotation_schedule` and audit due/overdue keys.
- `phase5_enable_modules.php`  
  Enable production modules with safety filters or force mode.
- `phase5_load_test.php`  
  Repeated load testing with latency and module success-rate metrics.

## Reports

All scripts write JSON reports to:

- `php/ops/reports/`
