# DNSAudit Module Integration Plan (CTI)

> Created: 2026-04-06  
> Goal: Integrate the existing `DNSAuditAPI` implementation as a first-class CTI module with module settings and UI presence, same as other modules.  
> Constraint: Additive changes only. Do not remove or break existing DNSAudit functionality.

---

## 1. Recommended Integration Approach

Use an adapter pattern:

- Keep `DNSAuditAPI` as-is (its scan/export/history logic remains the source implementation).
- Add a CTI module handler (`dnsaudit`) that consumes DNSAudit responses and converts them to `OsintResult`.
- Register DNSAudit in `api_configs` so it behaves like normal CTI modules (enabled/disabled, key management, query type filtering).

Why this approach:

- Reuses the working DNSAudit implementation.
- Keeps risk low and avoids rewriting scanner logic.
- Fits the current CTI architecture (`api_configs` + `OsintEngine` + module handlers).

---

## 2. Scope

### In Scope

- Add `dnsaudit` to CTI module registry.
- Add DNSAudit module handler and `handlerMap` wiring.
- Add module settings schema for DNSAudit.
- Add Settings/New Scan UI visibility (via static data file used by current UI).
- Define validation checklist and rollback plan.

### Out of Scope (for this phase)

- Replacing the standalone DNSAudit dashboard/pages.
- Merging `dnsaudit_db` tables into `cti_platform`.
- Changing existing DNSAudit finding logic.

---

## 3. Module Settings Specification

Planned DNSAudit settings in `ModuleSettingsSchema` (slug: `dnsaudit`):

| Key | Type | Default | Purpose |
|---|---|---|---|
| `timeout_seconds` | number | `45` | Request timeout for DNSAudit calls. |
| `max_retries` | number | `2` | Retry attempts on transient DNSAudit failures. |
| `save_results` | boolean | `false` | If true, allow DNSAudit side DB save behavior where supported. |
| `min_severity` | text | `warning` | Filter findings before CTI result summary (`info`, `warning`, `critical`). |
| `max_results` | number | `100` | Maximum findings to include in CTI result payload/summary. |
| `include_history` | boolean | `false` | Optionally fetch scan history context. |
| `history_limit` | number | `10` | Max history records when `include_history=true`. |
| `emit_subdomain_discoveries` | boolean | `true` | Add discovered subdomains as enrichment discoveries. |
| `include_raw_payload` | boolean | `true` | Keep full DNSAudit response in `rawData` for analyst drill-down. |

Notes:

- API key should be managed in `api_configs.api_key` (same pattern as other key-based modules).
- Keep `requires_key = 1` for consistent UI and operational behavior.

---

## 4. UI Interface Plan

Current project UI uses static module data (`assets/js/settings.static-data.js`) for Settings and New Scan preview pages.

To make DNSAudit appear like other modules:

- Add one DNSAudit object in `assets/js/settings.static-data.js` with:
  - `slug: "dnsaudit"`
  - `name: "DNSAudit"`
  - `info` (`description`, `category: "dns"`, `website`)
  - `apiConfig` (`requiresKey`, `isEnabled`, `supportedTypes`)
  - `settings` (keys listed above)
- No custom `settings.js` override is required unless custom labels are wanted; generic renderer already supports this.
- DNSAudit will then be visible in:
  - Settings module sidebar
  - Module settings panel
  - New Scan module list and data-type filters (because New Scan also reads static settings data)

---

## 5. Implementation Phases (Checklist)

## Phase 1 - Registry and Migration

- [x] Create `sql/migration_013_add_dnsaudit_module.sql` with `INSERT ... ON DUPLICATE KEY UPDATE` for `api_configs`.
- [x] Seed DNSAudit row with slug `dnsaudit` and category `dns`.
- [x] Set `requires_key = 1`, `auth_type = 'api_key'`, and supported types (recommended: `["domain","url"]`).
- [x] Add the same seed row in long-form seed files if you want fresh installs to include DNSAudit out of the box (`cti_platform.sql` and/or migration seed set).

## Phase 2 - Module Handler Wiring

- [x] Create `php/modules/DnsAuditModule.php`.
- [x] Implement `execute()` to call DNSAudit and map output to `OsintResult`.
- [x] Handle query normalization (`url` -> host/domain extraction).
- [x] Map DNSAudit severity/grade to CTI score and severity consistently.
- [x] Add discoveries (`Internet Name`) when subdomains are present and enabled by setting.
- [x] Add optional `healthCheck()` behavior.

## Phase 3 - Engine Registration

- [x] Add `'dnsaudit' => 'DnsAuditModule.php'` to `php/OsintEngine.php` handler map.
- [x] Ensure no mock fallback is used when DNSAudit is selected.

## Phase 4 - Settings Schema

- [x] Add `self::$schemas['dnsaudit']` block to `php/ModuleSettingsSchema.php`.
- [x] Keep key names aligned to existing module conventions (`timeout_seconds`, `max_results`, etc.).

## Phase 5 - UI Integration

- [x] Add DNSAudit module object to `assets/js/settings.static-data.js`.
- [x] Include all DNSAudit settings keys so Settings panel shows complete controls.
- [x] Verify DNSAudit appears in `newscan.php` module picker (fed by static settings data).

## Phase 6 - Key Flow Alignment (Important)

- [x] Decide key source of truth:
  - Recommended: CTI `api_configs.api_key` as the canonical key.
- [x] Pass CTI `api_configs.api_key` into DNSAudit client at runtime when configured.
- [x] Keep fallback to existing DNSAudit `config.php` key for backward compatibility.

## Phase 7 - Validation and Sign-off

- [x] Run a DNSAudit-only scan for a known domain and confirm real output.
- [x] Confirm module appears in Settings, API config list, and New Scan UI.
- [x] Confirm key-required state behaves correctly (missing key vs configured key).
- [x] Confirm findings are stored in CTI scan history as normal module results.
- [x] Confirm no regressions to existing modules.

Validation evidence (2026-04-07):
- Scan `#78` (`DNS testing`, target `gmail.com`) finished with DNSAudit findings persisted.
- Scan `#79` (`DNS testing`, target `gmail.com`) with missing key produced expected error: `[dnsaudit] API key not configured`.
- Scan `#80` (`DNS testing 2`, target `gmail.com`) after restoring key finished successfully with `6 elements, 0 errors`.
- Scan `#81` (`Regression test`, target `example.com`) using non-DNSAudit modules (`crt-sh`, `dns-resolver`) finished successfully with `24 elements, 0 errors`.

---

## 6. Validation Checklist (Manual)

1. DNSAudit appears in Settings sidebar and shows its module options.
2. DNSAudit appears in API key/config management with enable/disable and key status.
3. DNSAudit appears in New Scan module list and can be selected.
4. Running scan with DNSAudit selected returns non-mock data.
5. Severity and summary are readable in scan results.
6. Optional: DNSAudit standalone directory still works exactly as before.

---

## 7. Rollback Plan

If a problem appears during rollout:

1. Disable `dnsaudit` in `api_configs` (`is_enabled = 0`).
2. Remove `dnsaudit` from `OsintEngine::$handlerMap`.
3. Keep DNSAudit files on disk (non-destructive rollback).
4. Re-run validation on existing modules.

---

## 8. Acceptance Criteria

DNSAudit integration is complete when all items are true:

- DNSAudit is selectable and executable like other CTI modules.
- DNSAudit has module settings visible in Settings UI.
- DNSAudit uses CTI module flow (`api_configs` -> `OsintEngine` -> module handler -> scan results).
- Existing DNSAudit implementation remains intact and functional.

