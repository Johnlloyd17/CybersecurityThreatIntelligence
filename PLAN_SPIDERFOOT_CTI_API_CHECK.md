# SpiderFoot vs CTI API Check Plan (Core 6 APIs)

> Created: 2026-04-07  
> Goal: Verify API parity and operational correctness between SpiderFoot and this CTI project for high-priority modules.

---

## 1. Scope

APIs in scope:

- AbuseIPDB
- Shodan
- APIVoid
- abuse.ch
- AlienVault OTX
- VirusTotal

Out of scope for this plan:

- Adding new third-party APIs
- Full platform-wide parity for all modules

---

## 2. Module Mapping Baseline

| Provider | SpiderFoot Module ID | CTI Slug | CTI Handler |
|---|---|---|---|
| AbuseIPDB | `sfp_abuseipdb` | `abuseipdb` | `php/modules/AbuseIPDBModule.php` |
| Shodan | `sfp_shodan` | `shodan` | `php/modules/ShodanModule.php` |
| APIVoid | `sfp_apivoid` (UI display slug) | `apivoid` | `php/modules/ApiVoidModule.php` |
| abuse.ch | `sfp_abusech` | `abuse-ch` | `php/modules/AbuseChModule.php` |
| AlienVault OTX | `sfp_alienvault` | `alienvault` | `php/modules/AlienVaultModule.php` |
| VirusTotal | `sfp_virustotal` | `virustotal` | `php/modules/VirusTotalModule.php` |

Note:

- `SpiderFootModuleMapper` currently includes mappings for all above except `sfp_apivoid`. This must be confirmed and handled during checks.

---

## 3. Check Dimensions

Each API must be checked across these dimensions:

1. Registry parity (mapper + engine registration)
2. Settings parity (schema + UI options + API config)
3. Query-type parity (supported indicator types)
4. Auth and endpoint parity (base URL, headers, key use)
5. Runtime behavior parity (success, not found, rate-limit, unauthorized)
6. Output parity (type/value overlap via SpiderFoot diff reports)

---

## 4. Execution Checklist

## Phase 1 - Static Code and Config Audit

- [ ] Confirm SpiderFoot-to-CTI slug mapping in `php/SpiderFootModuleMapper.php`.
- [ ] Confirm handler registration in `php/OsintEngine.php`.
- [ ] Confirm module classes and `SUPPORTED_TYPES` in each handler file.
- [ ] Confirm module settings schema in `php/ModuleSettingsSchema.php`.
- [ ] Confirm settings UI overrides in `assets/js/settings.js`.
- [ ] Confirm DB/API config rows in SQL seed and/or live DB dump (`cti_platform.sql`).
- [ ] Log static mismatches in this plan under Section 7.

Suggested audit commands:

```powershell
rg -n "sfp_abusech|sfp_abuseipdb|sfp_shodan|sfp_apivoid|sfp_alienvault|sfp_virustotal" php/SpiderFootModuleMapper.php
rg -n "abuseipdb|shodan|apivoid|abuse-ch|alienvault|virustotal" php/OsintEngine.php php/ModuleSettingsSchema.php assets/js/settings.js
rg -n "private const SUPPORTED_TYPES" php/modules/AbuseIPDBModule.php php/modules/ShodanModule.php php/modules/ApiVoidModule.php php/modules/AbuseChModule.php php/modules/AlienVaultModule.php php/modules/VirusTotalModule.php
```

## Phase 2 - CTI Runtime Health and Smoke Validation

- [ ] Run health checks for all 6 slugs.
- [ ] Run individual smoke checks for all 6 slugs.
- [ ] Run at least one batch smoke check using a common type (`ip`).
- [ ] Save reports from `php/ops/reports/`.

Suggested commands:

```powershell
php php/ops/phase2_health_check.php --slugs=abuseipdb,shodan,apivoid,abuse-ch,alienvault,virustotal
php php/ops/phase2_scan_smoke.php --slugs=abuseipdb,shodan,apivoid,abuse-ch,alienvault,virustotal --configured-only --batch-type=ip
```

## Phase 3 - SpiderFoot vs CTI Diff Validation

- [ ] Run SpiderFoot scan per API with equivalent module and target.
- [ ] Export SpiderFoot result (`CSV` or `JSON`) per API.
- [ ] Run equivalent CTI scan and record CTI `scan_id`.
- [ ] Run `phase4_spiderfoot_compare.php` for each API pair.
- [ ] Store parity scores and mismatch reasons.

Command template:

```powershell
php php/ops/phase4_spiderfoot_compare.php --scan-id=<CTI_SCAN_ID> --file=<SPIDERFOOT_EXPORT_FILE> --format=csv --strict --min-score=70
```

---

## 5. Per-API Tracking Matrix

| API | Static Audit | CTI Health | CTI Smoke | SpiderFoot Export | Diff Report | Parity >= 70 |
|---|---|---|---|---|---|---|
| AbuseIPDB | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| Shodan | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| APIVoid | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| abuse.ch | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| AlienVault OTX | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |
| VirusTotal | [ ] | [ ] | [ ] | [ ] | [ ] | [ ] |

---

## 6. Acceptance Criteria

Plan is complete when all are true:

- All six APIs pass static audit with documented mapping/settings consistency.
- All six APIs pass CTI runtime health/smoke (or have documented key/rate-limit reason).
- Diff report exists for each API comparison run.
- Each API reaches parity score target (`>= 70`) or has an approved exception with root cause.
- Final summary report includes fixes needed, quick wins, and blocked items.

---

## 7. Initial Findings to Verify During Execution

1. APIVoid SpiderFoot mapping gap  
`assets/js/settings.js` defines `displaySlug: 'sfp_apivoid'`, but `php/SpiderFootModuleMapper.php` does not currently show `sfp_apivoid => apivoid`.

2. abuse.ch API ID normalization risk  
CTI slug is `abuse-ch`, while `php/modules/AbuseChModule.php` uses `API_ID = 'abusech'`. Validate that reporting, grouping, and parity scripts do not mis-attribute results.

3. Provider capability mismatch risk  
Some providers have different supported types/behaviors between SpiderFoot and CTI. Diff reasons from `SpiderFootDiffValidator` must be captured before classifying as defects.

---

## 8. Deliverables

- Updated checklist status in this file.
- Phase reports in `php/ops/reports/`:
  - Health check report
  - Smoke test report
  - SpiderFoot diff reports (`phase4_spiderfoot_diff_*.json`)
- One summary note with:
  - Pass/fail per API
  - Required code/config fixes
  - Recommended next action order

