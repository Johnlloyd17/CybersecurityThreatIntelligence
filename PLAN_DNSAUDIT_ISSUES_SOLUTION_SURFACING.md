# DNSAudit Issues & Solutions Surfacing Plan (CTI)

> **Created:** 2026-04-06  
> **Scope:** Make DNSAudit issue categories (including Email Authentication and Attack Surface Threats) clearly visible and actionable inside CTI.

---

## Current State (What is already implemented)

- DNSAudit scanning is integrated and active through:
  - `php/modules/DnsAuditModule.php`
  - `DNSAuditAPI/src/DnsAuditClient.php`
- CTI receives DNSAudit findings with:
  - `severity`, `category`, `title`, `description`, `recommendation`
- CTI stores/displays both:
  - module-level summary rows
  - issue-level rows (`DNS Security Issue`) in `query_history.result_summary`
- Default DNSAudit setting is `min_severity = warning`, so many `info`-level DNSAudit checks are hidden by default.
- Scan CSV export now includes parsed DNSAudit issue fields:
  - category group, issue title, severity, recommendation, docs URL

### Key Gap

CTI now presents a first-class "DNS Security Issues and Solutions" experience in scan details.
Remaining gaps are:
- full validation coverage for additional DNSAudit groups (beyond current verified groups)
- supplementary parity validation with different severity scope (`min_severity = info`)
- regression validation across non-DNSAudit modules and scan lifecycle operations

---

## Objective

Implement issue-level DNSAudit visibility in CTI so users can:
1. See all DNSAudit checks found (including Email Authentication and Attack Surface Threats),
2. Filter by category/severity,
3. View remediation guidance per issue,
4. Export results in a structured and comparable format.

---

## Phase 1 - Data Fidelity & Storage

- [x] Add optional **issue expansion mode** in DNSAudit module execution:
  - one CTI row per DNSAudit finding (not only one module summary row)
- [x] Preserve structured finding payload in CTI persistence path:
  - category, title, severity, recommendation, optional docs slug/link
- [x] Keep backward compatibility:
  - existing summary behavior remains available behind a toggle
- [x] Add safe truncation policy for long descriptions without losing critical fields

### Proposed implementation notes

- Add new setting key(s) under DNSAudit module:
  - `emit_issue_rows` (boolean, default `true`)
  - `include_docs_links` (boolean, default `true`)
- Maintain `emit_subdomain_discoveries` behavior unchanged.

---

## Phase 2 - Taxonomy Mapping

- [x] Create internal DNSAudit issue taxonomy map in CTI:
  - `issue_slug`
  - `display_name`
  - `category_group` (Email Authentication, DNS Vulnerabilities, Attack Surface Threats, etc.)
  - `docs_path` (e.g., `/docs/missing-spf-record`)
- [x] Map known DNSAudit issue names to stable slugs
- [x] Fallback rule:
  - if unmapped issue appears, show as `Unmapped DNSAudit Issue` while preserving raw title

### Priority groups to verify

- [x] Email Authentication Issues
- [x] Attack Surface Threats
- [x] DNS Vulnerabilities
- [ ] DNS Resolution and Connectivity
- [ ] Threat Intelligence & Reputation

---

## Phase 3 - UI/UX in Scan Details

- [x] Add DNSAudit issue panel in scan details page:
  - severity badges (`critical`, `warning`, `info`)
  - category group labels
  - issue title + recommendation
- [x] Add filters:
  - severity
  - category group
  - keyword search
- [x] Add docs action:
  - open DNSAudit article link per issue when available
- [x] Add summary widgets:
  - total issues
  - counts per category group
  - counts per severity

---

## Phase 4 - Settings & Defaults

- [x] Update DNSAudit settings UX:
  - keep `min_severity` configurable (`info`, `warning`, `critical`)
  - clarify that `warning` hides informational checks
- [ ] Add user-facing helper text for "Email Authentication" and "Attack Surface" coverage visibility
- [ ] Ensure Save Changes persists these new DNSAudit settings correctly

---

## Phase 5 - Validation & Parity Testing

- [x] Run controlled scans on known targets and verify:
  - Email Authentication findings appear in CTI
  - Attack Surface Threat findings appear in CTI
- [x] Compare CTI export vs DNSAudit export for configured severity scope (`min_severity = warning`):
  - issue count parity (warning/critical): DNSAudit `5` vs CTI `5`
  - severity parity (warning/critical): DNSAudit `2 critical + 3 warning` vs CTI `2 critical + 3 warning`
  - category parity (warning/critical): Email Authentication Issues, Attack Surface Threats, DNS Vulnerabilities
- [ ] Run supplementary parity validation with `min_severity = info` to confirm informational finding coverage end-to-end
- [x] Regression test: existing non-DNSAudit modules unaffected.
- [ ] Regression test: scan deletion and query history behaviors remain correct.

---

## Acceptance Criteria

- [x] CTI displays DNSAudit issues as individual findings, not only summary text
- [x] Email Authentication and Attack Surface Threat findings are visible and filterable
- [x] Recommendations are visible per finding
- [x] Docs links are available for mapped issues
- [x] Export includes structured fields (severity, category, title, recommendation, docs link/slug)
- [ ] Existing scan flow remains stable

> Note: Checked items are implemented in code and validated in runtime where indicated (e.g., scan #78, scan #80, scan #81, `scan_78_results (1).csv`, and DNSAudit export `gmail.com-security-report.csv` on 2026-04-07). Remaining unchecked items still need additional scope/regression validation.

---

## Risk Notes

- Main risk: increasing `query_history` row volume when issue expansion is enabled.
- Mitigation:
  - configurable `max_results`
  - optional expansion toggle
  - indexed fields for scan detail filtering

---

## Suggested Rollout

1. Enable feature behind DNSAudit setting toggles.
2. Validate on staging with 3-5 domains.
3. Turn on by default after parity checks pass.
