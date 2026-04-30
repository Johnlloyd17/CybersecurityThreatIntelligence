# CTI Platform Copilot Instructions


## Public Repository Rules

- Never commit real API keys, passwords, tokens, cookies, session IDs, database
  dumps, downloaded reports, browser profiles, or private scan results.
- Use redacted examples such as `YOUR_API_KEY`, `example.com`, `8.8.8.8`, and
  `test@example.com` in documentation and tests.
- Do not add machine-specific absolute paths to public docs unless they are
  clearly local examples. Prefer relative paths from the repository root.
- Do not commit generated cache files such as `__pycache__/`, `.pyc`, runtime
  SQLite databases, temporary payloads, or export downloads.

## Project Overview

CTI Platform is a PHP + MySQL Cyber Threat Intelligence dashboard with a
first-party Python scan engine.

Main application areas:

- `index.php`: public landing page and login form.
- `dashboard.php`: authenticated dashboard.
- `newscan.php`: scan creation UI and module selection.
- `query.php`: scan list, bulk actions, exports, and scan management.
- `scaninfo.php`: scan details, results, logs, graph, and settings snapshot.
- `settings.php`: API key and module configuration UI.
- `php/`: backend APIs, persistence, scan routing, and security helpers.
- `assets/`: frontend JavaScript, CSS, icons, and UI assets.
- `python/cti_service/`: HTTP service for the first-party Python engine.
- `python/cti_engine/`: event-driven CTI engine, modules, events, and tests.
- `python/spiderfoot_bridge/`: bridge used when CTI routes to SpiderFoot.
- `spiderfoot-master/`: vendored SpiderFoot reference/runtime code.
- `scripts/`: local helper scripts for tests, service startup, and bridge runs.
- `test/python/`: Python unit tests for the CTI engine and modules.
- `.github/`: roadmap, contributor guidance, and project planning docs.

## Local Development Quick Start

Typical local stack:

- XAMPP Apache + MySQL for PHP pages and database.
- Python 3.12+ for the CTI Python service and unit tests.
- Browser at `http://localhost:8080/CybersecurityThreatIntelligence/` or the
  local Apache port configured by the developer.

Start the CTI Python service from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_cti_python_service.ps1"
```

Equivalent direct Python command:

```powershell
python -m python.cti_service
```

Expected service startup output:

```json
{"service":"cti-python-engine","host":"127.0.0.1","port":8765}
```

Run Python engine tests:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_cti_engine_tests.ps1"
```

Equivalent direct test command:

```powershell
python -m unittest discover -s test\python -v
```

## Database Import And Export Guide

The project database SQL files are stored in:

```text
db_sql/
```

Current local database export:

```text
db_sql/cti_platform.sql
```

For XAMPP:

1. Start Apache and MySQL from the XAMPP Control Panel.
2. Open phpMyAdmin from `http://localhost/phpmyadmin`.
3. Create a database named `cti_platform` if it does not already exist.
4. Select the `cti_platform` database.
5. Open the Import tab.
6. Choose `db_sql/cti_platform.sql`.
7. Click Import and wait for phpMyAdmin to finish.

For WAMP:

1. Start all WAMP services.
2. Open phpMyAdmin from the WAMP tray menu or `http://localhost/phpmyadmin`.
3. Create or select the `cti_platform` database.
4. Open the Import tab.
5. Choose `db_sql/cti_platform.sql`.
6. Click Import and wait for phpMyAdmin to finish.

To export a fresh local database backup:

1. Open phpMyAdmin.
2. Select the `cti_platform` database.
3. Open the Export tab.
4. Choose SQL format.
5. Export the file as `cti_platform.sql`.
6. Place the updated SQL file in `db_sql/`.

Before committing an exported SQL file, review it carefully and remove private
API keys, real user accounts, session data, scan targets, downloaded reports,
and any other sensitive local data.

## Authentication Flow

Local login page:

```text
http://localhost:8080/CybersecurityThreatIntelligence/index.php
```

Demo credentials may exist in local SQL seed data, but public docs and examples
must not include production credentials.

Login flow:

1. `index.php` renders the login form.
2. `assets/js/landing.js` handles the landing page login submission.
3. `assets/js/auth.js` requests a CSRF token from
   `php/api/auth.php?action=csrf`.
4. The browser posts JSON to `php/api/auth.php?action=login`.
5. `php/api/auth.php` validates CSRF, rate limits failed attempts, loads the
   user, verifies the password hash, regenerates the session ID, and stores the
   authenticated user in `$_SESSION`.
6. Authenticated pages call `Auth.requireAuth()` and redirect unauthenticated
   users back to `index.php#hero-login-panel`.
7. Logout calls `php/api/auth.php?action=logout` and destroys the session.

Important auth/security files:

- `php/config.php`: app config, session lifetime, CSRF settings, bcrypt cost,
  and database defaults.
- `php/security-headers.php`: secure session startup, security headers, CSRF
  helpers, and request protection.
- `php/RateLimiter.php`: failed-login lockout behavior.
- `php/db.php`: PDO connection and password helpers.

## Scan Backend Selection

`php/ScanExecutor.php` decides which backend runs a scan.

Preferred order:

1. First-party CTI Python engine through `php/CtiPythonServiceRunner.php`.
2. SpiderFoot bridge through `php/SpiderFootBridgeRunner.php` when CTI Python
   does not support the selected module/target combination.
3. Native PHP CTI backend as the final fallback.

A scan can use the CTI Python engine only when:

- every selected module is mapped in `CTI_TO_SERVICE`,
- every selected module supports the scan target type in `MODULE_QUERY_SUPPORT`,
- every selected module has parity approval for that target type in
  `PARITY_VERIFIED_SUPPORT`, and
- the Python service is reachable.

Backend choice is stored in the scan `config_snapshot` using fields such as
`engine_backend` and `engine_backend_label`.

## CTI Python Service

The service layer lives in `python/cti_service/`.

Default local service settings:

```text
CTI_ENGINE_HOST=127.0.0.1
CTI_ENGINE_PORT=8765
CTI_ENGINE_MAX_WORKERS=4
```

PHP connects to `CTI_PYTHON_ENGINE_URL`, or defaults to:

```text
http://127.0.0.1:8765
```

Main service routes:

- `GET /`: simple service index and route list.
- `GET /health`: health check.
- `POST /api/v1/scans`: create an async scan job.
- `GET /api/v1/scans/{scan_id}`: job status.
- `GET /api/v1/scans/{scan_id}/logs`: scan logs.
- `GET /api/v1/scans/{scan_id}/results`: scan results projection.
- `POST /api/v1/scans/{scan_id}/terminate`: request cancellation.

The Python service returns projected JSON. It does not write directly to MySQL.
PHP imports the projection into CTI tables.

## CTI Python Engine

The engine layer lives in `python/cti_engine/`.

Important files:

- `targets.py`: normalizes raw targets into CTI target types.
- `settings.py`: carries frozen global/module settings and API config snapshots.
- `context.py`: defines `ScanRequest` and `ScanContext`.
- `events.py`: defines normalized `ScanEvent` and `ScanLogEntry`.
- `module_base.py`: base contract for Python modules.
- `registry.py`: module registration and watcher lookup.
- `queue.py`: event queue engine.
- `projector.py`: converts engine output into CTI-compatible result rows.
- `modules/__init__.py`: registers built-in Python modules.
- `storage/models.py`: shared projection/storage data shapes.

Engine flow:

1. PHP builds a scan payload in `CtiPythonServiceRunner.php`.
2. `python/cti_service/schemas.py` validates and normalizes the request.
3. `python/cti_service/worker.py` registers modules and starts the queue engine.
4. The queue creates a root event for the target.
5. Registered modules receive matching event types through `watched_types`.
6. Modules yield child `ScanEvent` objects.
7. The engine deduplicates events, computes simple severity, and continues the
   event graph.
8. The projector converts events/logs/correlations into CTI result JSON.
9. PHP imports the projected rows into MySQL.

## SpiderFoot Relationship

SpiderFoot is not the long-term application runtime for the first-party CTI
engine. It is used in two ways:

- As a bridge backend for modules that are not yet migrated or verified in CTI
  Python.
- As a behavior reference when tightening CTI Python module parity.

Official SpiderFoot repository:

```text
https://github.com/smicallef/spiderfoot
```

Review the upstream repository when studying SpiderFoot's Python scan runner,
module system, event routing, and module behavior.

When working on SpiderFoot parity:

- Compare against the matching `spiderfoot-master/modules/sfp_*.py` file.
- Match supported target types, watched events, produced events, settings,
  parsing behavior, and error behavior where practical.
- Keep CTI module code first-party and maintainable.
- Preserve attribution and do not remove SpiderFoot license notices.
- Do not mark parity support until tests and manual comparison are complete.

## Adding Or Updating CTI Python Modules

When adding or editing a Python module:

1. Subclass `BaseModule` from `python/cti_engine/module_base.py`.
2. Set `slug`, `name`, `watched_types`, `produced_types`, and `requires_key`.
3. Read module settings through `ctx.module_settings_for(slug)`.
4. Read API credentials through `ctx.api_config_for(slug)`.
5. Implement `async def handle(self, event, ctx)` and yield `ScanEvent` values.
6. Register the class in `python/cti_engine/modules/__init__.py`.
7. Add or update unit tests in `test/python/`.
8. Add the CTI UI slug and service slug to `CTI_TO_SERVICE`.
9. Add target support to `MODULE_QUERY_SUPPORT`.
10. Add API-key status to `MODULE_REQUIRES_KEY`.
11. Add reverse mapping to `SERVICE_TO_CTI` when needed.
12. Only update `PARITY_VERIFIED_SUPPORT` after parity review is complete.

Module implementation rules:

- Keep network timeouts bounded.
- Log provider throttling, invalid keys, and empty results clearly.
- Avoid crashing the scan for one provider failure unless the failure is truly
  unrecoverable.
- Deduplicate emitted events where possible.
- Use stable event types and values so CTI results remain predictable.
- Do not add real API responses or private scan data to tests.

## PHP Persistence Rules

The Python engine returns JSON. `php/CtiPythonServiceRunner.php` imports that
projection into MySQL inside a transaction.

Projection import responsibilities:

- Results become `query_history` rows.
- Engine events become `scan_events` rows.
- Logs become `scan_logs` rows.
- Correlations become `scan_correlations` rows.
- Scan status, counts, and timestamps are updated on `scans`.

When editing PHP APIs:

- Keep responses JSON-safe.
- Do not echo debug text from API endpoints.
- Use `DB::query`, `DB::queryOne`, `DB::execute`, and `DB::insert` for SQL.
- Use prepared statements and parameter binding.
- Preserve CSRF checks for mutating requests.
- Preserve scan snapshots as frozen scan-time configuration.

## Frontend Rules

- Keep existing CTI visual language unless the task explicitly asks for a redesign.
- Avoid exposing API keys in DOM text, logs, URLs, screenshots, or exports.
- Keep scan actions clear: refresh, terminate, delete, export, clone, and settings
  should be visually distinct.
- If adding module UI filters, use the canonical module metadata from PHP rather
  than a second hard-coded list where possible.
- Prefer accessible labels/tooltips for icon-only controls.

## Public Documentation Rules

When updating Markdown for GitHub:

- Use relative paths, not private local machine paths.
- Show commands from the repository root.
- Redact credentials and sensitive scan outputs.
- Mention when a feature requires the Python service.
- Mention when a module requires third-party API credentials.
- Mention when a module depends on local tools such as `nmap`, `nuclei`,
  `wafw00f`, `whatweb`, or similar executables.
- Do not promise identical SpiderFoot results unless the module is parity tested.

## Common Commands

Start CTI Python service:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_cti_python_service.ps1"
```

Run Python tests:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\run_cti_engine_tests.ps1"
```

Run direct unittest discovery:

```powershell
python -m unittest discover -s test\python -v
```

Check PHP syntax for one file:

```powershell
php -l php\CtiPythonServiceRunner.php
```

Health-check the Python service in a browser:

```text
http://127.0.0.1:8765/health
```

## Troubleshooting Notes

If the browser shows `{"error":"Not found"}` at `http://127.0.0.1:8765`, use
`/health` or `/` instead. The root route may show only service metadata depending
on the current service implementation.

If CTI falls back to SpiderFoot or PHP instead of CTI Python, check:

- the Python service is running,
- `CTI_PYTHON_ENGINE_URL` is correct,
- the selected module is listed in `CTI_TO_SERVICE`,
- the target type is listed in `MODULE_QUERY_SUPPORT`,
- the target type is parity-approved in `PARITY_VERIFIED_SUPPORT`, and
- required API keys are configured in CTI settings.

If a tool-based module returns no results, check whether the local executable is
installed and available on `PATH`, or configured in that module's settings.
