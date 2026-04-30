# CTI Platform Guide for GitHub Copilot

Use this file as the first context document when working in this repository.
It explains the dashboard login flow and the first-party Python CTI engine.

## Project Shape

This is a PHP + MySQL Cyber Threat Intelligence platform with a first-party
Python scan engine.

- `index.php` is the public landing page and login form.
- `dashboard.php`, `newscan.php`, `scaninfo.php`, `query.php`, and
  `settings.php` are authenticated dashboard pages.
- `assets/js/auth.js` is the shared browser auth helper.
- `php/api/auth.php` is the JSON authentication API.
- `php/api/query.php` is the main scan/query API.
- `php/ScanExecutor.php` selects the scan backend and persists scan results.
- `python/cti_service/` exposes the Python engine over HTTP.
- `python/cti_engine/` contains the event-driven CTI engine and modules.
- `spiderfoot-master/` is the vendored SpiderFoot reference code.
- `python/spiderfoot_bridge/` and `php/SpiderFootBridgeRunner.php` bridge to
  SpiderFoot when a scan is not routed to the first-party Python engine.

Do not add API keys, passwords, or tokens to docs or source. Use environment
variables, database records, or redacted examples.

## Dashboard Login

Local URL:

```text
http://localhost/CybersecurityThreatIntelligence/index.php
```

Seeded local account from `sql/schema.sql`:

```text
Email: admin@cti.local
Password: Admin@1234
Role: admin
```

Login flow:

1. The user opens `index.php`.
2. The login form in `index.php` is handled by `assets/js/landing.js`.
3. `landing.js` calls `Auth.login(email, password)` from `assets/js/auth.js`.
4. `Auth.login()` first requests a CSRF token from
   `php/api/auth.php?action=csrf`.
5. It posts JSON to `php/api/auth.php?action=login` with `email`, `password`,
   and `_csrf_token`.
6. `php/api/auth.php` validates the CSRF token, rate-limits failed attempts,
   loads the user by email from `users`, verifies `password_hash`, regenerates
   the session ID, and stores user fields in `$_SESSION`.
7. On success, the browser redirects to `dashboard.php`.
8. Protected dashboard pages load `assets/js/auth.js` and `assets/js/dashboard.js`.
   `dashboard.js` calls `Auth.requireAuth()`, which checks
   `php/api/auth.php?action=session` and redirects unauthenticated users back
   to `index.php#hero-login-panel`.
9. Logout calls `php/api/auth.php?action=logout` and destroys the PHP session.

Useful auth files:

- `php/config.php`: session lifetime, cookie name, CSRF settings, bcrypt cost,
  local database defaults.
- `php/security-headers.php`: starts secure sessions, sends headers, creates
  and validates CSRF tokens.
- `php/RateLimiter.php`: failed-login lockout behavior.
- `php/db.php`: PDO connection and password hashing/verification helpers.

If login fails locally, confirm that MySQL is running, the `cti_platform`
database exists, and the `users` table contains `admin@cti.local`. Failed login
attempts are locked after the configured threshold in `php/config.php`.

## CTI Scan Backend Selection

`php/ScanExecutor.php` decides which backend handles a scan:

1. Try the first-party Python engine if
   `CtiPythonServiceRunner::supportsScan($queryType, $selectedApis)` returns
   true. A module must be migrated, support the target type, and be listed as
   parity verified in `php/CtiPythonServiceRunner.php`.
2. If the Python service is unavailable or unsupported, try the SpiderFoot
   bridge when `php/SpiderFootBridgeRunner.php` supports the scan.
3. If neither Python path is used, fall back to the native PHP CTI backend:
   event queue if available, otherwise the legacy enrichment flow.

Backend selection is recorded in the scan `config_snapshot` as
`engine_backend` and `engine_backend_label`, then shown by `php/api/query.php`.

## Python Service

The service layer lives in `python/cti_service/`.

Start it locally with:

```powershell
.\scripts\run_cti_python_service.ps1
```

or:

```powershell
python -m python.cti_service
```

Default environment:

```text
CTI_ENGINE_HOST=127.0.0.1
CTI_ENGINE_PORT=8765
CTI_ENGINE_MAX_WORKERS=4
```

PHP connects to the service at `CTI_PYTHON_ENGINE_URL`, or
`http://127.0.0.1:8765` by default.

Service routes from `python/cti_service/app.py`:

- `GET /health`: health check.
- `POST /api/v1/scans`: create an async scan job.
- `GET /api/v1/scans/{scan_id}`: job status.
- `GET /api/v1/scans/{scan_id}/logs`: projected logs.
- `GET /api/v1/scans/{scan_id}/results`: projected scan results.
- `POST /api/v1/scans/{scan_id}/terminate`: request cancellation.

`python/cti_service/jobs.py` runs jobs in a `ThreadPoolExecutor`, tracks status,
stores the projection, and uses a cancellation event for terminate requests.

## Python CTI Engine

The engine layer lives in `python/cti_engine/`.

Important files:

- `targets.py`: normalizes raw targets into types such as `domain`, `ip`,
  `url`, `email`, `hash`, `phone`, `cve`, `bitcoin`, or `username`.
- `settings.py`: carries frozen global settings, per-module settings, and API
  config snapshots from PHP into Python.
- `context.py`: defines `ScanRequest` and `ScanContext`.
- `events.py`: defines normalized `ScanEvent` and `ScanLogEntry`.
- `module_base.py`: base contract for Python modules.
- `registry.py`: registers modules and finds modules that watch each event type.
- `queue.py`: the event queue engine.
- `projector.py`: converts engine events/logs/correlations into CTI-compatible
  result rows, event rows, log rows, and summary counts.
- `modules/__init__.py`: registers built-in Python modules.

Engine flow:

1. PHP builds a scan payload in `php/CtiPythonServiceRunner.php`.
2. `python/cti_service/schemas.py` turns that payload into a `CreateScanRequest`.
3. `CreateScanRequest.to_engine_request()` normalizes the target and builds a
   `SettingsSnapshot`.
4. `python/cti_service/worker.py` creates a `ModuleRegistry`, registers built-in
   modules, creates a `ScanContext`, and runs `ScanQueueEngine`.
5. `ScanQueueEngine.run()` creates one seed `ScanEvent` for the root target.
6. The queue asks `ModuleRegistry.watchers_for(event_type, selected_instances)`
   which selected modules handle the current event.
7. Each module receives the event and yields child `ScanEvent` objects.
8. The engine deduplicates child events by deterministic event ID, scores
   severity from risk, appends events to context, and enqueues new children.
9. When the queue completes or cancellation is requested, the engine runs simple
   correlations and returns events, logs, and correlations.
10. `projector.py` converts the engine result into the JSON shape PHP imports.
11. `php/CtiPythonServiceRunner.php` imports projected results into
    `query_history`, `scan_events`, `scan_logs`, and `scan_correlations`.

## Adding or Updating Python Modules

When editing a Python CTI module:

1. Subclass `BaseModule` from `python/cti_engine/module_base.py`.
2. Set `slug`, `name`, `watched_types`, `produced_types`, and `requires_key`.
3. Read settings through `ctx.module_settings_for(slug)` and API config through
   `ctx.api_config_for(slug)`.
4. Implement `async def handle(self, event, ctx)` and yield `ScanEvent` objects.
5. Register the module in `python/cti_engine/modules/__init__.py`.
6. Add or update tests in `test/python/`.
7. Only update `PARITY_VERIFIED_SUPPORT` in `php/CtiPythonServiceRunner.php`
   after the Python module has parity coverage for that target type.

Run Python tests with:

```powershell
.\scripts\run_cti_engine_tests.ps1
```

or:

```powershell
python -m unittest discover -s test\python -v
```

## PHP Scan Persistence

The Python service does not write directly to MySQL. It returns projected JSON.
`php/CtiPythonServiceRunner.php` imports that projection into existing CTI
tables inside a DB transaction.

Key import responsibilities:

- Results become `query_history` rows.
- Engine events become `scan_events` rows.
- Logs become `scan_logs` rows.
- Correlations become `scan_correlations` rows.
- Scan counts and finished status are updated on `scans`.

Keep projected Python output compatible with
`python/cti_engine/storage/models.py` and the PHP import methods in
`php/CtiPythonServiceRunner.php`.

## Copilot Editing Notes

- Prefer existing patterns before introducing new abstractions.
- Keep PHP API responses JSON-safe. Do not echo debugging text from API files.
- Use prepared statements through `DB::query`, `DB::queryOne`, `DB::execute`,
  and `DB::insert`.
- Preserve session and CSRF behavior in auth-related changes.
- Treat `config_snapshot` as the frozen scan-time source of settings.
- Keep Python modules deterministic where possible so parity tests are stable.
- Do not mark a module parity verified until tests prove the Python route
  matches the expected CTI behavior for that target type.
