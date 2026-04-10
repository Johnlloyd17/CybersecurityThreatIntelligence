<?php
// =============================================================================
//  PHASE 5 OPS - API KEY ROTATION SCHEDULE MANAGER
//  Seeds/updates rotation schedule rows and audits due/overdue modules.
// =============================================================================

declare(strict_types=1);

require_once __DIR__ . '/_bootstrap.php';

$usage = <<<TXT
Usage:
  php php/ops/phase5_key_rotation_schedule.php [--rotation-days=90] [--due-window-days=14] [--owner=secops@local] [--include-missing-key] [--audit-only] [--apply] [--strict]

Options:
  --rotation-days=...    Default rotation interval in days (default: 90)
  --due-window-days=...  "Due soon" window in days (default: 14)
  --owner=...            Owner contact used for seeded/updated rows
  --include-missing-key  Include key-required modules even when api_key is blank
  --audit-only           Skip seed/update and only perform audit
  --apply                Persist changes (default is dry-run)
  --strict               Exit non-zero if any schedule row is overdue
TXT;

$args = ops_parse_args($argv);
if (ops_bool($args, 'help', false)) {
    ops_print_usage($usage);
    exit(0);
}

$rotationDays = max(1, ops_int($args, 'rotation-days', 90));
$dueWindowDays = max(0, ops_int($args, 'due-window-days', 14));
$owner = ops_str($args, 'owner', 'secops@local');
$includeMissingKey = ops_bool($args, 'include-missing-key', false);
$auditOnly = ops_bool($args, 'audit-only', false);
$apply = ops_bool($args, 'apply', false);
$strict = ops_bool($args, 'strict', false);

if (!ops_table_exists('api_key_rotation_schedule')) {
    fwrite(
        STDERR,
        "[phase5] Table api_key_rotation_schedule not found. Run sql/migration_012_api_key_rotation_schedule.sql first.\n"
    );
    exit(1);
}

$modules = DB::query(
    "SELECT slug, name, requires_key, is_enabled,
            (api_key IS NOT NULL AND api_key <> '') AS has_key
     FROM api_configs
     WHERE requires_key = 1
     ORDER BY slug"
);

$existingRows = DB::query(
    "SELECT module_slug, owner_contact, rotation_days, last_rotated_at, next_rotation_due, is_active, notes
     FROM api_key_rotation_schedule"
);
$existing = [];
foreach ($existingRows as $row) {
    $existing[(string)$row['module_slug']] = $row;
}

$today = new DateTimeImmutable('today');
$defaultDueDate = $today->modify('+' . $rotationDays . ' days')->format('Y-m-d');

$seedSummary = [
    'considered' => 0,
    'skipped_missing_key' => 0,
    'would_insert' => 0,
    'inserted' => 0,
    'would_update' => 0,
    'updated' => 0,
];
$seedResults = [];
$inserts = [];
$updates = [];

if (!$auditOnly) {
    fwrite(STDOUT, "Phase 5 Key Rotation Schedule Seed/Update\n");
    fwrite(STDOUT, "Mode   : " . ($apply ? 'APPLY' : 'DRY-RUN') . "\n");
    fwrite(STDOUT, "Owner  : {$owner}\n");
    fwrite(STDOUT, "Rotate : {$rotationDays} days\n\n");

    foreach ($modules as $mod) {
        $slug = (string)$mod['slug'];
        $hasKey = (int)$mod['has_key'] === 1;
        $seedSummary['considered']++;

        if (!$includeMissingKey && !$hasKey) {
            $seedSummary['skipped_missing_key']++;
            $seedResults[] = [
                'slug' => $slug,
                'status' => 'skipped',
                'reason' => 'No API key configured.',
            ];
            fwrite(STDOUT, sprintf("[SKIPPED] %-20s (missing key)\n", $slug));
            continue;
        }

        $row = $existing[$slug] ?? null;
        if ($row === null) {
            $action = $apply ? 'inserted' : 'would_insert';
            if ($apply) {
                $seedSummary['inserted']++;
                $inserts[] = [
                    'slug' => $slug,
                    'owner' => $owner,
                    'rotation_days' => $rotationDays,
                    'next_due' => $defaultDueDate,
                ];
            } else {
                $seedSummary['would_insert']++;
            }

            $seedResults[] = [
                'slug' => $slug,
                'status' => $action,
                'rotation_days' => $rotationDays,
                'next_rotation_due' => $defaultDueDate,
            ];
            fwrite(STDOUT, sprintf("[%s] %-20s next_due=%s\n", strtoupper($action), $slug, $defaultDueDate));
            continue;
        }

        $existingRotationDays = (int)($row['rotation_days'] ?? 0);
        $existingOwner = (string)($row['owner_contact'] ?? '');
        $lastRotated = (string)($row['last_rotated_at'] ?? '');
        $nextDue = (string)($row['next_rotation_due'] ?? '');

        if ($lastRotated !== '') {
            $nextDueTarget = (new DateTimeImmutable($lastRotated))
                ->modify('+' . $rotationDays . ' days')
                ->format('Y-m-d');
        } elseif ($nextDue !== '') {
            $nextDueTarget = $nextDue;
        } else {
            $nextDueTarget = $defaultDueDate;
        }

        $needsUpdate =
            ($existingRotationDays !== $rotationDays)
            || ($existingOwner !== $owner && $owner !== '')
            || ($nextDue !== $nextDueTarget)
            || ((int)($row['is_active'] ?? 0) !== 1);

        if (!$needsUpdate) {
            $seedResults[] = [
                'slug' => $slug,
                'status' => 'unchanged',
                'rotation_days' => $existingRotationDays,
                'next_rotation_due' => $nextDue,
            ];
            fwrite(STDOUT, sprintf("[UNCHANGED] %-20s due=%s\n", $slug, $nextDue !== '' ? $nextDue : 'unset'));
            continue;
        }

        $action = $apply ? 'updated' : 'would_update';
        if ($apply) {
            $seedSummary['updated']++;
            $updates[] = [
                'slug' => $slug,
                'owner' => $owner !== '' ? $owner : $existingOwner,
                'rotation_days' => $rotationDays,
                'next_due' => $nextDueTarget,
            ];
        } else {
            $seedSummary['would_update']++;
        }

        $seedResults[] = [
            'slug' => $slug,
            'status' => $action,
            'rotation_days' => $rotationDays,
            'next_rotation_due' => $nextDueTarget,
        ];
        fwrite(STDOUT, sprintf("[%s] %-20s due=%s\n", strtoupper($action), $slug, $nextDueTarget));
    }

    if ($apply && (!empty($inserts) || !empty($updates))) {
        DB::transaction(static function () use ($inserts, $updates): void {
            foreach ($inserts as $ins) {
                DB::execute(
                    "INSERT INTO api_key_rotation_schedule
                        (module_slug, owner_contact, rotation_days, last_rotated_at, next_rotation_due, is_active, notes)
                     VALUES
                        (:slug, :owner, :rotation_days, NULL, :next_due, 1, 'Seeded by phase5_key_rotation_schedule.php')",
                    [
                        ':slug' => (string)$ins['slug'],
                        ':owner' => (string)$ins['owner'],
                        ':rotation_days' => (int)$ins['rotation_days'],
                        ':next_due' => (string)$ins['next_due'],
                    ]
                );
            }

            foreach ($updates as $upd) {
                DB::execute(
                    "UPDATE api_key_rotation_schedule
                     SET owner_contact = :owner,
                         rotation_days = :rotation_days,
                         next_rotation_due = :next_due,
                         is_active = 1,
                         updated_at = NOW()
                     WHERE module_slug = :slug",
                    [
                        ':slug' => (string)$upd['slug'],
                        ':owner' => (string)$upd['owner'],
                        ':rotation_days' => (int)$upd['rotation_days'],
                        ':next_due' => (string)$upd['next_due'],
                    ]
                );
            }
        });
    }
}

$auditRows = DB::query(
    "SELECT s.module_slug, c.name, c.is_enabled,
            (c.api_key IS NOT NULL AND c.api_key <> '') AS has_key,
            s.owner_contact, s.rotation_days, s.last_rotated_at, s.next_rotation_due, s.is_active
     FROM api_key_rotation_schedule s
     INNER JOIN api_configs c ON c.slug = s.module_slug
     WHERE s.is_active = 1
     ORDER BY s.next_rotation_due IS NULL, s.next_rotation_due, s.module_slug"
);

$auditSummary = [
    'active_rows' => 0,
    'overdue' => 0,
    'due_soon' => 0,
    'ok' => 0,
    'unset' => 0,
];
$auditResults = [];
$dueSoonBoundary = $today->modify('+' . $dueWindowDays . ' days');

fwrite(STDOUT, "\nRotation Audit\n");
fwrite(STDOUT, "Due-soon window: {$dueWindowDays} day(s)\n\n");

foreach ($auditRows as $row) {
    $auditSummary['active_rows']++;
    $slug = (string)$row['module_slug'];
    $due = (string)($row['next_rotation_due'] ?? '');

    $status = 'unset';
    $daysToDue = null;
    if ($due !== '') {
        try {
            $dueDate = new DateTimeImmutable($due);
            $diff = (int)$today->diff($dueDate)->format('%r%a');
            $daysToDue = $diff;

            if ($diff < 0) {
                $status = 'overdue';
            } elseif ($diff <= $dueWindowDays) {
                $status = 'due_soon';
            } else {
                $status = 'ok';
            }
        } catch (Throwable $e) {
            $status = 'unset';
        }
    }

    $auditSummary[$status]++;
    $auditResults[] = [
        'slug' => $slug,
        'status' => $status,
        'next_rotation_due' => $due !== '' ? $due : null,
        'days_to_due' => $daysToDue,
        'rotation_days' => (int)$row['rotation_days'],
        'owner_contact' => (string)($row['owner_contact'] ?? ''),
        'has_key' => (int)$row['has_key'] === 1,
        'module_enabled' => (int)$row['is_enabled'] === 1,
    ];

    $extra = $daysToDue === null ? 'days=n/a' : ('days=' . $daysToDue);
    fwrite(STDOUT, sprintf("[%s] %-20s due=%s (%s)\n", strtoupper($status), $slug, $due !== '' ? $due : 'unset', $extra));
}

$report = [
    'generated_at_utc' => gmdate('c'),
    'apply_mode' => $apply,
    'audit_only' => $auditOnly,
    'rotation_days' => $rotationDays,
    'due_window_days' => $dueWindowDays,
    'owner_contact' => $owner,
    'seed_summary' => $seedSummary,
    'seed_results' => $seedResults,
    'audit_summary' => $auditSummary,
    'audit_results' => $auditResults,
];
$reportPath = ops_write_json_report($report, 'phase5_key_rotation');

fwrite(STDOUT, "\nSeed Summary:\n");
foreach ($seedSummary as $k => $v) {
    fwrite(STDOUT, sprintf("  %-18s : %d\n", $k, $v));
}
fwrite(STDOUT, "Audit Summary:\n");
foreach ($auditSummary as $k => $v) {
    fwrite(STDOUT, sprintf("  %-18s : %d\n", $k, $v));
}
fwrite(STDOUT, "Report: {$reportPath}\n");

if ($strict && $auditSummary['overdue'] > 0) {
    exit(2);
}

exit(0);
