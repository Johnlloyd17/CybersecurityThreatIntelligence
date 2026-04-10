<?php
// =============================================================================
//  CTI — API Quota Tracker
//  php/ApiQuotaTracker.php
//
//  Tracks daily API call counts per module using the api_daily_usage table.
//  Modules call check() before making an API request and increment() after.
// =============================================================================

require_once __DIR__ . '/db.php';

class ApiQuotaTracker
{
    /**
     * Get the number of API calls made today for a given module.
     */
    public static function getUsageToday(string $moduleSlug): int
    {
        $row = DB::queryOne(
            "SELECT call_count FROM api_daily_usage WHERE module_slug = :slug AND usage_date = CURDATE()",
            [':slug' => $moduleSlug]
        );
        return $row ? (int)$row['call_count'] : 0;
    }

    /**
     * Check whether the module has remaining quota for today.
     *
     * @param  string $moduleSlug  Module identifier (e.g. 'virustotal')
     * @param  int    $dailyLimit  Maximum calls allowed per day (0 = unlimited)
     * @return bool   true if the request is allowed
     */
    public static function check(string $moduleSlug, int $dailyLimit): bool
    {
        if ($dailyLimit <= 0) return true; // unlimited
        return self::getUsageToday($moduleSlug) < $dailyLimit;
    }

    /**
     * Increment the daily counter for a module by $count.
     * Uses INSERT … ON DUPLICATE KEY UPDATE for atomic upsert.
     */
    public static function increment(string $moduleSlug, int $count = 1): void
    {
        DB::execute(
            "INSERT INTO api_daily_usage (module_slug, usage_date, call_count)
             VALUES (:slug, CURDATE(), :cnt)
             ON DUPLICATE KEY UPDATE call_count = call_count + :cnt2",
            [':slug' => $moduleSlug, ':cnt' => $count, ':cnt2' => $count]
        );
    }
}
