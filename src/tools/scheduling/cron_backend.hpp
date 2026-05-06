#pragma once
#include "core/config.hpp"
#include "core/cron_store.hpp"
#include <string>
#include <vector>

// Cron lifecycle operations split out of cron_ops.cpp so the per-platform
// scheduler integration (Linux: crontab + a runner shell script; Windows:
// schtasks.exe + a PowerShell runner via the priv service) can live in
// separate translation units. The cron tools registered in cron_ops.cpp
// drive these in a platform-neutral way.
//
// Failure model: every function throws std::runtime_error on failure. The
// caller (cron_ops.cpp) is responsible for rolling back the in-memory
// CronStore entry if a backend call fails partway through.
namespace cron_backend {

// Persist the user-readable per-job metadata file consumed by the runner.
// On Linux: writes <users_state_dir>/<os_username>/crons/<job_id>.json owned
// by the user, mode 0600. On Windows: writes the same path under
// %ProgramData%\mcp_bridge\users_state\... via the priv service.
void write_per_job_meta(const Config& cfg, const CronJob& j);

// Inverse of write_per_job_meta. Idempotent — best-effort, never throws.
void remove_per_job_meta(const Config& cfg, const CronJob& j);

// Materialise the user's full schedule. On Linux this rewrites the user's
// crontab from the current job set (one tagged block per job). On Windows
// it diffs the live schtasks state against `jobs` and reconciles by
// installing missing tasks and removing stale ones. `jobs` is the source
// of truth — anything for this user not in the list is removed.
void rebuild_user_schedule(const Config& cfg,
                           const std::string& os_username,
                           const std::vector<CronJob>& jobs);

// Validate that `schedule` is something the platform can install. Returns
// "" on success, an error message on failure. Linux accepts any 5-field
// expression (cron itself does the parsing). Windows accepts a subset of
// patterns that schtasks /SC can faithfully encode — see
// cron_backend_windows.cpp for the supported shapes.
std::string validate_schedule(const std::string& schedule);

}  // namespace cron_backend
