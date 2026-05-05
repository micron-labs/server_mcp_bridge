#pragma once
#include "core/config.hpp"
#include <string>

// Writes per-user runtime.json files (containing the bridge-wide webhook URL
// and optional secret token) into each user's state dir, where the cron-runner
// can read them as that OS user. The state dir + ownership must already have
// been provisioned by the priv helper's `prepare-user-state` verb.
namespace runtime_sync {

// Write the runtime.json for one user. `os_username` is e.g. `mcp_user_abc12345`.
// Throws std::runtime_error if the spawned write fails.
void write_for_user(const Config& cfg, const std::string& os_username);

// Iterate every <shortid>.json in cfg.users_dir, derive os_username, and call
// write_for_user. Failures for individual users are logged but do not abort the
// loop, so one malformed user record can't poison the rest.
void write_all(const Config& cfg);

}
