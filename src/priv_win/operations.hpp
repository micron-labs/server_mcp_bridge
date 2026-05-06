#pragma once
#ifdef _WIN32
#include <json.hpp>
#include <map>
#include <string>

using json = nlohmann::json;

namespace priv_win {

// Each handler returns a JSON response. Conventions:
//   {"ok": true,  "exit_code": N, "stdout": "...", "stderr": "..."}
//   {"ok": false, "error": "..."}
//
// Handlers do all input validation themselves (the dispatcher only routes
// op names to handlers). Validation is paranoid by design: a daemon
// compromise must not be able to slip arbitrary syscalls past this layer.
//
// All handlers are reentrant; the pipe server may invoke them concurrently.

json handle_useradd(const json& req);
json handle_userdel(const json& req);
json handle_install_grant(const json& req);
json handle_revoke_grant(const json& req);
json handle_install_system_admin(const json& req);
json handle_revoke_system_admin(const json& req);
json handle_prepare_user_state(const json& req);
json handle_cleanup_user_state(const json& req);
json handle_run_as(const json& req);
json handle_spawn_background_as(const json& req);

// ---- Cron ops ----------------------------------------------------------
// schtasks-backed equivalents of the Linux crontab dance. Tasks register
// under the namespace `mcp_bridge\<shortid>\<job_id>` so a single LIST
// scope cleanly separates per-tenant schedules. Each task is registered to
// run as the per-tenant user identity using the LSA-stored password the
// useradd handler captured.

json handle_cron_install_job(const json& req);
json handle_cron_remove_job(const json& req);
json handle_cron_list_jobs(const json& req);
json handle_cron_write_meta(const json& req);
json handle_cron_delete_meta(const json& req);

// ---- Helpers (exposed for testability) ----

// `mcp_user_<shortid>` per the Linux convention; same shape on Windows so
// behaviour is symmetric. Returns "" if shortid charset/length is invalid.
std::string username_from_shortid(const std::string& shortid);

// Crockford-base32 8-char shortid validator. Same rules as Linux side.
bool valid_shortid(const std::string& s);

// 16-hex grantid validator.
bool valid_grantid(const std::string& s);

}  // namespace priv_win
#endif
