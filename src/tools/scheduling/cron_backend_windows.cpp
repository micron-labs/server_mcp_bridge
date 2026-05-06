#ifdef _WIN32
#include "tools/scheduling/cron_backend.hpp"
#include "tools/scheduling/cron_to_schtasks.hpp"
#include "platform/windows/priv_client.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>
#include <stdexcept>
#include <string>
#include <unordered_set>

using json = nlohmann::json;

namespace cron_backend {

namespace {

std::string shortid_of(const std::string& os_username) {
    auto s = priv_client::shortid_from_username(os_username);
    if (s.empty()) {
        throw std::runtime_error("cron: os_username '" + os_username +
                                 "' is not 'mcp_user_<shortid>'");
    }
    return s;
}

void check_ok(const json& resp, const std::string& what) {
    if (!resp.value("ok", false)) {
        throw std::runtime_error(what + ": " + resp.value("error", "priv call failed"));
    }
}

}  // namespace

void write_per_job_meta(const Config& cfg, const CronJob& j) {
    (void)cfg;  // path layout lives in the priv service
    json content = {
        {"job_id",      j.job_id},
        {"user_id",     j.user_id},
        {"schedule",    j.schedule},
        {"command",     j.command},
        {"description", j.description},
        {"context_id",  j.context_id}
    };
    json req = {
        {"op",      "cron_write_meta"},
        {"shortid", shortid_of(j.os_username)},
        {"job_id",  j.job_id},
        {"content", content}
    };
    check_ok(priv_client::call(req), "cron_write_meta");
}

void remove_per_job_meta(const Config& cfg, const CronJob& j) {
    (void)cfg;
    json req = {
        {"op",      "cron_delete_meta"},
        {"shortid", shortid_of(j.os_username)},
        {"job_id",  j.job_id}
    };
    auto resp = priv_client::call(req);
    if (!resp.value("ok", false)) {
        spdlog::warn("cron_delete_meta {}: {}", j.job_id,
                     resp.value("error", "(no error string)"));
    }
}

void rebuild_user_schedule(const Config& cfg,
                           const std::string& os_username,
                           const std::vector<CronJob>& jobs) {
    (void)cfg;
    std::string shortid = shortid_of(os_username);

    // Diff the live schtasks state against `jobs` so we don't churn tasks
    // that are already correct. The priv service returns the set of
    // currently-installed mcp_bridge\<shortid>\* task names.
    json list_req = {
        {"op",      "cron_list_jobs"},
        {"shortid", shortid}
    };
    json list_resp = priv_client::call(list_req);
    check_ok(list_resp, "cron_list_jobs");

    std::unordered_set<std::string> on_box;
    if (list_resp.contains("job_ids") && list_resp["job_ids"].is_array()) {
        for (auto& v : list_resp["job_ids"]) {
            if (v.is_string()) on_box.insert(v.get<std::string>());
        }
    }

    std::unordered_set<std::string> wanted;
    for (const auto& j : jobs) wanted.insert(j.job_id);

    // Install missing / changed jobs. We always re-install on schedule
    // change rather than diffing the schedule string — the priv-side
    // install is idempotent (uses /F), and re-translation is cheap.
    for (const auto& j : jobs) {
        auto tr = cron_to_schtasks::translate(j.schedule);
        if (!tr.error.empty()) {
            throw std::runtime_error("cron schedule '" + j.schedule + "': " +
                                     tr.error);
        }
        json req = {
            {"op",        "cron_install_job"},
            {"shortid",   shortid},
            {"job_id",    j.job_id},
            {"schedule",  j.schedule},
            {"sched_args", tr.args}
        };
        check_ok(priv_client::call(req), "cron_install_job " + j.job_id);
    }

    // Remove tasks no longer in the wanted set.
    for (const auto& jid : on_box) {
        if (wanted.count(jid)) continue;
        json req = {
            {"op",      "cron_remove_job"},
            {"shortid", shortid},
            {"job_id",  jid}
        };
        auto resp = priv_client::call(req);
        if (!resp.value("ok", false)) {
            spdlog::warn("cron_remove_job {}: {}", jid,
                         resp.value("error", "(no error string)"));
        }
    }
}

std::string validate_schedule(const std::string& schedule) {
    auto tr = cron_to_schtasks::translate(schedule);
    return tr.error;  // "" iff supported
}

}  // namespace cron_backend
#endif
