#include "tools/scheduling/cron_ops.hpp"
#include "tools/scheduling/cron_backend.hpp"
#include "core/cron_store.hpp"
#include "core/server.hpp"
#include "registry/tool_registry.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

namespace {

json job_to_json(const CronJob& j) {
    return {
        {"job_id",      j.job_id},
        {"user_id",     j.user_id},
        {"schedule",    j.schedule},
        {"command",     j.command},
        {"description", j.description},
        {"context_id",  j.context_id},
        {"created_at",  j.created_at},
        {"updated_at",  j.updated_at}
    };
}

void apply_job_install(const Config& cfg, const CronJob& j,
                       const std::string& os_username) {
    cron_backend::write_per_job_meta(cfg, j);
    cron_backend::rebuild_user_schedule(
        cfg, os_username, Server::crons().list_for_user(os_username));
}

}  // namespace

void register_cron_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("cron_create", {
        "", "Schedule a recurring command for the bound user. The command is run as the "
        "user's OS account; each completed run posts the captured stdout/stderr/exit_code "
        "plus the job's metadata (description, context_id) to the bridge's configured "
        "webhook URL.",
        {"schedule", "command"}, {"description", "context_id"},
        [](const RequestContext& ctx, const json& args) -> json {
            if (ctx.os_username.empty()) {
                throw std::runtime_error("cron_create: request has no bound os_username");
            }
            std::string schedule    = args.at("schedule").get<std::string>();
            std::string command     = args.at("command").get<std::string>();
            std::string description = args.value("description", "");
            std::string context_id  = args.value("context_id", "");

            // Reject schedules the platform can't install before we mutate
            // the store. Linux validates loosely; Windows rejects shapes
            // schtasks /SC can't encode (see cron_to_schtasks).
            auto verr = cron_backend::validate_schedule(schedule);
            if (!verr.empty()) {
                throw std::runtime_error("cron_create: " + verr);
            }

            const Config& cfg = Server::config();
            CronJob j = Server::crons().add(ctx.user_id, ctx.os_username,
                                            schedule, command, description, context_id);
            try {
                apply_job_install(cfg, j, ctx.os_username);
            } catch (...) {
                // Roll back the in-memory + on-disk store entry on side-effect failure.
                try { Server::crons().remove(j.job_id, ctx.os_username); } catch (...) {}
                throw;
            }
            spdlog::info("cron_create user={} job_id={} schedule='{}'",
                         ctx.user_id, j.job_id, j.schedule);
            return job_to_json(j);
        }
    });

    reg.register_tool("cron_list", {
        "", "List the bound user's cron jobs.",
        {}, {},
        [](const RequestContext& ctx, const json&) -> json {
            if (ctx.os_username.empty()) {
                throw std::runtime_error("cron_list: request has no bound os_username");
            }
            json arr = json::array();
            for (const auto& j : Server::crons().list_for_user(ctx.os_username)) {
                arr.push_back(job_to_json(j));
            }
            return {{"jobs", arr}, {"count", arr.size()}};
        }
    });

    reg.register_tool("cron_update", {
        "", "Update an existing cron job. Any subset of fields may be supplied.",
        {"job_id"}, {"schedule", "command", "description", "context_id"},
        [](const RequestContext& ctx, const json& args) -> json {
            if (ctx.os_username.empty()) {
                throw std::runtime_error("cron_update: request has no bound os_username");
            }
            std::string job_id = args.at("job_id").get<std::string>();
            std::optional<std::string> sched, cmd, desc, cid;
            if (args.contains("schedule")) {
                sched = args["schedule"].get<std::string>();
                auto verr = cron_backend::validate_schedule(*sched);
                if (!verr.empty()) {
                    throw std::runtime_error("cron_update: " + verr);
                }
            }
            if (args.contains("command"))     cmd   = args["command"].get<std::string>();
            if (args.contains("description")) desc  = args["description"].get<std::string>();
            if (args.contains("context_id"))  cid   = args["context_id"].get<std::string>();

            const Config& cfg = Server::config();
            CronJob j = Server::crons().update(job_id, ctx.os_username, sched, cmd, desc, cid);
            apply_job_install(cfg, j, ctx.os_username);
            spdlog::info("cron_update user={} job_id={}", ctx.user_id, j.job_id);
            return job_to_json(j);
        }
    });

    reg.register_tool("cron_delete", {
        "", "Delete a cron job belonging to the bound user.",
        {"job_id"}, {},
        [](const RequestContext& ctx, const json& args) -> json {
            if (ctx.os_username.empty()) {
                throw std::runtime_error("cron_delete: request has no bound os_username");
            }
            std::string job_id = args.at("job_id").get<std::string>();
            const Config& cfg = Server::config();
            CronJob removed = Server::crons().remove(job_id, ctx.os_username);
            cron_backend::remove_per_job_meta(cfg, removed);
            cron_backend::rebuild_user_schedule(
                cfg, ctx.os_username,
                Server::crons().list_for_user(ctx.os_username));
            spdlog::info("cron_delete user={} job_id={}", ctx.user_id, removed.job_id);
            return {{"job_id", removed.job_id}, {"deleted", true}};
        }
    });
}
