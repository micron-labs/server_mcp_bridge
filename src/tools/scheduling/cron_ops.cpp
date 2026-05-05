#include "tools/scheduling/cron_ops.hpp"
#include "core/cron_store.hpp"
#include "core/server.hpp"
#include "platform/platform.hpp"
#include "registry/tool_registry.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <random>
#include <sstream>

using json = nlohmann::json;

namespace {

constexpr const char* kBlockTagPrefix = "# mcp_bridge:job_id=";

std::string base64_encode(const std::string& in) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= in.size()) {
        unsigned v = (static_cast<unsigned char>(in[i]) << 16)
                   | (static_cast<unsigned char>(in[i + 1]) << 8)
                   |  static_cast<unsigned char>(in[i + 2]);
        out.push_back(tbl[(v >> 18) & 0x3f]);
        out.push_back(tbl[(v >> 12) & 0x3f]);
        out.push_back(tbl[(v >>  6) & 0x3f]);
        out.push_back(tbl[ v        & 0x3f]);
        i += 3;
    }
    if (i < in.size()) {
        unsigned v = static_cast<unsigned char>(in[i]) << 16;
        if (i + 1 < in.size()) v |= static_cast<unsigned char>(in[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3f]);
        out.push_back(tbl[(v >> 12) & 0x3f]);
        out.push_back(i + 1 < in.size() ? tbl[(v >> 6) & 0x3f] : '=');
        out.push_back('=');
    }
    return out;
}

std::string read_user_crontab(const std::string& os_username) {
    auto r = run_process_as(os_username, "crontab -l 2>/dev/null || true", "", 30, {});
    return r.stdout_str;
}

// Build the crontab text from `existing` (with our managed blocks stripped)
// plus a fresh set of blocks for every job in `jobs`.
std::string build_crontab_text(const std::string& existing,
                               const std::vector<CronJob>& jobs,
                               const std::string& runner_path) {
    std::string out;
    std::istringstream is(existing);
    std::string line;
    bool skip_next = false;
    while (std::getline(is, line)) {
        if (skip_next) { skip_next = false; continue; }
        if (line.compare(0, std::strlen(kBlockTagPrefix), kBlockTagPrefix) == 0) {
            // Drop the tag line and the schedule line that follows it.
            skip_next = true;
            continue;
        }
        out += line;
        out += '\n';
    }
    for (const auto& j : jobs) {
        out += kBlockTagPrefix;
        out += j.job_id;
        out += '\n';
        out += j.schedule;
        out += ' ';
        out += runner_path;
        out += ' ';
        out += j.job_id;
        out += '\n';
    }
    return out;
}

void write_user_crontab(const Config& cfg,
                        const std::string& os_username,
                        const std::string& text) {
    // Stage in state_dir as a daemon-owned temp file (mode 0644 so the user's
    // crontab(1) can read it), then `crontab <path>` as the user.
    static std::random_device rd;
    char rand_hex[17];
    unsigned long long r = (static_cast<unsigned long long>(rd()) << 32) | rd();
    std::snprintf(rand_hex, sizeof(rand_hex), "%016llx", r);

    std::string tmp = cfg.state_dir + "/.cron_pending_" + rand_hex + ".txt";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) throw std::runtime_error("open " + tmp + ": " + std::strerror(errno));
    ssize_t off = 0;
    while (off < (ssize_t)text.size()) {
        ssize_t n = ::write(fd, text.data() + off, text.size() - off);
        if (n < 0) { ::close(fd); ::unlink(tmp.c_str()); throw std::runtime_error("write"); }
        off += n;
    }
    ::fsync(fd);
    ::close(fd);

    auto r2 = run_process_as(os_username, "crontab '" + tmp + "'", "", 30, {});
    ::unlink(tmp.c_str());
    if (r2.exit_code != 0) {
        throw std::runtime_error("crontab install for " + os_username +
                                 " exit=" + std::to_string(r2.exit_code) +
                                 " stderr=" + r2.stderr_str);
    }
}

void rebuild_user_crontab(const Config& cfg, const std::string& os_username) {
    auto jobs = Server::crons().list_for_user(os_username);
    std::string current = read_user_crontab(os_username);
    std::string fresh = build_crontab_text(current, jobs, cfg.cron_runner_path);
    write_user_crontab(cfg, os_username, fresh);
}

void write_per_job_meta(const Config& cfg, const CronJob& j) {
    json content = {
        {"job_id",      j.job_id},
        {"user_id",     j.user_id},
        {"schedule",    j.schedule},
        {"command",     j.command},
        {"description", j.description},
        {"context_id",  j.context_id}
    };
    std::string body = content.dump(2) + "\n";
    std::string b64 = base64_encode(body);

    std::string dir = cfg.users_state_dir + "/" + j.os_username + "/crons";
    std::string path = dir + "/" + j.job_id + ".json";
    std::string tmp = path + ".tmp";

    std::string cmd =
        "umask 077 && printf '%s' '" + b64 + "' | base64 -d > '" + tmp + "' && "
        "chmod 600 '" + tmp + "' && mv '" + tmp + "' '" + path + "'";
    auto r = run_process_as(j.os_username, cmd, "", 30, {});
    if (r.exit_code != 0) {
        throw std::runtime_error("write per-job meta " + path +
                                 " exit=" + std::to_string(r.exit_code) +
                                 " stderr=" + r.stderr_str);
    }
}

void remove_per_job_meta(const Config& cfg, const CronJob& j) {
    std::string path = cfg.users_state_dir + "/" + j.os_username + "/crons/"
                       + j.job_id + ".json";
    auto r = run_process_as(j.os_username, "rm -f -- '" + path + "'", "", 30, {});
    if (r.exit_code != 0) {
        spdlog::warn("remove per-job meta {}: exit={} stderr={}",
                     path, r.exit_code, r.stderr_str);
    }
}

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

}

void register_cron_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("cron_create", {
        "", "Schedule a recurring command for the bound user. The command is run as the "
        "user's OS account on the server crontab; each completed run posts the captured "
        "stdout/stderr/exit_code plus the job's metadata (description, context_id) to the "
        "bridge's configured webhook URL.",
        {"schedule", "command"}, {"description", "context_id"},
        [](const RequestContext& ctx, const json& args) -> json {
            if (ctx.os_username.empty()) {
                throw std::runtime_error("cron_create: request has no bound os_username");
            }
            std::string schedule    = args.at("schedule").get<std::string>();
            std::string command     = args.at("command").get<std::string>();
            std::string description = args.value("description", "");
            std::string context_id  = args.value("context_id", "");

            const Config& cfg = Server::config();
            CronJob j = Server::crons().add(ctx.user_id, ctx.os_username,
                                            schedule, command, description, context_id);
            try {
                write_per_job_meta(cfg, j);
                rebuild_user_crontab(cfg, ctx.os_username);
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
            if (args.contains("schedule"))    sched = args["schedule"].get<std::string>();
            if (args.contains("command"))     cmd   = args["command"].get<std::string>();
            if (args.contains("description")) desc  = args["description"].get<std::string>();
            if (args.contains("context_id"))  cid   = args["context_id"].get<std::string>();

            const Config& cfg = Server::config();
            CronJob j = Server::crons().update(job_id, ctx.os_username, sched, cmd, desc, cid);
            write_per_job_meta(cfg, j);
            rebuild_user_crontab(cfg, ctx.os_username);
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
            remove_per_job_meta(cfg, removed);
            rebuild_user_crontab(cfg, ctx.os_username);
            spdlog::info("cron_delete user={} job_id={}", ctx.user_id, removed.job_id);
            return {{"job_id", removed.job_id}, {"deleted", true}};
        }
    });
}
