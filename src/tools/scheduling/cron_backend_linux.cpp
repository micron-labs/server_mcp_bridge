#ifndef _WIN32
#include "tools/scheduling/cron_backend.hpp"
#include "core/server.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <random>
#include <sstream>

using json = nlohmann::json;

namespace cron_backend {

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

}  // namespace

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

void rebuild_user_schedule(const Config& cfg,
                           const std::string& os_username,
                           const std::vector<CronJob>& jobs) {
    std::string current = read_user_crontab(os_username);
    std::string fresh = build_crontab_text(current, jobs, cfg.cron_runner_path);
    write_user_crontab(cfg, os_username, fresh);
}

std::string validate_schedule(const std::string& schedule) {
    // Linux defers to cron itself for parsing. Reject only obviously
    // malformed input (fewer than 5 whitespace-separated fields, embedded
    // newline) that would break the crontab line we generate.
    if (schedule.empty()) return "schedule is empty";
    if (schedule.find('\n') != std::string::npos) return "schedule has newline";
    int fields = 0;
    bool in_field = false;
    for (char c : schedule) {
        bool space = (c == ' ' || c == '\t');
        if (!space && !in_field) { ++fields; in_field = true; }
        if (space) in_field = false;
    }
    if (fields < 5) return "schedule must have at least 5 fields";
    return "";
}

}  // namespace cron_backend
#endif
