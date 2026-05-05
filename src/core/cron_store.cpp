#include "core/cron_store.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>

using json = nlohmann::json;

namespace {

std::string make_jobid() {
    static const char hex[] = "0123456789abcdef";
    unsigned char buf[8];
    std::random_device rd;
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = static_cast<unsigned char>(rd());
    std::string out(16, '0');
    for (size_t i = 0; i < sizeof(buf); ++i) {
        out[i * 2]     = hex[buf[i] >> 4];
        out[i * 2 + 1] = hex[buf[i] & 0xf];
    }
    return out;
}

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

void atomic_write(const std::string& path, const std::string& data) {
    std::string tmp = path + ".tmp." + std::to_string(::getpid());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) throw std::runtime_error("open " + tmp + ": " + std::strerror(errno));
    ssize_t off = 0;
    while (off < (ssize_t)data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); ::unlink(tmp.c_str()); throw std::runtime_error("write"); }
        off += n;
    }
    if (::fsync(fd) != 0) {
        ::close(fd); ::unlink(tmp.c_str());
        throw std::runtime_error("fsync");
    }
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw std::runtime_error("rename to " + path + ": " + std::strerror(errno));
    }
}

}

bool CronStore::valid_jobid(const std::string& s) {
    if (s.size() != 16) return false;
    for (char c : s) {
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

// Restrict each schedule field to the cron metacharacters and digits. This
// blocks shell injection (no whitespace beyond field separators, no quotes,
// no `;` `&` `|` `$` etc.) while still allowing every legal cron form (`*`,
// `*/5`, `0-23/2`, `1,3,5`).
bool CronStore::valid_schedule(const std::string& s) {
    if (s.empty() || s.size() > 200) return false;
    int field_count = 1;
    bool in_field = false;
    for (char c : s) {
        if (c == ' ' || c == '\t') {
            if (in_field) { field_count++; in_field = false; }
            continue;
        }
        in_field = true;
        bool ok = (c >= '0' && c <= '9') || c == '*' || c == '/' || c == ',' || c == '-';
        if (!ok) return false;
    }
    return field_count == 5 && in_field;
}

CronStore::CronStore(std::string state_dir) : state_dir_(std::move(state_dir)) {}

void CronStore::load() {
    std::lock_guard lk(mutex_);
    load_locked();
}

void CronStore::load_locked() {
    std::string path = state_dir_ + "/crons.json";
    std::ifstream f(path);
    if (!f.is_open()) return;
    json doc;
    try { f >> doc; } catch (const std::exception& e) {
        spdlog::warn("cron_store: cannot parse {}: {}", path, e.what());
        return;
    }
    if (!doc.is_array()) return;
    for (const auto& j : doc) {
        if (!j.is_object()) continue;
        CronJob c;
        c.job_id      = j.value("job_id", "");
        c.user_id     = j.value("user_id", "");
        c.os_username = j.value("os_username", "");
        c.schedule    = j.value("schedule", "");
        c.command     = j.value("command", "");
        c.description = j.value("description", "");
        c.context_id  = j.value("context_id", "");
        c.created_at  = j.value("created_at", int64_t{0});
        c.updated_at  = j.value("updated_at", int64_t{0});
        if (!valid_jobid(c.job_id)) continue;
        jobs_[c.job_id] = std::move(c);
    }
    spdlog::info("cron_store: loaded {} cron(s) from {}", jobs_.size(), path);
}

void CronStore::persist_locked() {
    json arr = json::array();
    for (const auto& [_, c] : jobs_) {
        arr.push_back({
            {"job_id", c.job_id},
            {"user_id", c.user_id},
            {"os_username", c.os_username},
            {"schedule", c.schedule},
            {"command", c.command},
            {"description", c.description},
            {"context_id", c.context_id},
            {"created_at", c.created_at},
            {"updated_at", c.updated_at}
        });
    }
    atomic_write(state_dir_ + "/crons.json", arr.dump(2) + "\n");
}

CronJob CronStore::add(const std::string& user_id,
                       const std::string& os_username,
                       const std::string& schedule,
                       const std::string& command,
                       const std::string& description,
                       const std::string& context_id) {
    if (!valid_schedule(schedule)) {
        throw std::runtime_error("cron_store: invalid schedule");
    }
    if (command.empty()) throw std::runtime_error("cron_store: command must not be empty");

    CronJob c;
    // Loop only to be safe against the (vanishingly small) chance of a 64-bit collision.
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::string id = make_jobid();
        if (jobs_.find(id) == jobs_.end()) { c.job_id = id; break; }
    }
    if (c.job_id.empty()) throw std::runtime_error("cron_store: could not allocate job_id");

    c.user_id     = user_id;
    c.os_username = os_username;
    c.schedule    = schedule;
    c.command     = command;
    c.description = description;
    c.context_id  = context_id;
    c.created_at  = now_seconds();
    c.updated_at  = c.created_at;

    {
        std::lock_guard lk(mutex_);
        jobs_[c.job_id] = c;
        try { persist_locked(); }
        catch (...) { jobs_.erase(c.job_id); throw; }
    }
    return c;
}

CronJob CronStore::update(const std::string& job_id,
                          const std::string& os_username,
                          const std::optional<std::string>& schedule,
                          const std::optional<std::string>& command,
                          const std::optional<std::string>& description,
                          const std::optional<std::string>& context_id) {
    if (!valid_jobid(job_id)) throw std::runtime_error("cron_store: invalid job_id");
    if (schedule && !valid_schedule(*schedule)) {
        throw std::runtime_error("cron_store: invalid schedule");
    }
    if (command && command->empty()) {
        throw std::runtime_error("cron_store: command must not be empty");
    }

    std::lock_guard lk(mutex_);
    auto it = jobs_.find(job_id);
    if (it == jobs_.end()) throw std::runtime_error("cron_store: job_id not found");
    if (it->second.os_username != os_username) {
        throw std::runtime_error("cron_store: job_id does not belong to this user");
    }
    CronJob prev = it->second;
    if (schedule)    it->second.schedule    = *schedule;
    if (command)     it->second.command     = *command;
    if (description) it->second.description = *description;
    if (context_id)  it->second.context_id  = *context_id;
    it->second.updated_at = now_seconds();
    try { persist_locked(); }
    catch (...) { it->second = prev; throw; }
    return it->second;
}

CronJob CronStore::remove(const std::string& job_id, const std::string& os_username) {
    if (!valid_jobid(job_id)) throw std::runtime_error("cron_store: invalid job_id");
    std::lock_guard lk(mutex_);
    auto it = jobs_.find(job_id);
    if (it == jobs_.end()) throw std::runtime_error("cron_store: job_id not found");
    if (it->second.os_username != os_username) {
        throw std::runtime_error("cron_store: job_id does not belong to this user");
    }
    CronJob removed = it->second;
    jobs_.erase(it);
    try { persist_locked(); }
    catch (...) { jobs_[removed.job_id] = removed; throw; }
    return removed;
}

std::vector<CronJob> CronStore::list_for_user(const std::string& os_username) const {
    std::lock_guard lk(mutex_);
    std::vector<CronJob> out;
    for (const auto& [_, c] : jobs_) {
        if (c.os_username == os_username) out.push_back(c);
    }
    return out;
}

std::optional<CronJob> CronStore::find(const std::string& job_id) const {
    std::lock_guard lk(mutex_);
    auto it = jobs_.find(job_id);
    if (it == jobs_.end()) return std::nullopt;
    return it->second;
}

std::size_t CronStore::size() const {
    std::lock_guard lk(mutex_);
    return jobs_.size();
}
