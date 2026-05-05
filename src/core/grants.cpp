#include "core/grants.hpp"
#include <spdlog/spdlog.h>
#include <dirent.h>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <stdexcept>

extern char** environ;

namespace {

std::string make_grantid() {
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

bool valid_grantid(const std::string& s) {
    if (s.size() != 16) return false;
    for (char c : s) {
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
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

std::vector<std::string> sudoers_dropins(const std::string& dir) {
    std::vector<std::string> out;
    DIR* d = ::opendir(dir.c_str());
    if (!d) return out;
    while (auto* e = ::readdir(d)) {
        std::string n = e->d_name;
        if (n.compare(0, 10, "mcp_grant_") == 0 && n.size() == 10 + 16) {
            out.push_back(n.substr(10));  // the grantid
        }
    }
    ::closedir(d);
    return out;
}

}

GrantManager::GrantManager(Config cfg) : config_(std::move(cfg)) {
    std::lock_guard lk(mutex_);
    load_state_locked();
}

GrantManager::~GrantManager() {
    stop_sweeper();
}

std::size_t GrantManager::size() const {
    std::lock_guard lk(mutex_);
    return grants_.size();
}

void GrantManager::load_state_locked() {
    std::string path = config_.state_dir + "/grants.json";
    std::ifstream f(path);
    if (!f.is_open()) return;

    json doc;
    try { f >> doc; } catch (const std::exception& e) {
        spdlog::warn("grants: cannot parse {}: {}", path, e.what());
        return;
    }
    if (!doc.is_array()) return;
    for (const auto& g : doc) {
        if (!g.is_object()) continue;
        Grant rec;
        rec.grantid = g.value("grantid", "");
        rec.shortid = g.value("shortid", "");
        rec.template_name = g.value("template_name", "");
        rec.captured_args = g.value("captured_args", json::object());
        rec.expires_at = g.value("expires_at", int64_t{0});
        if (!valid_grantid(rec.grantid)) continue;
        grants_[rec.grantid] = std::move(rec);
    }
    spdlog::info("grants: loaded {} grant(s) from {}", grants_.size(), path);
}

void GrantManager::persist_state_locked() {
    json arr = json::array();
    for (const auto& [_, g] : grants_) {
        arr.push_back({
            {"grantid", g.grantid},
            {"shortid", g.shortid},
            {"template_name", g.template_name},
            {"captured_args", g.captured_args},
            {"expires_at", g.expires_at}
        });
    }
    atomic_write(config_.state_dir + "/grants.json", arr.dump(2) + "\n");
}

int GrantManager::spawn_helper(const std::vector<std::string>& argv,
                               std::string& stderr_out) const {
    int err_pipe[2];
    if (::pipe(err_pipe) != 0) {
        stderr_out = std::string("pipe: ") + std::strerror(errno);
        return -1;
    }

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addclose(&actions, err_pipe[0]);
    posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, err_pipe[1]);

    std::vector<char*> argv_c;
    argv_c.reserve(argv.size() + 1);
    for (auto& a : argv) argv_c.push_back(const_cast<char*>(a.c_str()));
    argv_c.push_back(nullptr);

    char path_env[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    char* env_c[] = {path_env, nullptr};

    pid_t pid;
    int rc = posix_spawn(&pid, config_.helper_path.c_str(), &actions, nullptr,
                         argv_c.data(), env_c);
    posix_spawn_file_actions_destroy(&actions);
    ::close(err_pipe[1]);

    if (rc != 0) {
        ::close(err_pipe[0]);
        stderr_out = std::string("posix_spawn: ") + std::strerror(rc);
        return -1;
    }

    char buf[1024];
    while (true) {
        ssize_t n = ::read(err_pipe[0], buf, sizeof(buf));
        if (n <= 0) break;
        stderr_out.append(buf, buf + n);
    }
    ::close(err_pipe[0]);

    int status;
    ::waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

int GrantManager::install_grant_via_helper(const Grant& g, const std::string& spec,
                                           std::string& err) const {
    std::string spec_path = config_.state_dir + "/grant_" + g.grantid + ".spec";
    try {
        atomic_write(spec_path, spec);
    } catch (const std::exception& e) {
        err = e.what();
        return -1;
    }
    int rc = spawn_helper({config_.helper_path, "install-grant", g.grantid}, err);
    if (rc != 0) {
        // Leave the .spec file behind for forensics on failure.
        return rc;
    }
    ::unlink(spec_path.c_str());
    return 0;
}

int GrantManager::revoke_grant_via_helper(const std::string& grantid,
                                          std::string& err) const {
    return spawn_helper({config_.helper_path, "revoke-grant", grantid}, err);
}

void GrantManager::log_audit(const std::string& event, const RequestContext& ctx,
                             const std::string& grantid,
                             const std::string& detail) const {
    static bool opened = false;
    if (!opened) {
        ::openlog("mcp-bridge-sudoers", LOG_PID, LOG_AUTHPRIV);
        opened = true;
    }
    ::syslog(LOG_NOTICE, "event=%s grantid=%s by=%s ip=%s %s",
             event.c_str(), grantid.c_str(),
             ctx.user_id.c_str(), ctx.client_ip.c_str(), detail.c_str());
}

Grant GrantManager::request_grant(const RequestContext& ctx,
                                  const std::string& shortid,
                                  const std::string& template_name,
                                  const json& captured_args,
                                  std::chrono::seconds ttl) {
    if (ttl.count() < 1 || ttl.count() > 86400) {
        throw std::runtime_error("grants: ttl must be between 1 and 86400 seconds");
    }

    std::string spec;
    if (template_name == kFullAdminTemplate) {
        spec = render_full_admin_spec(shortid);
    } else {
        const GrantTemplate* tmpl = nullptr;
        for (const auto& t : config_.templates) {
            if (t.name == template_name) { tmpl = &t; break; }
        }
        if (!tmpl) throw std::runtime_error("grants: unknown template '" + template_name + "'");
        spec = render_sudoers_spec(shortid, *tmpl, captured_args);
    }
    if (!spec_is_well_formed(spec)) {
        throw std::runtime_error("grants: rendered spec failed shape check");
    }

    Grant g;
    g.grantid = make_grantid();
    g.shortid = shortid;
    g.template_name = template_name;
    g.captured_args = captured_args;
    g.expires_at = now_seconds() + ttl.count();

    {
        std::lock_guard lk(mutex_);
        grants_[g.grantid] = g;
        try {
            persist_state_locked();
        } catch (...) {
            grants_.erase(g.grantid);
            throw;
        }
    }

    std::string err;
    int rc = install_grant_via_helper(g, spec, err);
    if (rc != 0) {
        std::lock_guard lk(mutex_);
        grants_.erase(g.grantid);
        try { persist_state_locked(); } catch (...) {}
        log_audit("grant_failed", ctx, g.grantid,
                  "template=" + template_name + " rc=" + std::to_string(rc) +
                  " err=" + err);
        throw std::runtime_error("grants: helper failed (rc=" + std::to_string(rc) +
                                 "): " + err);
    }

    log_audit("grant_issued", ctx, g.grantid,
              "template=" + template_name + " shortid=" + shortid +
              " ttl=" + std::to_string(ttl.count()));
    return g;
}

void GrantManager::revoke_grant(const std::string& grantid) {
    if (!valid_grantid(grantid)) {
        throw std::runtime_error("grants: invalid grantid");
    }
    std::string err;
    int rc = revoke_grant_via_helper(grantid, err);
    if (rc != 0 && rc != 0) {
        spdlog::warn("grants: helper revoke rc={} err={}", rc, err);
    }
    bool existed = false;
    {
        std::lock_guard lk(mutex_);
        existed = grants_.erase(grantid) > 0;
        if (existed) persist_state_locked();
    }
    RequestContext sys;
    sys.user_id = "daemon";
    log_audit(existed ? "grant_revoked" : "grant_revoke_orphan", sys, grantid,
              std::string("rc=") + std::to_string(rc));
}

void GrantManager::sweep_expired() {
    auto now = now_seconds();
    std::vector<std::string> to_revoke;
    {
        std::lock_guard lk(mutex_);
        for (const auto& [id, g] : grants_) {
            if (g.expires_at <= now) to_revoke.push_back(id);
        }
    }
    for (const auto& id : to_revoke) {
        try { revoke_grant(id); } catch (const std::exception& e) {
            spdlog::warn("grants: sweep revoke {} failed: {}", id, e.what());
        }
    }
}

void GrantManager::reconcile_at_startup() {
    auto on_disk = sudoers_dropins(config_.sudoers_dir);
    std::vector<std::string> to_remove_from_disk;
    std::vector<std::string> to_remove_from_state;
    auto now = now_seconds();

    {
        std::lock_guard lk(mutex_);
        // In-state grants that expired or never made it to disk get dropped.
        for (auto it = grants_.begin(); it != grants_.end();) {
            bool expired = it->second.expires_at <= now;
            bool on_disk_match = std::find(on_disk.begin(), on_disk.end(), it->first) != on_disk.end();
            if (expired || !on_disk_match) {
                to_remove_from_state.push_back(it->first);
                if (on_disk_match) to_remove_from_disk.push_back(it->first);
                it = grants_.erase(it);
            } else {
                ++it;
            }
        }

        // Drop-ins on disk with no matching state entry are orphans.
        for (const auto& id : on_disk) {
            if (grants_.find(id) == grants_.end()) {
                to_remove_from_disk.push_back(id);
            }
        }

        try { persist_state_locked(); } catch (const std::exception& e) {
            spdlog::warn("grants: reconcile persist: {}", e.what());
        }
    }

    for (const auto& id : to_remove_from_disk) {
        std::string err;
        revoke_grant_via_helper(id, err);
        RequestContext sys; sys.user_id = "daemon-reconcile";
        log_audit("grant_reconciled", sys, id, "removed orphan drop-in");
    }
    spdlog::info("grants: reconciled — {} orphan drop-in(s) removed, {} stale state entr(ies) dropped",
                 to_remove_from_disk.size(), to_remove_from_state.size());
}

void GrantManager::start_sweeper() {
    if (sweep_thread_.joinable()) return;
    sweep_thread_ = std::thread([this]() {
        std::unique_lock lk(sweep_mutex_);
        while (!stopping_) {
            if (sweep_cv_.wait_for(lk, config_.sweep_interval,
                                   [this] { return stopping_; })) break;
            lk.unlock();
            try { sweep_expired(); } catch (const std::exception& e) {
                spdlog::warn("grants: sweep error: {}", e.what());
            }
            lk.lock();
        }
    });
}

void GrantManager::stop_sweeper() {
    {
        std::lock_guard lk(sweep_mutex_);
        stopping_ = true;
    }
    sweep_cv_.notify_all();
    if (sweep_thread_.joinable()) sweep_thread_.join();
}
