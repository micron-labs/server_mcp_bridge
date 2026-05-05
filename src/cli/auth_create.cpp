#include "cli/welcome_banner.hpp"
#include "core/config.hpp"
#include "core/crypto.hpp"
#include "core/runtime_sync.hpp"
#include "core/shortid.hpp"
#include <json.hpp>
#include <spawn.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>

extern char** environ;

using json = nlohmann::json;

namespace {

bool is_email_ish(const std::string& s) {
    static const std::regex re(R"(^[^\s@]+@[^\s@]+\.[^\s@]+$)");
    return std::regex_match(s, re);
}

std::string prompt_line(const std::string& label) {
    std::string s;
    std::cerr << label << ": ";
    if (!std::getline(std::cin, s)) return "";
    return s;
}

int spawn_helper(const std::string& helper_path, const std::string& sub,
                 const std::string& shortid) {
    char* argv_c[] = {
        const_cast<char*>(helper_path.c_str()),
        const_cast<char*>(sub.c_str()),
        const_cast<char*>(shortid.c_str()),
        nullptr
    };
    char path_env[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    char* env_c[] = {path_env, nullptr};

    pid_t pid;
    int rc = posix_spawn(&pid, helper_path.c_str(), nullptr, nullptr, argv_c, env_c);
    if (rc != 0) return -1;
    int st;
    if (::waitpid(pid, &st, 0) < 0) return -1;
    if (!WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

void try_sighup_daemon(const std::string& state_dir) {
    std::string pidfile = state_dir + "/daemon.pid";
    std::ifstream f(pidfile);
    if (!f.is_open()) return;
    int pid = 0;
    f >> pid;
    if (pid <= 1) return;
    ::kill(pid, SIGHUP);
}

void atomic_write_excl(const std::string& path, const std::string& data) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        throw std::runtime_error(std::string("open ") + path + ": " + std::strerror(errno));
    }
    std::size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); ::unlink(path.c_str()); throw std::runtime_error("write"); }
        off += n;
    }
    ::fsync(fd);
    ::close(fd);
}

}

int cli_auth_create(int argc, char** argv) {
    std::string config_path = "/etc/mcp_bridge/mcp.json";
    std::string name, email;
    bool is_admin = false;
    bool non_interactive = false;

    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--config" && i + 1 < argc) config_path = argv[++i];
        else if (a == "--name"   && i + 1 < argc) name        = argv[++i];
        else if (a == "--email"  && i + 1 < argc) email       = argv[++i];
        else if (a == "--admin")                  is_admin    = true;
        else if (a == "--non-interactive")        non_interactive = true;
        else { std::fprintf(stderr, "unknown flag: %s\n", a.c_str()); return 2; }
    }

    Config cfg;
    try { cfg = load_config(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }
    if (cfg.global_token_salt.empty()) {
        std::fprintf(stderr, "ERROR: %s has no auth.global_token_salt\n", config_path.c_str());
        return 1;
    }

    if (name.empty()) {
        if (non_interactive) { std::fprintf(stderr, "--name required in non-interactive mode\n"); return 2; }
        name = prompt_line("Name");
    }
    if (email.empty()) {
        if (non_interactive) { std::fprintf(stderr, "--email required in non-interactive mode\n"); return 2; }
        email = prompt_line("Email");
    }
    if (name.empty() || !is_email_ish(email)) {
        std::fprintf(stderr, "ERROR: name and a well-formed email are required\n");
        return 2;
    }

    auto shortid = mcp::make_shortid();
    auto token   = mcp::make_token();
    auto hash    = crypto::sha256_salted_hex(cfg.global_token_salt, token);

    json record = {
        {"user_id", shortid},
        {"os_username", "mcp_user_" + shortid},
        {"name", name},
        {"email", email},
        {"is_admin", is_admin},
        {"token_hash", hash},
        {"created_at", static_cast<int64_t>(std::time(nullptr))}
    };

    std::string user_path = cfg.users_dir + "/" + shortid + ".json";
    try {
        atomic_write_excl(user_path, record.dump(2) + "\n");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: write %s: %s\n", user_path.c_str(), e.what());
        return 1;
    }

    int rc = spawn_helper(cfg.helper_path, "useradd", shortid);
    if (rc != 0 && rc != 14) {  // 14 = user already exists (idempotent)
        std::fprintf(stderr,
                     "WARNING: helper useradd returned %d; user record was written but the OS "
                     "account mcp_user_%s may not exist. Re-run as root or fix the helper at %s\n",
                     rc, shortid.c_str(), cfg.helper_path.c_str());
    } else {
        int st_rc = spawn_helper(cfg.helper_path, "prepare-user-state", shortid);
        if (st_rc != 0) {
            std::fprintf(stderr,
                         "WARNING: helper prepare-user-state returned %d; per-user state dir "
                         "may not be in place for mcp_user_%s\n", st_rc, shortid.c_str());
        } else {
            try {
                runtime_sync::write_for_user(cfg, "mcp_user_" + shortid);
            } catch (const std::exception& e) {
                std::fprintf(stderr,
                             "WARNING: could not seed runtime.json for mcp_user_%s: %s\n",
                             shortid.c_str(), e.what());
            }
        }
    }

    try_sighup_daemon(cfg.state_dir);

    int fallback = non_interactive ? STDOUT_FILENO : -1;
    mcp::print_connection_block(shortid, token, is_admin, fallback);
    return 0;
}
