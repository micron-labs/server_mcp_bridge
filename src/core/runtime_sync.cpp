#include "core/runtime_sync.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>
#include <dirent.h>
#include <fstream>
#include <spawn.h>
#include <sys/wait.h>
#include <stdexcept>

using json = nlohmann::json;
extern char** environ;

namespace {

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

int spawn_priv_write_runtime(const std::string& helper_path,
                             const std::string& shortid,
                             const std::string& b64) {
    if (helper_path.empty()) return -1;
    if (shortid.empty()) return -1;
    if (b64.empty()) return -1;

    char* argv_c[] = {
        const_cast<char*>(helper_path.c_str()),
        const_cast<char*>("write-runtime"),
        const_cast<char*>(shortid.c_str()),
        const_cast<char*>(b64.c_str()),
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

}

namespace runtime_sync {

void write_for_user(const Config& cfg, const std::string& os_username) {
    if (os_username.empty() || os_username.find('/') != std::string::npos) {
        throw std::runtime_error("runtime_sync: invalid os_username");
    }

    json content = {
        {"webhook_url", cfg.webhook_url},
        {"webhook_secret_token", cfg.webhook_secret_token}
    };
    std::string body = content.dump(2) + "\n";
    std::string b64 = base64_encode(body);

    // Prefer the privileged helper: it writes the file as root then chown/chmod,
    // avoiding dependence on per-user directory permissions and shell tooling.
    if (!cfg.helper_path.empty()) {
        const std::string prefix = "mcp_user_";
        if (os_username.rfind(prefix, 0) == 0 && os_username.size() == prefix.size() + 8) {
            std::string shortid = os_username.substr(prefix.size());
            int rc = spawn_priv_write_runtime(cfg.helper_path, shortid, b64);
            if (rc == 0) return;
            throw std::runtime_error("runtime_sync: write for " + os_username +
                                     " failed (helper_exit=" + std::to_string(rc) + ")");
        }
    }

    // Fallback: best-effort shell pipeline as the user.
    std::string runtime_path = cfg.users_state_dir + "/" + os_username + "/runtime.json";
    std::string tmp_path     = runtime_path + ".tmp";
    std::string cmd =
        "umask 077 && printf '%s' '" + b64 + "' | base64 -d > '" + tmp_path + "' && "
        "chmod 600 '" + tmp_path + "' && "
        "mv '" + tmp_path + "' '" + runtime_path + "'";

    auto result = run_process_as(os_username, cmd, "", 30, {});
    if (result.exit_code != 0) {
        throw std::runtime_error("runtime_sync: write for " + os_username +
                                 " exit=" + std::to_string(result.exit_code) +
                                 " stderr=" + result.stderr_str);
    }
}

void write_all(const Config& cfg) {
    DIR* d = ::opendir(cfg.users_dir.c_str());
    if (!d) {
        spdlog::warn("runtime_sync: cannot open users_dir {}", cfg.users_dir);
        return;
    }
    int ok = 0, failed = 0;
    while (auto* e = ::readdir(d)) {
        std::string name = e->d_name;
        if (name.size() < 6 || name.substr(name.size() - 5) != ".json") continue;

        std::string path = cfg.users_dir + "/" + name;
        std::ifstream f(path);
        if (!f.is_open()) continue;
        json doc;
        try { f >> doc; } catch (...) { continue; }
        if (!doc.is_object()) continue;

        std::string os_user = doc.value("os_username", "");
        if (os_user.empty()) continue;

        try {
            write_for_user(cfg, os_user);
            ok++;
        } catch (const std::exception& ex) {
            failed++;
            spdlog::warn("runtime_sync: {} failed: {}", os_user, ex.what());
        }
    }
    ::closedir(d);
    spdlog::info("runtime_sync: rewrote {} runtime.json file(s); {} failure(s)", ok, failed);
}

}
