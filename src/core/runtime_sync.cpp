#include "core/runtime_sync.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>
#include <dirent.h>
#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

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

    std::string runtime_path = cfg.users_state_dir + "/" + os_username + "/runtime.json";
    std::string tmp_path     = runtime_path + ".tmp";

    // base64 chars are shell-safe inside single-quotes; the only thing that
    // could surprise us is the `=` padding which is also single-quote-safe.
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
