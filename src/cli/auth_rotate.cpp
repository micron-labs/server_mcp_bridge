#include "cli/welcome_banner.hpp"
#include "core/config.hpp"
#include "core/crypto.hpp"
#include "core/shortid.hpp"
#include <json.hpp>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>

using json = nlohmann::json;

namespace {

void try_sighup_daemon(const std::string& state_dir) {
    std::ifstream f(state_dir + "/daemon.pid");
    if (!f.is_open()) return;
    int pid = 0; f >> pid;
    if (pid > 1) ::kill(pid, SIGHUP);
}

void atomic_replace(const std::string& path, const std::string& data) {
    std::string tmp = path + ".tmp." + std::to_string(::getpid());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) throw std::runtime_error("open tmp");
    std::size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); ::unlink(tmp.c_str()); throw std::runtime_error("write"); }
        off += n;
    }
    ::fsync(fd); ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw std::runtime_error("rename");
    }
}

}

int cli_auth_rotate(int argc, char** argv) {
    std::string config_path = "/etc/mcp_bridge/mcp.json";
    bool non_interactive = false;
    std::string shortid;

    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--config" && i + 1 < argc) config_path = argv[++i];
        else if (a == "--non-interactive")        non_interactive = true;
        else if (shortid.empty())                 shortid = a;
        else { std::fprintf(stderr, "unexpected arg: %s\n", a.c_str()); return 2; }
    }
    if (shortid.empty() || !mcp::valid_shortid(shortid)) {
        std::fprintf(stderr, "usage: mcp_bridge auth rotate <shortid> [--non-interactive]\n");
        return 2;
    }

    Config cfg;
    try { cfg = load_config(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }

    std::string user_path = cfg.users_dir + "/" + shortid + ".json";
    std::ifstream in(user_path);
    if (!in.is_open()) {
        std::fprintf(stderr, "ERROR: no user record at %s\n", user_path.c_str());
        return 1;
    }
    json doc;
    try { in >> doc; } catch (...) {
        std::fprintf(stderr, "ERROR: malformed user record\n"); return 1;
    }
    in.close();

    auto token = mcp::make_token();
    auto hash  = crypto::sha256_salted_hex(cfg.global_token_salt, token);
    doc["token_hash"] = hash;
    doc["rotated_at"] = static_cast<int64_t>(std::time(nullptr));

    try { atomic_replace(user_path, doc.dump(2) + "\n"); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: rewrite: %s\n", e.what()); return 1;
    }

    try_sighup_daemon(cfg.state_dir);

    bool is_admin = doc.value("is_admin", false);
    int fallback = non_interactive ? STDOUT_FILENO : -1;
    mcp::print_connection_block(shortid, token, is_admin, fallback);
    return 0;
}
