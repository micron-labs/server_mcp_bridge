#include "core/config.hpp"
#include <json.hpp>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using json = nlohmann::json;

namespace {

void atomic_replace(const std::string& path, const std::string& data) {
    std::string tmp = path + ".tmp." + std::to_string(::getpid());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        throw std::runtime_error(std::string("open ") + tmp + ": " + std::strerror(errno));
    }
    std::size_t off = 0;
    while (off < data.size()) {
        ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) { ::close(fd); ::unlink(tmp.c_str()); throw std::runtime_error("write"); }
        off += n;
    }
    ::fsync(fd);
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        throw std::runtime_error(std::string("rename: ") + std::strerror(errno));
    }
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

json read_config_doc(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error(std::string("cannot open ") + path);
    }
    std::stringstream ss; ss << f.rdbuf();
    json doc = json::parse(ss.str());
    if (!doc.is_object()) {
        throw std::runtime_error("config root is not a JSON object");
    }
    return doc;
}

int do_set(int argc, char** argv) {
    std::string config_path = "/etc/mcp_bridge/mcp.json";
    std::string url;
    std::string secret;
    bool secret_provided = false;
    bool url_provided = false;

    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--config" && i + 1 < argc) config_path = argv[++i];
        else if (a == "--url"    && i + 1 < argc) { url = argv[++i]; url_provided = true; }
        else if (a == "--secret" && i + 1 < argc) { secret = argv[++i]; secret_provided = true; }
        else { std::fprintf(stderr, "unknown flag: %s\n", a.c_str()); return 2; }
    }
    if (!url_provided) {
        std::fprintf(stderr, "ERROR: --url is required\n");
        return 2;
    }

    Config cfg;
    try { cfg = load_config(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }

    json doc;
    try { doc = read_config_doc(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }
    if (!doc.contains("webhook") || !doc["webhook"].is_object()) {
        doc["webhook"] = json::object();
    }
    doc["webhook"]["url"] = url;
    if (secret_provided) {
        doc["webhook"]["secret_token"] = secret;
    } else if (!doc["webhook"].contains("secret_token")) {
        doc["webhook"]["secret_token"] = "";
    }

    try { atomic_replace(config_path, doc.dump(2) + "\n"); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: write %s: %s\n", config_path.c_str(), e.what());
        return 1;
    }

    try_sighup_daemon(cfg.state_dir);
    std::fprintf(stderr, "webhook set: url=%s secret=%s\n",
                 url.c_str(),
                 (secret_provided && !secret.empty()) ? "(set)" : "(unchanged)");
    return 0;
}

int do_show(int argc, char** argv) {
    std::string config_path = "/etc/mcp_bridge/mcp.json";
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) config_path = argv[++i];
        else { std::fprintf(stderr, "unknown flag: %s\n", a.c_str()); return 2; }
    }
    Config cfg;
    try { cfg = load_config(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }
    std::printf("webhook.url:          %s\n",
                cfg.webhook_url.empty() ? "(unset)" : cfg.webhook_url.c_str());
    std::printf("webhook.secret_token: %s\n",
                cfg.webhook_secret_token.empty() ? "(unset)" : "(set)");
    return 0;
}

int do_clear(int argc, char** argv) {
    std::string config_path = "/etc/mcp_bridge/mcp.json";
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) config_path = argv[++i];
        else { std::fprintf(stderr, "unknown flag: %s\n", a.c_str()); return 2; }
    }

    Config cfg;
    try { cfg = load_config(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }
    json doc;
    try { doc = read_config_doc(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }
    doc["webhook"] = { {"url", ""}, {"secret_token", ""} };
    try { atomic_replace(config_path, doc.dump(2) + "\n"); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: write %s: %s\n", config_path.c_str(), e.what());
        return 1;
    }
    try_sighup_daemon(cfg.state_dir);
    std::fprintf(stderr, "webhook cleared\n");
    return 0;
}

}

int cli_webhook(int argc, char** argv) {
    // argv[0]=set|show|clear, argv[1...]=opts
    if (argc < 1) {
        std::fputs(
            "Usage:\n"
            "  mcp_bridge webhook set   --url <url> [--secret <token>] [--config <path>]\n"
            "  mcp_bridge webhook show  [--config <path>]\n"
            "  mcp_bridge webhook clear [--config <path>]\n",
            stderr);
        return 2;
    }
    std::string sub = argv[0];
    if (sub == "set")   return do_set  (argc - 1, argv + 1);
    if (sub == "show")  return do_show (argc - 1, argv + 1);
    if (sub == "clear") return do_clear(argc - 1, argv + 1);
    std::fprintf(stderr, "unknown webhook subcommand: %s\n", sub.c_str());
    return 2;
}
