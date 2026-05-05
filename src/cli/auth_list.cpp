#include "core/config.hpp"
#include <json.hpp>
#include <dirent.h>
#include <sys/stat.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

using json = nlohmann::json;

namespace {

struct Row {
    std::string user_id;
    std::string os_username;
    std::string name;
    std::string email;
    bool is_admin = false;
    int64_t created_at = 0;
    int64_t rotated_at = 0;
};

bool ends_with_json(const std::string& s) {
    return s.size() > 5 && s.compare(s.size() - 5, 5, ".json") == 0;
}

std::string fmt_time(int64_t epoch) {
    if (epoch <= 0) return "-";
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
    if (!localtime_r(&t, &tm)) return "-";
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", &tm);
    return buf;
}

void pad(std::string& s, std::size_t w) {
    if (s.size() < w) s.append(w - s.size(), ' ');
}

}

int cli_auth_list(int argc, char** argv) {
    std::string config_path = "/etc/mcp_bridge/mcp.json";
    bool show_json = false;

    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--config" && i + 1 < argc) config_path = argv[++i];
        else if (a == "--json")                   show_json = true;
        else { std::fprintf(stderr, "unknown flag: %s\n", a.c_str()); return 2; }
    }

    Config cfg;
    try { cfg = load_config(config_path); }
    catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what()); return 1;
    }

    std::vector<Row> rows;

    DIR* dir = opendir(cfg.users_dir.c_str());
    if (!dir) {
        std::fprintf(stderr, "ERROR: cannot open users dir %s: %s\n",
                     cfg.users_dir.c_str(), std::strerror(errno));
        return 1;
    }
    while (auto* entry = readdir(dir)) {
        if (entry->d_name[0] == '.') continue;
        if (!ends_with_json(entry->d_name)) continue;
        std::string path = cfg.users_dir + "/" + entry->d_name;
        struct stat st;
        if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;

        std::ifstream f(path);
        if (!f.is_open()) continue;
        json doc;
        try { f >> doc; } catch (...) {
            std::fprintf(stderr, "WARNING: skipping malformed %s\n", path.c_str());
            continue;
        }
        if (!doc.is_object()) continue;

        Row r;
        r.user_id     = doc.value("user_id", "");
        r.os_username = doc.value("os_username", "");
        r.name        = doc.value("name", "");
        r.email       = doc.value("email", "");
        r.is_admin    = doc.value("is_admin", false);
        r.created_at  = doc.value("created_at", int64_t{0});
        r.rotated_at  = doc.value("rotated_at", int64_t{0});
        if (r.user_id.empty()) continue;
        rows.push_back(std::move(r));
    }
    closedir(dir);

    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        return a.created_at < b.created_at;
    });

    if (show_json) {
        json arr = json::array();
        for (const auto& r : rows) {
            arr.push_back({
                {"user_id", r.user_id},
                {"os_username", r.os_username},
                {"name", r.name},
                {"email", r.email},
                {"is_admin", r.is_admin},
                {"created_at", r.created_at},
                {"rotated_at", r.rotated_at},
            });
        }
        std::fputs(arr.dump(2).c_str(), stdout);
        std::fputc('\n', stdout);
        return 0;
    }

    if (rows.empty()) {
        std::fprintf(stderr, "no users in %s\n", cfg.users_dir.c_str());
        return 0;
    }

    struct Cell { std::string id, os, name, email, admin, created, rotated; };
    std::vector<Cell> cells;
    cells.reserve(rows.size());
    Cell hdr{"USER_ID", "OS_USERNAME", "NAME", "EMAIL", "ADMIN", "CREATED", "ROTATED"};
    std::size_t w_id=hdr.id.size(), w_os=hdr.os.size(), w_name=hdr.name.size(),
                w_email=hdr.email.size(), w_admin=hdr.admin.size(),
                w_created=hdr.created.size(), w_rotated=hdr.rotated.size();
    for (const auto& r : rows) {
        Cell c;
        c.id = r.user_id;
        c.os = r.os_username;
        c.name = r.name;
        c.email = r.email;
        c.admin = r.is_admin ? "yes" : "no";
        c.created = fmt_time(r.created_at);
        c.rotated = fmt_time(r.rotated_at);
        w_id      = std::max(w_id, c.id.size());
        w_os      = std::max(w_os, c.os.size());
        w_name    = std::max(w_name, c.name.size());
        w_email   = std::max(w_email, c.email.size());
        w_admin   = std::max(w_admin, c.admin.size());
        w_created = std::max(w_created, c.created.size());
        w_rotated = std::max(w_rotated, c.rotated.size());
        cells.push_back(std::move(c));
    }

    auto print_row = [&](Cell c) {
        pad(c.id, w_id);
        pad(c.os, w_os);
        pad(c.name, w_name);
        pad(c.email, w_email);
        pad(c.admin, w_admin);
        pad(c.created, w_created);
        std::fprintf(stdout, "%s  %s  %s  %s  %s  %s  %s\n",
                     c.id.c_str(), c.os.c_str(), c.name.c_str(),
                     c.email.c_str(), c.admin.c_str(),
                     c.created.c_str(), c.rotated.c_str());
    };

    print_row(hdr);
    for (auto& c : cells) print_row(c);
    std::fprintf(stdout, "\n%zu user(s)\n", rows.size());
    return 0;
}
