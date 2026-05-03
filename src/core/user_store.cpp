#include "core/user_store.hpp"
#include "core/crypto.hpp"
#include <json.hpp>
#include <spdlog/spdlog.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fstream>
#include <utility>

using json = nlohmann::json;

namespace {

bool ends_with_json(const std::string& name) {
    return name.size() > 5 && name.compare(name.size() - 5, 5, ".json") == 0;
}

std::optional<UserRecord> read_user_file(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return std::nullopt;

    json doc;
    try {
        f >> doc;
    } catch (const json::parse_error& e) {
        spdlog::warn("user_store: skipping {} (parse error: {})", path, e.what());
        return std::nullopt;
    }
    if (!doc.is_object()) {
        spdlog::warn("user_store: skipping {} (not an object)", path);
        return std::nullopt;
    }

    UserRecord r;
    try {
        r.user_id = doc.at("user_id").get<std::string>();
        r.os_username = doc.value("os_username", "");
        r.name = doc.value("name", "");
        r.email = doc.value("email", "");
        r.is_admin = doc.value("is_admin", false);
        r.token_hash = doc.at("token_hash").get<std::string>();
        r.created_at = doc.value("created_at", int64_t{0});
    } catch (const std::exception& e) {
        spdlog::warn("user_store: skipping {} ({})", path, e.what());
        return std::nullopt;
    }
    if (r.user_id.empty() || r.token_hash.empty()) return std::nullopt;
    return r;
}

}

UserStore::UserStore(std::string users_dir, std::string global_salt_hex)
    : users_dir_(std::move(users_dir)), global_salt_(std::move(global_salt_hex)) {}

void UserStore::load_all() {
    std::unordered_map<std::string, UserRecord> next;

    DIR* dir = opendir(users_dir_.c_str());
    if (!dir) {
        spdlog::info("user_store: users_dir {} not present, no users loaded", users_dir_);
        std::unique_lock lock(mutex_);
        by_hash_.swap(next);
        return;
    }

    while (auto* entry = readdir(dir)) {
        if (entry->d_name[0] == '.') continue;
        if (!ends_with_json(entry->d_name)) continue;
        std::string path = users_dir_ + "/" + entry->d_name;

        struct stat st;
        if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;

        auto rec = read_user_file(path);
        if (!rec) continue;
        next.emplace(rec->token_hash, std::move(*rec));
    }
    closedir(dir);

    std::unique_lock lock(mutex_);
    by_hash_.swap(next);
    spdlog::info("user_store: loaded {} user(s) from {}", by_hash_.size(), users_dir_);
}

void UserStore::reload() {
    load_all();
}

std::optional<UserRecord> UserStore::lookup_by_token(const std::string& bearer_token) const {
    auto hash = crypto::sha256_salted_hex(global_salt_, bearer_token);
    return lookup_by_hash(hash);
}

std::optional<UserRecord> UserStore::lookup_by_hash(const std::string& token_hash) const {
    std::shared_lock lock(mutex_);
    auto it = by_hash_.find(token_hash);
    if (it == by_hash_.end()) return std::nullopt;
    return it->second;
}

std::size_t UserStore::size() const {
    std::shared_lock lock(mutex_);
    return by_hash_.size();
}
