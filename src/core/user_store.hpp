#pragma once
#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

struct UserRecord {
    std::string user_id;
    std::string os_username;
    std::string name;
    std::string email;
    bool is_admin = false;
    std::string token_hash;
    int64_t created_at = 0;
};

class UserStore {
public:
    UserStore(std::string users_dir, std::string global_salt_hex);

    void load_all();
    void reload();

    std::optional<UserRecord> lookup_by_token(const std::string& bearer_token) const;
    std::optional<UserRecord> lookup_by_hash(const std::string& token_hash) const;

    std::size_t size() const;

private:
    std::string users_dir_;
    std::string global_salt_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, UserRecord> by_hash_;
};
