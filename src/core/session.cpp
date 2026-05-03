#include "core/session.hpp"
#include "core/crypto.hpp"
#include "core/shortid.hpp"

SessionStore::SessionStore(std::chrono::milliseconds idle_ttl)
    : idle_ttl_(idle_ttl), last_gc_(std::chrono::steady_clock::now()) {}

Session SessionStore::issue(const std::string& bearer_hash, const std::string& user_id) {
    Session s;
    s.id = mcp::make_uuid_v4();
    s.bearer_hash = bearer_hash;
    s.user_id = user_id;
    s.created_at = std::chrono::steady_clock::now();
    s.last_seen = s.created_at;

    std::lock_guard lk(mutex_);
    gc_locked(s.created_at);
    sessions_[s.id] = s;
    return s;
}

std::optional<Session> SessionStore::validate(const std::string& session_id,
                                              const std::string& bearer_hash) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard lk(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return std::nullopt;
    if (now - it->second.last_seen > idle_ttl_) {
        sessions_.erase(it);
        return std::nullopt;
    }
    // Constant-time compare on bearer hashes — both are 64 hex chars.
    if (!crypto::constant_time_equal(it->second.bearer_hash, bearer_hash)) {
        return std::nullopt;
    }
    it->second.last_seen = now;
    return it->second;
}

void SessionStore::invalidate(const std::string& session_id) {
    std::lock_guard lk(mutex_);
    sessions_.erase(session_id);
}

std::size_t SessionStore::size() const {
    std::lock_guard lk(mutex_);
    return sessions_.size();
}

void SessionStore::gc_locked(std::chrono::steady_clock::time_point now) {
    if (now - last_gc_ < std::chrono::minutes(5)) return;
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (now - it->second.last_seen > idle_ttl_) {
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
    last_gc_ = now;
}
