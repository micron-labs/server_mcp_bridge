#pragma once
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

struct Session {
    std::string id;
    std::string bearer_hash;
    std::string user_id;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_seen;
};

class SessionStore {
public:
    explicit SessionStore(std::chrono::milliseconds idle_ttl = std::chrono::hours(1));

    Session issue(const std::string& bearer_hash, const std::string& user_id);

    // Returns the session iff it exists, has not idled out, and its
    // bearer_hash matches the one supplied. Bearer mismatch (token rotation
    // or session theft) causes the lookup to fail — the caller should respond
    // 401 and the client must re-`initialize`. Updates last_seen on success.
    std::optional<Session> validate(const std::string& session_id,
                                    const std::string& bearer_hash);

    void invalidate(const std::string& session_id);
    std::size_t size() const;

private:
    std::chrono::milliseconds idle_ttl_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_;
    std::chrono::steady_clock::time_point last_gc_;

    void gc_locked(std::chrono::steady_clock::time_point now);
};
