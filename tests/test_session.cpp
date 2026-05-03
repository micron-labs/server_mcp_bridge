#include "test_framework.hpp"
#include "core/session.hpp"
#include <chrono>
#include <thread>

TEST(issue_then_validate_with_same_bearer) {
    SessionStore s;
    auto sess = s.issue("hash_a", "user_1");
    ASSERT_EQ(sess.user_id, std::string("user_1"));
    ASSERT_EQ(sess.bearer_hash, std::string("hash_a"));
    ASSERT_EQ(sess.id.size(), std::size_t{36});
    auto v = s.validate(sess.id, "hash_a");
    ASSERT(v.has_value());
    ASSERT_EQ(v->user_id, std::string("user_1"));
}

TEST(validate_rejects_different_bearer) {
    SessionStore s;
    auto sess = s.issue("hash_a", "user_1");
    auto v = s.validate(sess.id, "hash_b");
    ASSERT(!v.has_value());
}

TEST(validate_rejects_unknown_session) {
    SessionStore s;
    auto v = s.validate("00000000-0000-4000-8000-000000000000", "anything");
    ASSERT(!v.has_value());
}

TEST(invalidate_drops_session) {
    SessionStore s;
    auto sess = s.issue("h", "u");
    ASSERT_EQ(s.size(), std::size_t{1});
    s.invalidate(sess.id);
    ASSERT_EQ(s.size(), std::size_t{0});
    ASSERT(!s.validate(sess.id, "h").has_value());
}

TEST(idle_expiry_via_short_ttl) {
    SessionStore s(std::chrono::milliseconds(50));
    auto sess = s.issue("h", "u");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ASSERT(!s.validate(sess.id, "h").has_value());
}

TEST(validate_extends_last_seen) {
    SessionStore s(std::chrono::milliseconds(150));
    auto sess = s.issue("h", "u");
    std::this_thread::sleep_for(std::chrono::milliseconds(75));
    auto first = s.validate(sess.id, "h");
    ASSERT(first.has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(75));
    // 150ms total elapsed since issue, but only 75ms since last validate ⇒ still alive.
    auto second = s.validate(sess.id, "h");
    ASSERT(second.has_value());
}

TEST(bearer_rotation_invalidates_existing_sessions) {
    // The "no session reuse across tokens" rule. Phase 4 `auth rotate` changes
    // the token hash; any session bound to the old hash must fail next request.
    SessionStore s;
    auto sess = s.issue("old_hash", "user_1");
    auto v_new = s.validate(sess.id, "new_hash");
    ASSERT(!v_new.has_value());
    // The session is still in the store — only this lookup fails.
    auto v_old = s.validate(sess.id, "old_hash");
    ASSERT(v_old.has_value());
}

TEST_MAIN
