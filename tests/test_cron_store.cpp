#include "test_framework.hpp"
#include "core/cron_store.hpp"
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace {

std::string make_tmp_dir() {
    char tmpl[] = "/tmp/mcp_bridge_cron_test_XXXXXX";
    char* d = ::mkdtemp(tmpl);
    if (!d) throw std::runtime_error("mkdtemp failed");
    return d;
}

void rm_rf(const std::string& dir) {
    std::string cmd = "rm -rf '" + dir + "'";
    (void)std::system(cmd.c_str());
}

constexpr const char* kAlice    = "abcdefgh";
constexpr const char* kAliceOs  = "mcp_user_abcdefgh";
constexpr const char* kBob      = "ijklmnop";
constexpr const char* kBobOs    = "mcp_user_ijklmnop";

}

TEST(valid_schedule_accepts_common_forms) {
    ASSERT(CronStore::valid_schedule("* * * * *"));
    ASSERT(CronStore::valid_schedule("*/5 * * * *"));
    ASSERT(CronStore::valid_schedule("0 0 * * 0"));
    ASSERT(CronStore::valid_schedule("0-23/2 * * * *"));
    ASSERT(CronStore::valid_schedule("1,3,5 0 * * *"));
}

TEST(valid_schedule_rejects_injection_and_wrong_arity) {
    ASSERT(!CronStore::valid_schedule(""));
    ASSERT(!CronStore::valid_schedule("* * * *"));            // 4 fields
    ASSERT(!CronStore::valid_schedule("* * * * * *"));        // 6 fields
    ASSERT(!CronStore::valid_schedule("*/5 * * * * ; rm -rf /"));
    ASSERT(!CronStore::valid_schedule("*/5 * * * * `id`"));
    ASSERT(!CronStore::valid_schedule("*/5 * * * * $(id)"));
    ASSERT(!CronStore::valid_schedule("*/5 * * * * |cat"));
}

TEST(add_returns_job_with_unique_id_and_persists) {
    auto dir = make_tmp_dir();
    {
        CronStore store(dir);
        store.load();
        auto a = store.add(kAlice, kAliceOs, "*/5 * * * *",
                           "echo hello", "first job", "ctx-1");
        ASSERT_EQ(a.user_id, std::string(kAlice));
        ASSERT_EQ(a.os_username, std::string(kAliceOs));
        ASSERT_EQ(a.schedule, std::string("*/5 * * * *"));
        ASSERT_EQ(a.command, std::string("echo hello"));
        ASSERT_EQ(a.description, std::string("first job"));
        ASSERT_EQ(a.context_id, std::string("ctx-1"));
        ASSERT(CronStore::valid_jobid(a.job_id));

        auto b = store.add(kAlice, kAliceOs, "0 0 * * *", "echo bye", "", "");
        ASSERT(a.job_id != b.job_id);
        ASSERT_EQ(store.size(), std::size_t{2});
    }
    // Reopen the store and confirm both jobs were persisted to disk.
    {
        CronStore store(dir);
        store.load();
        ASSERT_EQ(store.size(), std::size_t{2});
        auto jobs = store.list_for_user(kAliceOs);
        ASSERT_EQ(jobs.size(), std::size_t{2});
    }
    rm_rf(dir);
}

TEST(list_for_user_isolates_owners) {
    auto dir = make_tmp_dir();
    CronStore store(dir);
    store.load();
    store.add(kAlice, kAliceOs, "* * * * *", "alice-1", "", "");
    store.add(kAlice, kAliceOs, "* * * * *", "alice-2", "", "");
    store.add(kBob,   kBobOs,   "* * * * *", "bob-1",   "", "");
    ASSERT_EQ(store.list_for_user(kAliceOs).size(), std::size_t{2});
    ASSERT_EQ(store.list_for_user(kBobOs).size(),   std::size_t{1});
    ASSERT_EQ(store.list_for_user("mcp_user_unknown").size(), std::size_t{0});
    rm_rf(dir);
}

TEST(update_rejects_other_users_jobs) {
    auto dir = make_tmp_dir();
    CronStore store(dir);
    store.load();
    auto a = store.add(kAlice, kAliceOs, "* * * * *", "alice", "", "");
    ASSERT_THROWS(store.update(a.job_id, kBobOs,
                               std::string("0 0 * * *"),
                               std::nullopt, std::nullopt, std::nullopt));
    // After a failed update Alice's job is unchanged.
    auto found = store.find(a.job_id);
    ASSERT(found.has_value());
    ASSERT_EQ(found->schedule, std::string("* * * * *"));
    rm_rf(dir);
}

TEST(remove_rejects_other_users_jobs) {
    auto dir = make_tmp_dir();
    CronStore store(dir);
    store.load();
    auto a = store.add(kAlice, kAliceOs, "* * * * *", "alice", "", "");
    ASSERT_THROWS(store.remove(a.job_id, kBobOs));
    ASSERT(store.find(a.job_id).has_value());
    // Alice can remove her own job.
    auto removed = store.remove(a.job_id, kAliceOs);
    ASSERT_EQ(removed.job_id, a.job_id);
    ASSERT(!store.find(a.job_id).has_value());
    rm_rf(dir);
}

TEST(update_mutates_only_supplied_fields) {
    auto dir = make_tmp_dir();
    CronStore store(dir);
    store.load();
    auto j = store.add(kAlice, kAliceOs, "* * * * *", "echo hi", "first", "ctx");
    auto u = store.update(j.job_id, kAliceOs,
                          std::string("0 * * * *"),  // schedule changes
                          std::nullopt,              // command unchanged
                          std::string("renamed"),    // description changes
                          std::nullopt);             // context_id unchanged
    ASSERT_EQ(u.schedule, std::string("0 * * * *"));
    ASSERT_EQ(u.command, std::string("echo hi"));
    ASSERT_EQ(u.description, std::string("renamed"));
    ASSERT_EQ(u.context_id, std::string("ctx"));
    ASSERT(u.updated_at >= j.created_at);
    rm_rf(dir);
}

TEST(add_rejects_invalid_schedule_and_empty_command) {
    auto dir = make_tmp_dir();
    CronStore store(dir);
    store.load();
    ASSERT_THROWS(store.add(kAlice, kAliceOs, "garbage", "echo", "", ""));
    ASSERT_THROWS(store.add(kAlice, kAliceOs, "* * * * *", "", "", ""));
    ASSERT_EQ(store.size(), std::size_t{0});
    rm_rf(dir);
}

TEST_MAIN
