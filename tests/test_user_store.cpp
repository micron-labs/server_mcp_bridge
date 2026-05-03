#include "test_framework.hpp"
#include "core/user_store.hpp"
#include "core/crypto.hpp"
#include <json.hpp>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

using json = nlohmann::json;

namespace {

std::string make_tmp_dir() {
    char tmpl[] = "/tmp/mcp_bridge_test_XXXXXX";
    char* d = ::mkdtemp(tmpl);
    if (!d) throw std::runtime_error("mkdtemp failed");
    return d;
}

void rm_rf(const std::string& dir) {
    std::string cmd = "rm -rf '" + dir + "'";
    (void)std::system(cmd.c_str());
}

void write_file(const std::string& path, const std::string& body) {
    std::ofstream f(path);
    f << body;
}

}

TEST(load_all_on_missing_dir_is_empty_and_safe) {
    UserStore us("/tmp/__mcp_bridge_does_not_exist__", "salt");
    us.load_all();
    ASSERT_EQ(us.size(), std::size_t{0});
}

TEST(load_one_user_and_lookup_by_token) {
    auto dir = make_tmp_dir();
    std::string salt = "deadbeefcafebabe";
    std::string token = "raw_token_value";
    std::string hash = crypto::sha256_salted_hex(salt, token);

    json rec = {
        {"user_id","abc23456"},
        {"os_username","mcp_user_abc23456"},
        {"name","Bob"},
        {"email","bob@example.com"},
        {"is_admin",false},
        {"token_hash", hash},
        {"created_at", 1746268800}
    };
    write_file(dir + "/abc23456.json", rec.dump());

    UserStore us(dir, salt);
    us.load_all();
    ASSERT_EQ(us.size(), std::size_t{1});

    auto found = us.lookup_by_token(token);
    ASSERT(found.has_value());
    ASSERT_EQ(found->user_id, std::string("abc23456"));
    ASSERT_EQ(found->os_username, std::string("mcp_user_abc23456"));
    ASSERT_EQ(found->is_admin, false);

    auto not_found = us.lookup_by_token("wrong");
    ASSERT(!not_found.has_value());

    rm_rf(dir);
}

TEST(reload_picks_up_newly_added_user) {
    auto dir = make_tmp_dir();
    std::string salt = "salty";
    UserStore us(dir, salt);
    us.load_all();
    ASSERT_EQ(us.size(), std::size_t{0});

    std::string token = "tok";
    std::string hash = crypto::sha256_salted_hex(salt, token);
    json rec = {
        {"user_id","234567ab"},
        {"os_username","mcp_user_234567ab"},
        {"name","Alice"}, {"email","alice@example.com"},
        {"is_admin", true}, {"token_hash", hash}, {"created_at", 0}
    };
    write_file(dir + "/234567ab.json", rec.dump());

    us.reload();
    ASSERT_EQ(us.size(), std::size_t{1});
    auto u = us.lookup_by_token(token);
    ASSERT(u.has_value());
    ASSERT(u->is_admin);

    rm_rf(dir);
}

TEST(skips_malformed_user_files) {
    auto dir = make_tmp_dir();
    write_file(dir + "/bad.json", "this is not json");
    write_file(dir + "/empty.json", "{}");                     // missing required fields
    write_file(dir + "/nottracked.txt", "ignored");             // non-.json

    std::string salt = "x";
    std::string tok  = "valid_tok";
    std::string hash = crypto::sha256_salted_hex(salt, tok);
    json good = {
        {"user_id","aaaa2222"}, {"token_hash", hash},
        {"is_admin",false}, {"created_at", 0}
    };
    write_file(dir + "/aaaa2222.json", good.dump());

    UserStore us(dir, salt);
    us.load_all();
    ASSERT_EQ(us.size(), std::size_t{1});
    ASSERT(us.lookup_by_token(tok).has_value());

    rm_rf(dir);
}

TEST(reload_drops_removed_users) {
    auto dir = make_tmp_dir();
    std::string salt = "s", token = "t";
    std::string hash = crypto::sha256_salted_hex(salt, token);
    json rec = {{"user_id","abcdefgh"},{"token_hash",hash},
                {"is_admin",false},{"created_at",0}};
    write_file(dir + "/abcdefgh.json", rec.dump());

    UserStore us(dir, salt);
    us.load_all();
    ASSERT_EQ(us.size(), std::size_t{1});

    std::remove((dir + "/abcdefgh.json").c_str());
    us.reload();
    ASSERT_EQ(us.size(), std::size_t{0});
    ASSERT(!us.lookup_by_token(token).has_value());

    rm_rf(dir);
}

TEST_MAIN
