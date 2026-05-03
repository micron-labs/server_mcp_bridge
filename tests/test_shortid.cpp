#include "test_framework.hpp"
#include "core/shortid.hpp"
#include <set>

TEST(shortid_length_and_charset) {
    for (int i = 0; i < 200; ++i) {
        auto s = mcp::make_shortid();
        ASSERT_EQ(s.size(), std::size_t{8});
        ASSERT(mcp::valid_shortid(s));
    }
}

TEST(shortid_distinct_in_200) {
    std::set<std::string> seen;
    for (int i = 0; i < 200; ++i) seen.insert(mcp::make_shortid());
    // 40 bits of entropy, 200 draws — collision is astronomically unlikely.
    ASSERT(seen.size() >= 195);
}

TEST(valid_shortid_rejects_bad_inputs) {
    ASSERT(!mcp::valid_shortid(""));
    ASSERT(!mcp::valid_shortid("abc"));         // too short
    ASSERT(!mcp::valid_shortid("abcdefghi"));   // too long
    ASSERT(!mcp::valid_shortid("abc12def"));    // '1' not in [a-z2-7]
    ASSERT(!mcp::valid_shortid("ABCDEFGH"));    // uppercase
    ASSERT(!mcp::valid_shortid("abc89def"));    // '8','9' out of range
    ASSERT(!mcp::valid_shortid("abc-defg"));    // hyphen
    ASSERT(mcp::valid_shortid("abcdefgh"));
    ASSERT(mcp::valid_shortid("234567ab"));
}

TEST(make_token_shape) {
    auto t = mcp::make_token();
    ASSERT_EQ(t.size(), std::size_t{64});
    for (char c : t) {
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        ASSERT(ok);
    }
}

TEST(uuid_v4_shape) {
    auto u = mcp::make_uuid_v4();
    ASSERT_EQ(u.size(), std::size_t{36});
    ASSERT_EQ(u[8], '-');
    ASSERT_EQ(u[13], '-');
    ASSERT_EQ(u[14], '4');                // version 4 nibble
    ASSERT_EQ(u[18], '-');
    char variant = u[19];
    ASSERT(variant == '8' || variant == '9' || variant == 'a' || variant == 'b');
    ASSERT_EQ(u[23], '-');
}

TEST(uuid_v4_distinct) {
    std::set<std::string> seen;
    for (int i = 0; i < 100; ++i) seen.insert(mcp::make_uuid_v4());
    ASSERT_EQ(seen.size(), std::size_t{100});
}

TEST_MAIN
