#include "test_framework.hpp"
#include "core/crypto.hpp"

TEST(sha256_known_vector_empty) {
    ASSERT_EQ(crypto::sha256_hex(""),
              std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST(sha256_known_vector_abc) {
    ASSERT_EQ(crypto::sha256_hex("abc"),
              std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

TEST(sha256_known_vector_long) {
    // Two-block input — exercises the multi-block path. Computed independently
    // via Python's hashlib.sha256(b'a'*200).
    std::string s(200, 'a');
    ASSERT_EQ(crypto::sha256_hex(s),
              std::string("c2a908d98f5df987ade41b5fce213067efbcc21ef2240212a41e54b5e7c28ae5"));
}

TEST(sha256_salted_hex_concatenates) {
    ASSERT_EQ(crypto::sha256_salted_hex("ab", "cd"), crypto::sha256_hex("abcd"));
}

TEST(constant_time_equal_basics) {
    ASSERT(crypto::constant_time_equal("", ""));
    ASSERT(crypto::constant_time_equal("abc", "abc"));
    ASSERT(!crypto::constant_time_equal("abc", "abd"));
    ASSERT(!crypto::constant_time_equal("abc", "abcd"));
    ASSERT(!crypto::constant_time_equal("abc", ""));
}

TEST(to_hex_lowercase) {
    unsigned char b[] = {0x00, 0x0f, 0xff, 0xa5};
    ASSERT_EQ(crypto::to_hex(b, 4), std::string("000fffa5"));
}

TEST_MAIN
