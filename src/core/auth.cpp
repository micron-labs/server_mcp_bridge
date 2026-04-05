#include "core/auth.hpp"
#include <cstring>

// Constant-time comparison to prevent timing attacks
static bool constant_time_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile unsigned char result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        result |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return result == 0;
}

bool verify_bearer_token(const std::string& auth_header, const std::string& expected_key) {
    const std::string prefix = "Bearer ";
    if (auth_header.size() <= prefix.size()) return false;
    if (auth_header.substr(0, prefix.size()) != prefix) return false;
    std::string token = auth_header.substr(prefix.size());
    return constant_time_compare(token, expected_key);
}
