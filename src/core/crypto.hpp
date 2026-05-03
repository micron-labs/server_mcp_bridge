#pragma once
#include <array>
#include <cstdint>
#include <string>

namespace crypto {

std::array<uint8_t, 32> sha256(const void* data, std::size_t len);

std::string sha256_hex(const std::string& input);

std::string sha256_salted_hex(const std::string& salt_hex, const std::string& token);

std::string to_hex(const uint8_t* data, std::size_t len);

bool constant_time_equal(const std::string& a, const std::string& b);

}
