#pragma once
#include <string>

bool verify_bearer_token(const std::string& auth_header, const std::string& expected_key);
