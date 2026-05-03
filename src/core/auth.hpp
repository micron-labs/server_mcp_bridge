#pragma once
#include "core/request_context.hpp"
#include <optional>
#include <string>

class UserStore;

bool verify_bearer_token(const std::string& auth_header,
                         const std::string& global_salt_hex,
                         const std::string& expected_hash_hex);

std::optional<RequestContext> auth_resolve(const std::string& auth_header,
                                           const std::string& global_salt_hex,
                                           const std::string& admin_token_hash_hex,
                                           const UserStore& users,
                                           const std::string& client_ip);
