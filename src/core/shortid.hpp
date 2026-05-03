#pragma once
#include <string>

namespace mcp {

// Random 8-char identifier from the RFC 4648 base32 alphabet (lowercase a-z + 2-7).
// 40 bits of entropy. Used as the per-user `shortid` and as the basis for the
// OS username `mcp_user_<shortid>`.
std::string make_shortid();

bool valid_shortid(const std::string& s);

// Hex-encoded 32-byte token from /dev/urandom.
std::string make_token();

// RFC 4122 v4 UUID, lowercase, with hyphens. Used as the `Mcp-Session-Id`.
std::string make_uuid_v4();

}
