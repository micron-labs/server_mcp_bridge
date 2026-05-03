#pragma once
#include <string>

namespace mcp {

// Writes a connection block to /dev/tty (so it bypasses apt's persistent term
// log) when available, else to stdout. Always also writes to fallback_fd if
// /dev/tty is unavailable. Returns true if anything was written somewhere.
bool print_connection_block(const std::string& shortid,
                            const std::string& token,
                            bool is_admin,
                            int fallback_fd);

std::string infinity_art();

}
