#include "cli/welcome_banner.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sstream>

namespace mcp {

std::string infinity_art() {
    return
        "      ******         ******\n"
        "    **      **     **      **\n"
        "   *          *****          *\n"
        "   *           ***           *\n"
        "   *          *****          *\n"
        "    **      **     **      **\n"
        "      ******         ******\n";
}

bool print_connection_block(const std::string& shortid,
                            const std::string& token,
                            bool is_admin,
                            int fallback_fd) {
    std::ostringstream block;
    block << "\n"
          << infinity_art()
          << "\n"
          << "  MCP Bridge — connection block (shown only once)\n"
          << "  ------------------------------------------------\n"
          << "  shortid:  " << shortid << "\n"
          << "  role:     " << (is_admin ? "admin" : "user") << "\n"
          << "  endpoint: http://<host>:8080/\n"
          << "  header:   Authorization: Bearer " << token << "\n"
          << "\n"
          << "  Save this token now. Use `mcp_bridge auth rotate " << shortid
          << "` to issue a new one.\n\n";
    auto s = block.str();

    int fd = ::open("/dev/tty", O_WRONLY | O_NOCTTY);
    if (fd >= 0) {
        ::write(fd, s.data(), s.size());
        ::close(fd);
        return true;
    }
    if (fallback_fd >= 0) {
        ::write(fallback_fd, s.data(), s.size());
        return true;
    }
    return false;
}

}
