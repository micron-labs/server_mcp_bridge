#include "core/shortid.hpp"
#include "core/crypto.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>

namespace mcp {

namespace {

void read_urandom(unsigned char* out, std::size_t n) {
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) throw std::runtime_error("open /dev/urandom failed");
    std::size_t off = 0;
    while (off < n) {
        ssize_t r = ::read(fd, out + off, n - off);
        if (r <= 0) { ::close(fd); throw std::runtime_error("read /dev/urandom"); }
        off += static_cast<std::size_t>(r);
    }
    ::close(fd);
}

}

std::string make_shortid() {
    unsigned char raw[5];
    read_urandom(raw, sizeof(raw));

    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
    // 5 bytes = 40 bits → 8 base32 chars.
    std::string out(8, 'a');
    out[0] = alphabet[ raw[0] >> 3 ];
    out[1] = alphabet[((raw[0] & 0x07) << 2) | (raw[1] >> 6) ];
    out[2] = alphabet[ (raw[1] >> 1) & 0x1f ];
    out[3] = alphabet[((raw[1] & 0x01) << 4) | (raw[2] >> 4) ];
    out[4] = alphabet[((raw[2] & 0x0f) << 1) | (raw[3] >> 7) ];
    out[5] = alphabet[ (raw[3] >> 2) & 0x1f ];
    out[6] = alphabet[((raw[3] & 0x03) << 3) | (raw[4] >> 5) ];
    out[7] = alphabet[  raw[4] & 0x1f ];
    return out;
}

bool valid_shortid(const std::string& s) {
    if (s.size() != 8) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return false;
    }
    return true;
}

std::string make_token() {
    unsigned char raw[32];
    read_urandom(raw, sizeof(raw));
    return crypto::to_hex(raw, sizeof(raw));
}

std::string make_uuid_v4() {
    unsigned char b[16];
    read_urandom(b, sizeof(b));
    b[6] = (b[6] & 0x0f) | 0x40;  // version 4
    b[8] = (b[8] & 0x3f) | 0x80;  // variant 1
    auto hex = crypto::to_hex(b, 16);
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" +
           hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

}
