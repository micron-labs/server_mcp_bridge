#include "core/auth.hpp"
#include "core/crypto.hpp"
#include "core/user_store.hpp"

namespace {

bool extract_bearer(const std::string& auth_header, std::string& token) {
    static const std::string prefix = "Bearer ";
    if (auth_header.size() <= prefix.size()) return false;
    if (auth_header.compare(0, prefix.size(), prefix) != 0) return false;
    token = auth_header.substr(prefix.size());
    return !token.empty();
}

}

bool verify_bearer_token(const std::string& auth_header,
                         const std::string& global_salt_hex,
                         const std::string& expected_hash_hex) {
    std::string token;
    if (!extract_bearer(auth_header, token)) return false;
    if (expected_hash_hex.empty()) return false;
    auto computed = crypto::sha256_salted_hex(global_salt_hex, token);
    return crypto::constant_time_equal(computed, expected_hash_hex);
}

std::optional<RequestContext> auth_resolve(const std::string& auth_header,
                                           const std::string& global_salt_hex,
                                           const std::string& admin_token_hash_hex,
                                           const UserStore& users,
                                           const std::string& client_ip) {
    std::string token;
    if (!extract_bearer(auth_header, token)) return std::nullopt;

    auto computed = crypto::sha256_salted_hex(global_salt_hex, token);

    if (auto user = users.lookup_by_hash(computed)) {
        RequestContext ctx;
        ctx.user_id = user->user_id;
        ctx.os_username = user->os_username;
        ctx.is_admin = user->is_admin;
        ctx.bearer_hash = computed;
        ctx.client_ip = client_ip;
        return ctx;
    }

    if (!admin_token_hash_hex.empty() &&
        crypto::constant_time_equal(computed, admin_token_hash_hex)) {
        RequestContext ctx;
        ctx.user_id = "admin";
        // Bind to the install-time ephemeral OS account provisioned by
        // postinst (`mcp_bridge-priv useradd mcpadmin` +
        // `install-system-admin mcpadmin`). The install admin therefore
        // executes tool calls as mcp_user_mcpadmin, which holds a wildcard
        // sudoers entry in /etc/sudoers.d/mcp_system_admin.
        ctx.os_username = "mcp_user_mcpadmin";
        ctx.is_admin = true;
        ctx.bearer_hash = computed;
        ctx.client_ip = client_ip;
        return ctx;
    }

    return std::nullopt;
}
