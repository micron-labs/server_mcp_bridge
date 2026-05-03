#include "tools/admin/grant_ops.hpp"
#include "core/server.hpp"
#include "registry/tool_registry.hpp"
#include <stdexcept>

void register_grant_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("grant_request", {
        "", "Issue a time-limited sudoers drop-in via the privileged helper. Admin-only.",
        {"shortid", "template", "captured_args", "ttl_seconds"}, {},
        [](const RequestContext& ctx, const json& args) -> json {
            if (!ctx.is_admin) throw std::runtime_error("admin only");
            auto shortid = args.at("shortid").get<std::string>();
            auto tmpl    = args.at("template").get<std::string>();
            auto captured = args.at("captured_args");
            auto ttl     = std::chrono::seconds(args.at("ttl_seconds").get<int>());
            auto g = Server::grants().request_grant(ctx, shortid, tmpl, captured, ttl);
            return {
                {"grantid", g.grantid},
                {"expires_at", g.expires_at}
            };
        }
    });

    reg.register_tool("grant_revoke", {
        "", "Revoke a previously-issued sudoers drop-in. Admin-only. Idempotent.",
        {"grantid"}, {},
        [](const RequestContext& ctx, const json& args) -> json {
            if (!ctx.is_admin) throw std::runtime_error("admin only");
            Server::grants().revoke_grant(args.at("grantid").get<std::string>());
            return {{"revoked", true}};
        }
    });
}
