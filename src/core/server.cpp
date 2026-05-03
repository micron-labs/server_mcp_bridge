#include "core/server.hpp"
#include "core/auth.hpp"
#include "registry/tool_registry.hpp"
#include <httplib.h>
#include <spdlog/spdlog.h>
#include <json.hpp>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <memory>
#include <thread>

using json = nlohmann::json;

Config* Server::s_config_ = nullptr;
Context* Server::s_context_ = nullptr;
GrantManager* Server::s_grants_ = nullptr;

namespace {
std::atomic<bool> g_reload_users{false};
void on_sighup(int) { g_reload_users.store(true); }

constexpr const char* kSessionHeader = "Mcp-Session-Id";

bool is_ip_allowed(const std::string& ip, const std::vector<std::string>& allowed) {
    if (allowed.empty()) return true;
    for (const auto& a : allowed) if (a == ip) return true;
    return false;
}

GrantManager::Config make_grant_cfg(const Config& c) {
    GrantManager::Config g;
    g.state_dir = c.state_dir;
    g.sudoers_dir = c.sudoers_dir;
    g.helper_path = c.helper_path;
    g.templates = c.sudo_grant_templates;
    g.sweep_interval = std::chrono::seconds(c.grant_sweep_interval_seconds);
    return g;
}
}

Config& Server::config() { return *s_config_; }
Context& Server::context() { return *s_context_; }
GrantManager& Server::grants() { return *s_grants_; }

Server::Server(const Config& config)
    : config_(config)
    , users_(config.users_dir, config.global_token_salt)
    , rate_limiter_(config.rate_limit)
    , context_("context.json")
    , grants_(make_grant_cfg(config))
    , sessions_(std::chrono::hours(1))
    , router_(mcp::make_default_router())
{
    s_config_ = &config_;
    s_context_ = &context_;
    s_grants_ = &grants_;
}

void Server::start() {
    users_.load_all();
    grants_.reconcile_at_startup();
    grants_.start_sweeper();

    struct sigaction sa{};
    sa.sa_handler = on_sighup;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP, &sa, nullptr);

    httplib::Server svr;
    svr.set_payload_max_length(8 * 1024 * 1024);

    // Public probe — does NOT carry tool metadata. Use `tools/list` over MCP for that.
    svr.Get("/healthz", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("ok\n", "text/plain");
    });

    // ----- POST /  : JSON-RPC 2.0 endpoint -----
    svr.Post("/", [this](const httplib::Request& req, httplib::Response& res) {
        if (g_reload_users.exchange(false)) users_.reload();

        auto client_ip = req.remote_addr;

        if (!is_ip_allowed(client_ip, config_.allowed_ips)) {
            res.status = 403;
            res.set_content("Forbidden\n", "text/plain");
            return;
        }

        auto auth_hdr = req.get_header_value("Authorization");
        auto ctx_opt = auth_resolve(auth_hdr,
                                    config_.global_token_salt,
                                    config_.admin_token_hash,
                                    users_,
                                    client_ip);
        if (!ctx_opt) {
            res.status = 401;
            res.set_content("Unauthorized\n", "text/plain");
            return;
        }
        RequestContext ctx = *ctx_opt;

        if (!rate_limiter_.allow(ctx.user_id)) {
            res.status = 429;
            res.set_content("Rate limit exceeded\n", "text/plain");
            return;
        }

        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            res.status = 400;
            auto err = jsonrpc::make_error(nullptr, jsonrpc::kParseError,
                                           "invalid JSON body");
            res.set_content(err.dump(), "application/json");
            return;
        }

        json env_err;
        auto parsed = jsonrpc::parse_request(body, env_err);
        if (!parsed) {
            res.status = 400;
            res.set_content(env_err.dump(), "application/json");
            return;
        }
        const auto& rpc = *parsed;

        // Session handling: `initialize` issues the session id (no header
        // required); every other method must carry a valid Mcp-Session-Id
        // bound to the same bearer hash.
        std::string sess_hdr = req.get_header_value(kSessionHeader);
        if (rpc.method == "initialize") {
            if (!sess_hdr.empty()) sessions_.invalidate(sess_hdr);
            auto sess = sessions_.issue(ctx.bearer_hash, ctx.user_id);
            ctx.session_id = sess.id;
            res.set_header(kSessionHeader, sess.id);
        } else {
            if (sess_hdr.empty()) {
                res.status = 400;
                auto err = jsonrpc::make_error(rpc.id, jsonrpc::kInvalidRequest,
                                               "missing Mcp-Session-Id; call initialize first");
                res.set_content(err.dump(), "application/json");
                return;
            }
            auto sess = sessions_.validate(sess_hdr, ctx.bearer_hash);
            if (!sess) {
                res.status = 401;
                auto err = jsonrpc::make_error(rpc.id, jsonrpc::kInvalidRequest,
                                               "session unknown or bound to a different bearer");
                res.set_content(err.dump(), "application/json");
                return;
            }
            ctx.session_id = sess->id;
        }

        spdlog::info("[{}] user={} sess={} method={}", client_ip, ctx.user_id,
                     ctx.session_id.substr(0, 8), rpc.method);

        std::optional<json> result;
        try {
            result = router_.dispatch(rpc.method, ctx, rpc.params);
        } catch (const McpError& e) {
            if (rpc.is_notification()) {
                res.status = 204;
                return;
            }
            res.status = (e.code == jsonrpc::kMethodNotFound) ? 404 : 400;
            res.set_content(jsonrpc::make_error(rpc.id, e.code, e.what()).dump(),
                            "application/json");
            return;
        } catch (const std::exception& e) {
            spdlog::error("[{}] user={} {} internal error: {}", client_ip, ctx.user_id,
                          rpc.method, e.what());
            if (rpc.is_notification()) { res.status = 204; return; }
            res.status = 500;
            res.set_content(jsonrpc::make_error(rpc.id, jsonrpc::kInternalError,
                                                e.what()).dump(),
                            "application/json");
            return;
        }

        if (rpc.method == "shutdown") sessions_.invalidate(ctx.session_id);

        if (rpc.is_notification()) {
            res.status = 204;
            return;
        }
        res.set_content(jsonrpc::make_response(rpc.id, *result).dump(),
                        "application/json");
    });

    // ----- GET /  : Server-Sent Events for server→client notifications -----
    svr.Get("/", [this](const httplib::Request& req, httplib::Response& res) {
        if (g_reload_users.exchange(false)) users_.reload();
        auto client_ip = req.remote_addr;

        if (!is_ip_allowed(client_ip, config_.allowed_ips)) {
            res.status = 403; res.set_content("Forbidden\n", "text/plain"); return;
        }

        auto auth_hdr = req.get_header_value("Authorization");
        auto ctx_opt = auth_resolve(auth_hdr, config_.global_token_salt,
                                    config_.admin_token_hash, users_, client_ip);
        if (!ctx_opt) {
            res.status = 401; res.set_content("Unauthorized\n", "text/plain"); return;
        }

        std::string sess_hdr = req.get_header_value(kSessionHeader);
        if (sess_hdr.empty() || !sessions_.validate(sess_hdr, ctx_opt->bearer_hash)) {
            res.status = 401;
            res.set_content("session required (call initialize first)\n", "text/plain");
            return;
        }

        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");

        auto state = std::make_shared<int>(0);
        res.set_chunked_content_provider(
            "text/event-stream",
            [state](std::size_t, httplib::DataSink& sink) -> bool {
                if (!sink.is_writable()) return false;
                if (*state == 0) {
                    *state = 1;
                    static const std::string ready =
                        "event: ready\ndata: {\"jsonrpc\":\"2.0\","
                        "\"method\":\"server/ready\"}\n\n";
                    sink.write(ready.data(), ready.size());
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (!sink.is_writable()) return false;
                static const std::string hb =
                    "event: heartbeat\ndata: {}\n\n";
                sink.write(hb.data(), hb.size());
                return true;
            });
    });

    spdlog::info("MCP Bridge listening on {}:{}", config_.host, config_.port);
    spdlog::info("{} tools registered, {} user(s) loaded",
                 ToolRegistry::instance().size(), users_.size());

    if (!svr.listen(config_.host, config_.port)) {
        spdlog::critical("Failed to bind {}:{}", config_.host, config_.port);
    }
}
