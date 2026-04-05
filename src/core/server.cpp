#include "core/server.hpp"
#include "core/auth.hpp"
#include "core/response.hpp"
#include "registry/tool_registry.hpp"
#include <httplib.h>
#include <spdlog/spdlog.h>
#include <json.hpp>

using json = nlohmann::json;

Config* Server::s_config_ = nullptr;
Context* Server::s_context_ = nullptr;

Config& Server::config() { return *s_config_; }
Context& Server::context() { return *s_context_; }

Server::Server(const Config& config)
    : config_(config)
    , rate_limiter_(config.rate_limit)
    , context_("context.json")
{
    s_config_ = &config_;
    s_context_ = &context_;
}

static bool is_ip_allowed(const std::string& ip, const std::vector<std::string>& allowed) {
    if (allowed.empty()) return true;
    for (const auto& a : allowed) {
        if (a == ip) return true;
    }
    return false;
}

void Server::start() {
    httplib::Server svr;

    svr.set_payload_max_length(8 * 1024 * 1024); // 8MB

    // GET /?tools — list tools (no auth)
    svr.Get("/", [this](const httplib::Request& req, httplib::Response& res) {
        if (req.has_param("tools")) {
            auto tools = ToolRegistry::instance().list_all();
            res.set_content(success_response(tools).dump(), "application/json");
            return;
        }
        json info = {
            {"name", "Server MCP Bridge"},
            {"version", "1.0.0"},
            {"tools_count", ToolRegistry::instance().size()}
        };
        res.set_content(success_response(info).dump(), "application/json");
    });

    // POST / — execute tool
    svr.Post("/", [this](const httplib::Request& req, httplib::Response& res) {
        auto client_ip = req.remote_addr;

        // IP allowlist
        if (!is_ip_allowed(client_ip, config_.allowed_ips)) {
            res.status = 403;
            res.set_content(error_response("Forbidden").dump(), "application/json");
            spdlog::warn("Blocked IP: {}", client_ip);
            return;
        }

        // Rate limiting
        if (!rate_limiter_.allow(client_ip)) {
            res.status = 429;
            res.set_content(error_response("Rate limit exceeded").dump(), "application/json");
            spdlog::warn("Rate limited: {}", client_ip);
            return;
        }

        // Authentication
        auto auth = req.get_header_value("Authorization");
        if (!verify_bearer_token(auth, config_.api_key)) {
            res.status = 401;
            res.set_content(error_response("Unauthorized").dump(), "application/json");
            spdlog::warn("Auth failed from: {}", client_ip);
            return;
        }

        // Parse body
        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            res.status = 400;
            res.set_content(error_response("Invalid JSON body").dump(), "application/json");
            return;
        }

        // Extract tool name
        if (!body.contains("tool") || !body["tool"].is_string()) {
            res.status = 400;
            res.set_content(error_response("Missing 'tool' field").dump(), "application/json");
            return;
        }
        std::string tool_name = body["tool"];
        json args = body.value("args", json::object());

        // Find tool
        auto* tool = ToolRegistry::instance().find(tool_name);
        if (!tool) {
            res.status = 400;
            res.set_content(error_response("Unknown tool: " + tool_name).dump(), "application/json");
            return;
        }

        // Validate required args
        for (const auto& req_arg : tool->required) {
            if (!args.contains(req_arg)) {
                res.status = 400;
                res.set_content(
                    error_response("Missing required argument: " + req_arg).dump(),
                    "application/json");
                return;
            }
        }

        // Execute tool
        spdlog::info("[{}] {} args={}", client_ip, tool_name, args.dump());
        try {
            auto result = tool->handler(args);
            res.set_content(success_response(result).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(error_response(e.what()).dump(), "application/json");
            spdlog::error("[{}] {} error: {}", client_ip, tool_name, e.what());
        }
    });

    spdlog::info("Server starting on {}:{}", config_.host, config_.port);
    spdlog::info("Registered {} tools", ToolRegistry::instance().size());

    if (!svr.listen(config_.host, config_.port)) {
        spdlog::critical("Failed to start server on {}:{}", config_.host, config_.port);
    }
}
