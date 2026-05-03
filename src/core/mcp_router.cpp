#include "core/mcp_router.hpp"
#include "registry/tool_registry.hpp"

void McpRouter::add_method(const std::string& method, Handler h) {
    methods_[method] = std::move(h);
}

bool McpRouter::has_method(const std::string& method) const {
    return methods_.count(method) > 0;
}

std::optional<json> McpRouter::dispatch(const std::string& method,
                                       const RequestContext& ctx,
                                       const json& params) {
    auto it = methods_.find(method);
    if (it == methods_.end()) {
        throw McpError(jsonrpc::kMethodNotFound, "method not found: " + method);
    }
    return it->second(ctx, params);
}

namespace mcp {

namespace {

// MCP `tools/list` — array of {name, description, inputSchema}.
json mcp_tools_list() {
    auto raw = ToolRegistry::instance().list_all();  // {name: {description, ..., inputSchema}}
    json arr = json::array();
    for (auto it = raw.begin(); it != raw.end(); ++it) {
        json tool = {
            {"name", it.key()},
            {"description", it.value().value("description", "")},
            {"inputSchema", it.value().value("inputSchema", json{
                {"type", "object"}, {"properties", json::object()}})}
        };
        arr.push_back(std::move(tool));
    }
    return {{"tools", arr}};
}

json mcp_tools_call(const RequestContext& ctx, const json& params) {
    if (!params.is_object()) {
        throw McpError(jsonrpc::kInvalidParams, "params must be an object");
    }
    auto name_it = params.find("name");
    if (name_it == params.end() || !name_it->is_string()) {
        throw McpError(jsonrpc::kInvalidParams, "params.name must be a string");
    }
    std::string tool_name = name_it->get<std::string>();
    json args = params.value("arguments", json::object());
    if (!args.is_object()) {
        throw McpError(jsonrpc::kInvalidParams, "params.arguments must be an object");
    }

    auto* tool = ToolRegistry::instance().find(tool_name);
    if (!tool) {
        throw McpError(jsonrpc::kInvalidParams, "unknown tool: " + tool_name);
    }
    for (const auto& req_arg : tool->required) {
        if (!args.contains(req_arg)) {
            throw McpError(jsonrpc::kInvalidParams,
                          "missing required argument: " + req_arg);
        }
    }

    json content;
    bool is_error = false;
    try {
        json result = tool->handler(ctx, args);
        content = json::array({{
            {"type", "text"},
            {"text", result.dump(2)}
        }});
    } catch (const std::exception& e) {
        is_error = true;
        content = json::array({{
            {"type", "text"},
            {"text", std::string("Error: ") + e.what()}
        }});
    }
    return {
        {"content", content},
        {"isError", is_error}
    };
}

}

McpRouter make_default_router() {
    McpRouter r;

    r.add_method("initialize", [](const RequestContext&, const json& params) -> std::optional<json> {
        // The HTTP layer issues Mcp-Session-Id; we only build the body here.
        std::string client_proto = "2025-03-26";
        if (params.is_object() && params.contains("protocolVersion")) {
            if (params["protocolVersion"].is_string()) {
                client_proto = params["protocolVersion"].get<std::string>();
            }
        }
        return json{
            {"protocolVersion", client_proto},
            {"capabilities", {{"tools", json::object()}}},
            {"serverInfo", {{"name", "mcp_bridge"}, {"version", "2.0.0"}}}
        };
    });

    r.add_method("notifications/initialized",
                 [](const RequestContext&, const json&) -> std::optional<json> {
        return std::nullopt;  // pure notification
    });

    r.add_method("ping", [](const RequestContext&, const json&) -> std::optional<json> {
        return json::object();
    });

    r.add_method("shutdown", [](const RequestContext&, const json&) -> std::optional<json> {
        return json::object();
    });

    r.add_method("tools/list",
                 [](const RequestContext&, const json&) -> std::optional<json> {
        return mcp_tools_list();
    });

    r.add_method("tools/call",
                 [](const RequestContext& ctx, const json& params) -> std::optional<json> {
        return mcp_tools_call(ctx, params);
    });

    return r;
}

}
