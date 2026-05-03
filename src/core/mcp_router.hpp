#pragma once
#include "core/jsonrpc.hpp"
#include "core/request_context.hpp"
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>

class McpRouter {
public:
    using Handler = std::function<std::optional<json>(const RequestContext&, const json& params)>;

    McpRouter() = default;
    void add_method(const std::string& method, Handler h);
    bool has_method(const std::string& method) const;

    // Returns the result JSON, or std::nullopt for notifications. Throws
    // McpError when the method or params are invalid.
    std::optional<json> dispatch(const std::string& method,
                                 const RequestContext& ctx,
                                 const json& params);

private:
    std::unordered_map<std::string, Handler> methods_;
};

// Thrown by handlers to signal a JSON-RPC error with a specific code; caller
// converts to a JSON-RPC error envelope.
struct McpError : public std::runtime_error {
    int code;
    McpError(int c, const std::string& msg) : std::runtime_error(msg), code(c) {}
};

namespace mcp {

// Build a router pre-populated with: initialize, notifications/initialized,
// ping, shutdown, tools/list, tools/call.
McpRouter make_default_router();

}
