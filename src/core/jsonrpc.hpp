#pragma once
#include <json.hpp>
#include <optional>
#include <string>

using json = nlohmann::json;

namespace jsonrpc {

constexpr int kParseError     = -32700;
constexpr int kInvalidRequest = -32600;
constexpr int kMethodNotFound = -32601;
constexpr int kInvalidParams  = -32602;
constexpr int kInternalError  = -32603;

struct Request {
    json id;             // null when absent (notification)
    bool has_id = false;
    std::string method;
    json params;

    bool is_notification() const { return !has_id; }
};

// Parses a single JSON-RPC envelope. Returns nullopt and fills `error_response`
// (already shaped as a JSON-RPC error envelope) if the input is malformed.
// Batches are not supported in v1 — they yield kInvalidRequest.
std::optional<Request> parse_request(const json& doc, json& error_response);

json make_response(const json& id, const json& result);
json make_error(const json& id, int code, const std::string& message);

}
