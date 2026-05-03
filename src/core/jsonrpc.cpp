#include "core/jsonrpc.hpp"

namespace jsonrpc {

json make_response(const json& id, const json& result) {
    return {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", result}
    };
}

json make_error(const json& id, int code, const std::string& message) {
    return {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", {{"code", code}, {"message", message}}}
    };
}

std::optional<Request> parse_request(const json& doc, json& error_response) {
    if (doc.is_array()) {
        error_response = make_error(nullptr, kInvalidRequest, "batch requests are not supported");
        return std::nullopt;
    }
    if (!doc.is_object()) {
        error_response = make_error(nullptr, kInvalidRequest, "request must be a JSON object");
        return std::nullopt;
    }

    auto jr = doc.find("jsonrpc");
    if (jr == doc.end() || !jr->is_string() || jr->get<std::string>() != "2.0") {
        error_response = make_error(nullptr, kInvalidRequest, "jsonrpc must be \"2.0\"");
        return std::nullopt;
    }

    auto m = doc.find("method");
    if (m == doc.end() || !m->is_string()) {
        error_response = make_error(nullptr, kInvalidRequest, "method must be a string");
        return std::nullopt;
    }

    Request req;
    req.method = m->get<std::string>();

    auto idi = doc.find("id");
    if (idi != doc.end() && !idi->is_null()) {
        if (!idi->is_string() && !idi->is_number()) {
            error_response = make_error(nullptr, kInvalidRequest,
                                        "id must be a string or number");
            return std::nullopt;
        }
        req.id = *idi;
        req.has_id = true;
    } else {
        req.id = nullptr;
        req.has_id = false;
    }

    auto p = doc.find("params");
    if (p != doc.end()) {
        if (!p->is_object() && !p->is_array()) {
            error_response = make_error(req.id, kInvalidRequest,
                                        "params must be an object or array");
            return std::nullopt;
        }
        req.params = *p;
    } else {
        req.params = json::object();
    }

    return req;
}

}
