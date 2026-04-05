#pragma once
#include <json.hpp>
#include <string>

using json = nlohmann::json;

inline json success_response(const json& data) {
    return {{"success", true}, {"data", data}, {"error", nullptr}};
}

inline json error_response(const std::string& msg) {
    return {{"success", false}, {"data", nullptr}, {"error", msg}};
}
