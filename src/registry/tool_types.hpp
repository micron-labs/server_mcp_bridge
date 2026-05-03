#pragma once
#include "core/request_context.hpp"
#include <json.hpp>
#include <string>
#include <vector>
#include <functional>

using json = nlohmann::json;
using ToolHandler = std::function<json(const RequestContext&, const json& args)>;

struct ToolDef {
    std::string name;
    std::string description;
    std::vector<std::string> required;
    std::vector<std::string> optional;
    ToolHandler handler;
};
