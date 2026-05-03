#include "registry/tool_registry.hpp"

ToolRegistry& ToolRegistry::instance() {
    static ToolRegistry reg;
    return reg;
}

void ToolRegistry::register_tool(const std::string& name, ToolDef def) {
    def.name = name;
    tools_[name] = std::move(def);
}

const ToolDef* ToolRegistry::find(const std::string& name) const {
    auto it = tools_.find(name);
    return (it != tools_.end()) ? &it->second : nullptr;
}

json ToolRegistry::list_all() const {
    json result = json::object();
    for (const auto& [name, def] : tools_) {
        // Synthesize a minimal JSON Schema from required/optional names so that
        // an MCP tools/list response can use this directly as `inputSchema`.
        json properties = json::object();
        for (const auto& a : def.required) properties[a] = json::object();
        for (const auto& a : def.optional) properties[a] = json::object();
        json input_schema = {
            {"type", "object"},
            {"properties", properties},
            {"required", def.required},
            {"additionalProperties", true}
        };
        result[name] = {
            {"description", def.description},
            {"required", def.required},
            {"optional", def.optional},
            {"inputSchema", input_schema}
        };
    }
    return result;
}

size_t ToolRegistry::size() const {
    return tools_.size();
}
