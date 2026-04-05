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
        result[name] = {
            {"description", def.description},
            {"required", def.required},
            {"optional", def.optional}
        };
    }
    return result;
}

size_t ToolRegistry::size() const {
    return tools_.size();
}
