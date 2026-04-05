#pragma once
#include "registry/tool_types.hpp"
#include <unordered_map>
#include <string>

class ToolRegistry {
public:
    static ToolRegistry& instance();

    void register_tool(const std::string& name, ToolDef def);
    const ToolDef* find(const std::string& name) const;
    json list_all() const;
    size_t size() const;

private:
    ToolRegistry() = default;
    std::unordered_map<std::string, ToolDef> tools_;
};
