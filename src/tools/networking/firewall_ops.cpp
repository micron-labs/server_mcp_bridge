#include "tools/networking/firewall_ops.hpp"
#include "registry/tool_registry.hpp"
#include "platform/platform.hpp"
#include <json.hpp>

using json = nlohmann::json;

void register_firewall_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("list_firewall_rules", {
        "", "List current firewall rules",
        {}, {},
        [](const json&) -> json {
            return {{"rules", list_firewall_rules_raw()}};
        }
    });

    reg.register_tool("add_firewall_rule", {
        "", "Add a firewall rule to allow or deny traffic on a port",
        {"port", "action"}, {"protocol", "source_ip", "direction"},
        [](const json& args) -> json {
            FirewallRule rule;
            rule.port = args["port"];
            rule.action = args["action"];
            rule.protocol = args.value("protocol", "tcp");
            rule.source_ip = args.value("source_ip", "");
            rule.direction = args.value("direction", "in");
            bool ok = add_firewall_rule(rule);
            if (!ok) throw std::runtime_error("Failed to add firewall rule");
            return {{"port", rule.port}, {"action", rule.action}, {"added", true}};
        }
    });

    reg.register_tool("delete_firewall_rule", {
        "", "Delete a firewall rule by ID",
        {"rule_id"}, {},
        [](const json& args) -> json {
            std::string rule_id = args["rule_id"];
            bool ok = delete_firewall_rule(rule_id);
            if (!ok) throw std::runtime_error("Failed to delete firewall rule");
            return {{"rule_id", rule_id}, {"deleted", true}};
        }
    });

    reg.register_tool("add_port_forward", {
        "", "Create a port forwarding rule",
        {"source_port", "dest_host", "dest_port"}, {"protocol"},
        [](const json& args) -> json {
            int src = args["source_port"];
            std::string dest_host = args["dest_host"];
            int dest_port = args["dest_port"];
            std::string proto = args.value("protocol", "tcp");
            bool ok = add_port_forward(src, dest_host, dest_port, proto);
            if (!ok) throw std::runtime_error("Failed to add port forward");
            return {{"source_port", src}, {"dest_host", dest_host}, {"dest_port", dest_port}, {"added", true}};
        }
    });

    reg.register_tool("delete_port_forward", {
        "", "Remove a port forwarding rule",
        {"source_port"}, {},
        [](const json& args) -> json {
            int port = args["source_port"];
            bool ok = delete_port_forward(port);
            if (!ok) throw std::runtime_error("Failed to delete port forward");
            return {{"source_port", port}, {"deleted", true}};
        }
    });
}
