#ifdef _WIN32
#include "platform/platform.hpp"
#include <sstream>

std::string list_firewall_rules_raw() {
    auto result = run_process("netsh advfirewall firewall show rule name=all");
    return result.stdout_str;
}

bool add_firewall_rule(const FirewallRule& rule) {
    std::string dir = (rule.direction == "out") ? "dir=out" : "dir=in";
    std::string action = (rule.action == "deny") ? "action=block" : "action=allow";
    std::string proto = rule.protocol.empty() ? "tcp" : rule.protocol;

    std::ostringstream cmd;
    cmd << "netsh advfirewall firewall add rule"
        << " name=\"MCP_" << rule.port << "\""
        << " " << dir
        << " " << action
        << " protocol=" << proto
        << " localport=" << rule.port;

    if (!rule.source_ip.empty()) {
        cmd << " remoteip=" << rule.source_ip;
    }

    auto result = run_process(cmd.str());
    return result.exit_code == 0;
}

bool delete_firewall_rule(const std::string& rule_id) {
    auto result = run_process("netsh advfirewall firewall delete rule name=\"" + rule_id + "\"");
    return result.exit_code == 0;
}

bool add_port_forward(int source_port, const std::string& dest_host, int dest_port, const std::string& /*protocol*/) {
    std::ostringstream cmd;
    cmd << "netsh interface portproxy add v4tov4"
        << " listenport=" << source_port
        << " connectaddress=" << dest_host
        << " connectport=" << dest_port;
    auto result = run_process(cmd.str());
    return result.exit_code == 0;
}

bool delete_port_forward(int source_port) {
    std::ostringstream cmd;
    cmd << "netsh interface portproxy delete v4tov4 listenport=" << source_port;
    auto result = run_process(cmd.str());
    return result.exit_code == 0;
}
#endif
