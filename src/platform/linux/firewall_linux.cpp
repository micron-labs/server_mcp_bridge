#include "platform/platform.hpp"
#include <sstream>

std::string list_firewall_rules_raw() {
    auto result = run_process("iptables -L -n --line-numbers 2>/dev/null || echo 'iptables not available'");
    return result.stdout_str;
}

bool add_firewall_rule(const FirewallRule& rule) {
    std::string chain = (rule.direction == "out") ? "OUTPUT" : "INPUT";
    std::string target = (rule.action == "deny") ? "DROP" : "ACCEPT";
    std::string proto = rule.protocol.empty() ? "tcp" : rule.protocol;

    std::ostringstream cmd;
    cmd << "iptables -A " << chain << " -p " << proto << " --dport " << rule.port;
    if (!rule.source_ip.empty()) {
        cmd << " -s " << rule.source_ip;
    }
    cmd << " -j " << target;

    auto result = run_process(cmd.str());
    return result.exit_code == 0;
}

bool delete_firewall_rule(const std::string& rule_id) {
    // rule_id format: "INPUT:3" or "OUTPUT:5"
    auto colon = rule_id.find(':');
    if (colon == std::string::npos) return false;
    std::string chain = rule_id.substr(0, colon);
    std::string num = rule_id.substr(colon + 1);

    auto result = run_process("iptables -D " + chain + " " + num);
    return result.exit_code == 0;
}

bool add_port_forward(int source_port, const std::string& dest_host, int dest_port, const std::string& protocol) {
    std::string proto = protocol.empty() ? "tcp" : protocol;
    std::ostringstream cmd;
    cmd << "iptables -t nat -A PREROUTING -p " << proto
        << " --dport " << source_port
        << " -j DNAT --to-destination " << dest_host << ":" << dest_port;
    auto result = run_process(cmd.str());
    return result.exit_code == 0;
}

bool delete_port_forward(int source_port) {
    std::ostringstream cmd;
    cmd << "iptables -t nat -D PREROUTING -p tcp --dport " << source_port << " -j DNAT 2>/dev/null; "
        << "iptables -t nat -D PREROUTING -p udp --dport " << source_port << " -j DNAT 2>/dev/null";
    auto result = run_process(cmd.str());
    return result.exit_code == 0;
}
