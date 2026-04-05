#include "platform/platform.hpp"

ProcessResult service_action(const std::string& service, const std::string& action) {
    return run_process("systemctl " + action + " " + service);
}

std::string detect_webserver() {
    auto nginx = run_process("which nginx 2>/dev/null");
    if (nginx.exit_code == 0) return "nginx";
    auto apache = run_process("which apache2 2>/dev/null || which httpd 2>/dev/null");
    if (apache.exit_code == 0) return "apache";
    return "none";
}

std::string list_listening_ports_raw() {
    auto result = run_process("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null");
    return result.stdout_str;
}

bool check_port(int port, const std::string& host) {
    std::string cmd = "timeout 2 bash -c 'echo > /dev/tcp/" + host + "/" + std::to_string(port) + "' 2>/dev/null";
    auto result = run_process(cmd);
    return result.exit_code == 0;
}
