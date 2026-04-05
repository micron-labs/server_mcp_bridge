#ifdef _WIN32
#include "platform/platform.hpp"

ProcessResult service_action(const std::string& service, const std::string& action) {
    std::string cmd;
    if (action == "start") cmd = "net start " + service;
    else if (action == "stop") cmd = "net stop " + service;
    else if (action == "restart") {
        cmd = "net stop " + service + " && net start " + service;
    } else if (action == "status") {
        cmd = "sc query " + service;
    } else {
        cmd = "sc " + action + " " + service;
    }
    return run_process(cmd);
}

std::string detect_webserver() {
    auto nginx = run_process("where nginx 2>nul");
    if (nginx.exit_code == 0) return "nginx";
    auto apache = run_process("where httpd 2>nul");
    if (apache.exit_code == 0) return "apache";
    return "none";
}

std::string list_listening_ports_raw() {
    auto result = run_process("netstat -ano | findstr LISTENING");
    return result.stdout_str;
}

bool check_port(int port, const std::string& /*host*/) {
    auto result = run_process("netstat -ano | findstr :" + std::to_string(port));
    return result.exit_code == 0 && !result.stdout_str.empty();
}
#endif
