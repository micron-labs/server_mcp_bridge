#include "tools/hosting/process_mgmt.hpp"
#include "registry/tool_registry.hpp"
#include "platform/platform.hpp"
#include <json.hpp>

using json = nlohmann::json;

void register_process_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("list_processes", {
        "", "List running processes",
        {}, {"filter"},
        [](const json& args) -> json {
            std::string filter = args.value("filter", "");
            auto procs = list_processes(filter);
            json result = json::array();
            for (const auto& p : procs) {
                result.push_back({
                    {"pid", p.pid},
                    {"name", p.name},
                    {"user", p.user},
                    {"cpu", p.cpu_percent},
                    {"memory", p.mem_percent},
                    {"command", p.command}
                });
            }
            return {{"processes", result}, {"count", result.size()}};
        }
    });

    reg.register_tool("kill_process", {
        "", "Kill a process by PID",
        {"pid"}, {"signal"},
        [](const json& args) -> json {
            int pid = args["pid"];
            int sig = args.value("signal", 15);
            bool ok = kill_process_by_pid(pid, sig);
            return {{"pid", pid}, {"signal", sig}, {"killed", ok}};
        }
    });

    reg.register_tool("process_info", {
        "", "Get detailed information about a process",
        {"pid"}, {},
        [](const json& args) -> json {
            int pid = args["pid"];
            auto p = get_process_info(pid);
            if (p.pid < 0) throw std::runtime_error("Process not found: " + std::to_string(pid));
            return {
                {"pid", p.pid},
                {"name", p.name},
                {"user", p.user},
                {"cpu", p.cpu_percent},
                {"memory", p.mem_percent},
                {"command", p.command}
            };
        }
    });
}
