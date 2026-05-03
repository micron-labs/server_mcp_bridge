#include "tools/exec/command_ops.hpp"
#include "registry/tool_registry.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <mutex>
#include <unordered_map>
#include <fstream>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

struct BackgroundProc {
    int pid;
    std::string name;
    std::string command;
    std::string output_file;
};

static std::mutex bg_mutex;
static std::unordered_map<int, BackgroundProc> bg_procs;

void register_exec_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("run_command", {
        "", "Execute a shell command and return output",
        {"command"}, {"cwd", "timeout", "env"},
        [](const RequestContext&, const json& args) -> json {
            std::string cmd = args["command"];
            std::string cwd = args.value("cwd", "");
            int timeout = args.value("timeout", 60);

            std::map<std::string, std::string> env;
            if (args.contains("env") && args["env"].is_object()) {
                for (auto& [k, v] : args["env"].items()) {
                    env[k] = v.get<std::string>();
                }
            }

            spdlog::info("Executing: {}", cmd);
            auto result = run_process(cmd, cwd, timeout, env);
            return {
                {"command", cmd},
                {"exit_code", result.exit_code},
                {"stdout", result.stdout_str},
                {"stderr", result.stderr_str}
            };
        }
    });

    reg.register_tool("run_background", {
        "", "Start a command as a background process",
        {"command"}, {"cwd", "env", "name"},
        [](const RequestContext&, const json& args) -> json {
            std::string cmd = args["command"];
            std::string cwd = args.value("cwd", "");
            std::string name = args.value("name", cmd.substr(0, 30));

            // Create output file for capturing
            std::string output_file = "/tmp/mcp_bg_" + std::to_string(std::hash<std::string>{}(cmd)) + ".log";
            std::string full_cmd = cmd + " > " + output_file + " 2>&1";

            int pid = spawn_background(full_cmd, cwd);
            if (pid < 0) throw std::runtime_error("Failed to spawn background process");

            {
                std::lock_guard<std::mutex> lock(bg_mutex);
                bg_procs[pid] = {pid, name, cmd, output_file};
            }

            spdlog::info("Background process started: pid={} cmd={}", pid, cmd);
            return {{"pid", pid}, {"name", name}, {"command", cmd}};
        }
    });

    reg.register_tool("list_background", {
        "", "List managed background processes",
        {}, {},
        [](const RequestContext&, const json&) -> json {
            std::lock_guard<std::mutex> lock(bg_mutex);
            json result = json::array();
            for (const auto& [pid, proc] : bg_procs) {
                result.push_back({
                    {"pid", proc.pid},
                    {"name", proc.name},
                    {"command", proc.command}
                });
            }
            return {{"processes", result}, {"count", result.size()}};
        }
    });

    reg.register_tool("kill_background", {
        "", "Kill a managed background process",
        {"pid"}, {"signal"},
        [](const RequestContext&, const json& args) -> json {
            int pid = args["pid"];
            int sig = args.value("signal", 15);
            bool ok = kill_process_by_pid(pid, sig);

            {
                std::lock_guard<std::mutex> lock(bg_mutex);
                bg_procs.erase(pid);
            }

            return {{"pid", pid}, {"signal", sig}, {"killed", ok}};
        }
    });

    reg.register_tool("get_output", {
        "", "Get stdout/stderr of a background process",
        {"pid"}, {"lines"},
        [](const RequestContext&, const json& args) -> json {
            int pid = args["pid"];
            int lines = args.value("lines", 100);

            std::string output_file;
            {
                std::lock_guard<std::mutex> lock(bg_mutex);
                auto it = bg_procs.find(pid);
                if (it == bg_procs.end()) {
                    throw std::runtime_error("No managed background process with pid: " + std::to_string(pid));
                }
                output_file = it->second.output_file;
            }

            std::ifstream file(output_file);
            if (!file.is_open()) return {{"pid", pid}, {"output", ""}, {"lines", 0}};

            std::string content;
            std::string line;
            std::vector<std::string> all_lines;
            while (std::getline(file, line)) {
                all_lines.push_back(line);
            }

            // Return last N lines
            int start = std::max(0, static_cast<int>(all_lines.size()) - lines);
            for (int i = start; i < static_cast<int>(all_lines.size()); ++i) {
                content += all_lines[i] + "\n";
            }

            return {{"pid", pid}, {"output", content}, {"total_lines", all_lines.size()}};
        }
    });
}
