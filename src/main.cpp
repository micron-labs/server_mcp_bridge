#include "cli/cli_main.hpp"
#include "core/config.hpp"
#include "core/server.hpp"
#include "core/logger.hpp"
#include "registry/tool_registry.hpp"

// Tool registration
#include "tools/data/file_ops.hpp"
#include "tools/data/database_ops.hpp"
#include "tools/networking/port_ops.hpp"
#include "tools/networking/firewall_ops.hpp"
#include "tools/hosting/webserver_ops.hpp"
#include "tools/hosting/process_mgmt.hpp"
#include "tools/exec/command_ops.hpp"
#include "tools/sandbox/sandbox_ops.hpp"
#include "tools/admin/grant_ops.hpp"
#include "tools/admin/user_ops.hpp"

#include <json.hpp>
#include <cstring>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

static void register_builtin_tools() {
    auto& reg = ToolRegistry::instance();
    reg.register_tool("ping", {
        "", "Health check endpoint",
        {}, {},
        [](const RequestContext&, const json&) -> json {
            return {{"pong", true}};
        }
    });
}

static void register_all_tools() {
    register_builtin_tools();
    register_file_tools();
    register_database_tools();
    register_port_tools();
    register_firewall_tools();
    register_webserver_tools();
    register_process_tools();
    register_exec_tools();
    register_sandbox_tools();
    register_grant_tools();
    register_user_tools();
}

static void write_pidfile(const std::string& state_dir) {
    if (state_dir.empty()) return;
    std::string path = state_dir + "/daemon.pid";
    std::ofstream f(path);
    if (!f.is_open()) return;
    f << ::getpid() << "\n";
}

static int run_daemon(int argc, char** argv) {
    std::string config_path = "/etc/mcp_bridge/mcp.json";
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "MCP Bridge v2.0.0\n"
                      << "Usage: mcp_bridge daemon [options]\n"
                      << "  --config <path>  Path to JSON config (default: /etc/mcp_bridge/mcp.json)\n";
            return 0;
        }
    }

    Config config;
    try {
        config = load_config(config_path);
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }

    init_logger(config.log_file, config.log_level);

    if (config.admin_token_hash.empty() || config.global_token_salt.empty()) {
        std::cerr << "ERROR: auth.admin_token_hash and auth.global_token_salt must be set in "
                  << config_path << "\n";
        return 1;
    }

    register_all_tools();

    write_pidfile(config.state_dir);

    Server server(config);
    server.start();
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc >= 2 && std::strcmp(argv[1], "auth") == 0) {
        return cli_main(argc, argv);
    }

    int daemon_argc = argc - 1;
    char** daemon_argv = argv + 1;
    if (daemon_argc > 0 && std::strcmp(daemon_argv[0], "daemon") == 0) {
        // explicit `daemon` subcommand — strip it
        daemon_argc -= 1;
        daemon_argv += 1;
    }

    if (daemon_argc > 0 && (std::strcmp(daemon_argv[0], "--help") == 0 ||
                            std::strcmp(daemon_argv[0], "-h") == 0)) {
        std::cout << "MCP Bridge v2.0.0\n"
                  << "Usage:\n"
                  << "  mcp_bridge daemon [--config <path>]   Run the server (default)\n"
                  << "  mcp_bridge auth create [opts]         Create a user record\n"
                  << "  mcp_bridge auth rotate <shortid>      Rotate a user's token\n"
                  << "  mcp_bridge auth list [--json]         List all user records\n";
        return 0;
    }

    return run_daemon(daemon_argc, daemon_argv);
}
