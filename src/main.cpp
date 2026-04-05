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

#include <json.hpp>
#include <iostream>

using json = nlohmann::json;

static void register_builtin_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("ping", {
        "", "Health check endpoint",
        {}, {},
        [](const json&) -> json {
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
}

int main(int argc, char* argv[]) {
    // Allow custom .env path via argument
    std::string env_path = ".env";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--env" && i + 1 < argc) {
            env_path = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Server MCP Bridge v1.0.0\n"
                      << "Usage: server_mcp_bridge [options]\n"
                      << "  --env <path>   Path to .env file (default: .env)\n"
                      << "  --help, -h     Show this help\n";
            return 0;
        }
    }

    // Load config
    auto config = load_config(env_path);

    // Init logger
    init_logger(config.log_file, config.log_level);

    // Validate required config
    if (config.api_key.empty()) {
        std::cerr << "ERROR: API_KEY not set in " << env_path << "\n";
        std::cerr << "Generate one with: openssl rand -hex 32\n";
        return 1;
    }

    // Register all tools
    register_all_tools();

    // Start server
    Server server(config);
    server.start();

    return 0;
}
