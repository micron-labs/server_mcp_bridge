#include "cli/cli_main.hpp"
#include <cstdio>
#include <cstring>

int cli_auth_create(int argc, char** argv);
int cli_auth_rotate(int argc, char** argv);
int cli_auth_list(int argc, char** argv);
int cli_webhook(int argc, char** argv);

static void print_usage() {
    std::fputs(
        "Usage:\n"
        "  mcp_bridge daemon [--config <path>]              Run the server (default)\n"
        "  mcp_bridge auth create [opts]                    Create a user record\n"
        "  mcp_bridge auth rotate <shortid> [opts]          Rotate a user's token\n"
        "  mcp_bridge auth list [opts]                      List all user records\n"
        "  mcp_bridge webhook set --url <url> [opts]        Set bridge webhook URL/secret\n"
        "  mcp_bridge webhook show [opts]                   Print current webhook config\n"
        "  mcp_bridge webhook clear [opts]                  Clear webhook URL and secret\n"
        "  mcp_bridge --help                                This message\n"
        "\n"
        "auth create options:\n"
        "  --name <str>            User's display name (interactive prompt if absent)\n"
        "  --email <str>           User's email (interactive prompt if absent)\n"
        "  --admin                 Create with is_admin=true\n"
        "  --non-interactive       Fail rather than prompt; require --name/--email\n"
        "  --config <path>         Daemon config (default: /etc/mcp_bridge/mcp.json)\n"
        "\n"
        "auth rotate options:\n"
        "  --non-interactive       Print token to stdout instead of /dev/tty\n"
        "  --config <path>         Daemon config (default: /etc/mcp_bridge/mcp.json)\n"
        "\n"
        "auth list options:\n"
        "  --json                  Emit JSON array instead of a human table\n"
        "  --config <path>         Daemon config (default: /etc/mcp_bridge/mcp.json)\n"
        "\n"
        "webhook set options:\n"
        "  --url <url>             Webhook URL (required)\n"
        "  --secret <token>        Optional bearer secret sent with each POST\n"
        "  --config <path>         Daemon config (default: /etc/mcp_bridge/mcp.json)\n",
        stderr);
}

int cli_main(int argc, char** argv) {
    // argv[0]=mcp_bridge, argv[1]=<top>, argv[2]=<sub>, ...
    if (argc < 3) { print_usage(); return 2; }

    if (std::strcmp(argv[1], "auth") == 0) {
        if (std::strcmp(argv[2], "create") == 0) return cli_auth_create(argc - 3, argv + 3);
        if (std::strcmp(argv[2], "rotate") == 0) return cli_auth_rotate(argc - 3, argv + 3);
        if (std::strcmp(argv[2], "list")   == 0) return cli_auth_list  (argc - 3, argv + 3);
        print_usage();
        return 2;
    }

    if (std::strcmp(argv[1], "webhook") == 0) {
        return cli_webhook(argc - 2, argv + 2);
    }

    print_usage();
    return 2;
}
