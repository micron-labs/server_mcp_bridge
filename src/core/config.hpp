#pragma once
#include "core/grant_template.hpp"
#include <string>
#include <vector>

struct Config {
    // Server
    std::string host = "0.0.0.0";
    int port = 8080;
    bool enable_ssl = false;
    std::string ssl_cert;
    std::string ssl_key;

    // Auth
    std::string global_token_salt;   // hex string, written by postinst
    std::string admin_token_hash;    // hex string, sha256(salt || admin_token)

    // Paths
    std::string users_dir = "/var/lib/mcp_bridge/users";
    std::string state_dir = "/var/lib/mcp_bridge/state";
    std::string users_state_dir = "/var/lib/mcp_bridge/users_state";
    std::string sudoers_dir = "/etc/sudoers.d";
    std::string helper_path = "/usr/lib/mcp_bridge/mcp_bridge-priv";
    std::string cron_runner_path = "/usr/lib/mcp_bridge/mcp_bridge-cron-runner";
    int grant_sweep_interval_seconds = 30;

    // Sudoers grant templates (rendered by daemon, installed via setuid helper)
    std::vector<GrantTemplate> sudo_grant_templates;

    // Security
    std::vector<std::string> allowed_ips;
    int rate_limit = 60;
    std::string allowed_root = "/";
    bool dangerous_tools_enabled = true;
    bool enable_raw_queries = false;

    // MySQL
    std::string mysql_host = "localhost";
    int mysql_port = 3306;
    std::string mysql_root_user = "root";
    std::string mysql_root_password;

    // PostgreSQL
    std::string postgres_host = "localhost";
    int postgres_port = 5432;
    std::string postgres_root_user = "postgres";
    std::string postgres_root_password;

    // Web Server
    std::string nginx_config_dir = "/etc/nginx";
    std::string apache_config_dir = "/etc/apache2";
    std::string certbot_path = "/usr/bin/certbot";

    // Sandbox
    std::string sandbox_temp_dir = "/tmp/mcp_sandbox";
    int sandbox_default_timeout = 30;
    int sandbox_default_memory_mb = 256;
    bool sandbox_enable_network = false;

    // Logging
    std::string log_file = "/var/log/mcp_bridge/server.log";
    std::string log_level = "info";

    // Webhook (bridge-wide, copied per-user into runtime.json)
    std::string webhook_url;
    std::string webhook_secret_token;
};

Config load_config(const std::string& path = "/etc/mcp_bridge/mcp.json");
