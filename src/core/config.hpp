#pragma once
#include <string>
#include <vector>
#include <map>

struct Config {
    // Auth
    std::string api_key;

    // Server
    std::string host = "0.0.0.0";
    int port = 8080;
    bool enable_ssl = false;
    std::string ssl_cert;
    std::string ssl_key;

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
    std::string log_file = "logs/server.log";
    std::string log_level = "info";
};

Config load_config(const std::string& env_path = ".env");
