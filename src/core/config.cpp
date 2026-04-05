#include "core/config.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::vector<std::string> split_csv(const std::string& s) {
    std::vector<std::string> result;
    std::istringstream stream(s);
    std::string item;
    while (std::getline(stream, item, ',')) {
        auto trimmed = trim(item);
        if (!trimmed.empty()) result.push_back(trimmed);
    }
    return result;
}

Config load_config(const std::string& env_path) {
    Config cfg;
    std::map<std::string, std::string> env;

    std::ifstream file(env_path);
    if (!file.is_open()) {
        std::cerr << "[config] Warning: Could not open " << env_path << ", using defaults\n";
        return cfg;
    }

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        auto key = trim(line.substr(0, eq));
        auto val = trim(line.substr(eq + 1));
        env[key] = val;
    }

    auto get = [&](const std::string& key) -> std::string {
        auto it = env.find(key);
        return (it != env.end()) ? it->second : "";
    };
    auto get_int = [&](const std::string& key, int def) -> int {
        auto v = get(key);
        return v.empty() ? def : std::stoi(v);
    };
    auto get_bool = [&](const std::string& key, bool def) -> bool {
        auto v = get(key);
        if (v.empty()) return def;
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        return v == "true" || v == "1" || v == "yes";
    };

    // Auth
    cfg.api_key = get("API_KEY");

    // Server
    if (!get("HOST").empty()) cfg.host = get("HOST");
    cfg.port = get_int("PORT", cfg.port);
    cfg.enable_ssl = get_bool("ENABLE_SSL", cfg.enable_ssl);
    if (!get("SSL_CERT").empty()) cfg.ssl_cert = get("SSL_CERT");
    if (!get("SSL_KEY").empty()) cfg.ssl_key = get("SSL_KEY");

    // Security
    if (!get("ALLOWED_IPS").empty()) cfg.allowed_ips = split_csv(get("ALLOWED_IPS"));
    cfg.rate_limit = get_int("RATE_LIMIT", cfg.rate_limit);
    if (!get("ALLOWED_ROOT").empty()) cfg.allowed_root = get("ALLOWED_ROOT");
    cfg.dangerous_tools_enabled = get_bool("DANGEROUS_TOOLS_ENABLED", cfg.dangerous_tools_enabled);
    cfg.enable_raw_queries = get_bool("ENABLE_RAW_QUERIES", cfg.enable_raw_queries);

    // MySQL
    if (!get("MYSQL_HOST").empty()) cfg.mysql_host = get("MYSQL_HOST");
    cfg.mysql_port = get_int("MYSQL_PORT", cfg.mysql_port);
    if (!get("MYSQL_ROOT_USER").empty()) cfg.mysql_root_user = get("MYSQL_ROOT_USER");
    cfg.mysql_root_password = get("MYSQL_ROOT_PASSWORD");

    // PostgreSQL
    if (!get("POSTGRES_HOST").empty()) cfg.postgres_host = get("POSTGRES_HOST");
    cfg.postgres_port = get_int("POSTGRES_PORT", cfg.postgres_port);
    if (!get("POSTGRES_ROOT_USER").empty()) cfg.postgres_root_user = get("POSTGRES_ROOT_USER");
    cfg.postgres_root_password = get("POSTGRES_ROOT_PASSWORD");

    // Web Server
    if (!get("NGINX_CONFIG_DIR").empty()) cfg.nginx_config_dir = get("NGINX_CONFIG_DIR");
    if (!get("APACHE_CONFIG_DIR").empty()) cfg.apache_config_dir = get("APACHE_CONFIG_DIR");
    if (!get("CERTBOT_PATH").empty()) cfg.certbot_path = get("CERTBOT_PATH");

    // Sandbox
    if (!get("SANDBOX_TEMP_DIR").empty()) cfg.sandbox_temp_dir = get("SANDBOX_TEMP_DIR");
    cfg.sandbox_default_timeout = get_int("SANDBOX_DEFAULT_TIMEOUT", cfg.sandbox_default_timeout);
    cfg.sandbox_default_memory_mb = get_int("SANDBOX_DEFAULT_MEMORY_MB", cfg.sandbox_default_memory_mb);
    cfg.sandbox_enable_network = get_bool("SANDBOX_ENABLE_NETWORK", cfg.sandbox_enable_network);

    // Logging
    if (!get("LOG_FILE").empty()) cfg.log_file = get("LOG_FILE");
    if (!get("LOG_LEVEL").empty()) cfg.log_level = get("LOG_LEVEL");

    return cfg;
}
