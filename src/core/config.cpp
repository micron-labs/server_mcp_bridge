#include "core/config.hpp"
#include <json.hpp>
#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

namespace {

template <typename T>
T get_or(const json& obj, const char* key, T fallback) {
    auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return fallback;
    return it->template get<T>();
}

std::string str_or(const json& obj, const char* key, const std::string& fallback) {
    auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return fallback;
    if (!it->is_string()) {
        throw std::runtime_error(std::string("config: '") + key + "' must be a string");
    }
    return it->get<std::string>();
}

}

Config load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("config: cannot open " + path);
    }

    json doc;
    try {
        file >> doc;
    } catch (const json::parse_error& e) {
        throw std::runtime_error("config: parse error in " + path + ": " + e.what());
    }
    if (!doc.is_object()) {
        throw std::runtime_error("config: " + path + " must be a JSON object at the top level");
    }

    Config cfg;

    if (doc.contains("server") && doc["server"].is_object()) {
        const auto& s = doc["server"];
        cfg.host = str_or(s, "host", cfg.host);
        cfg.port = get_or(s, "port", cfg.port);
        cfg.enable_ssl = get_or(s, "enable_ssl", cfg.enable_ssl);
        cfg.ssl_cert = str_or(s, "ssl_cert", cfg.ssl_cert);
        cfg.ssl_key = str_or(s, "ssl_key", cfg.ssl_key);
    }

    if (doc.contains("auth") && doc["auth"].is_object()) {
        const auto& a = doc["auth"];
        cfg.global_token_salt = str_or(a, "global_token_salt", "");
        cfg.admin_token_hash = str_or(a, "admin_token_hash", "");
    }

    if (doc.contains("paths") && doc["paths"].is_object()) {
        const auto& p = doc["paths"];
        cfg.users_dir = str_or(p, "users_dir", cfg.users_dir);
        cfg.state_dir = str_or(p, "state_dir", cfg.state_dir);
        cfg.sudoers_dir = str_or(p, "sudoers_dir", cfg.sudoers_dir);
        cfg.helper_path = str_or(p, "helper_path", cfg.helper_path);
    }

    cfg.grant_sweep_interval_seconds =
        get_or(doc, "grant_sweep_interval_seconds", cfg.grant_sweep_interval_seconds);

    if (doc.contains("sudo_grant_templates")) {
        cfg.sudo_grant_templates = parse_templates(doc["sudo_grant_templates"]);
    }

    if (doc.contains("security") && doc["security"].is_object()) {
        const auto& s = doc["security"];
        if (s.contains("allowed_ips") && s["allowed_ips"].is_array()) {
            cfg.allowed_ips.clear();
            for (const auto& v : s["allowed_ips"]) {
                if (v.is_string()) cfg.allowed_ips.push_back(v.get<std::string>());
            }
        }
        cfg.rate_limit = get_or(s, "rate_limit", cfg.rate_limit);
        cfg.allowed_root = str_or(s, "allowed_root", cfg.allowed_root);
        cfg.dangerous_tools_enabled = get_or(s, "dangerous_tools_enabled", cfg.dangerous_tools_enabled);
        cfg.enable_raw_queries = get_or(s, "enable_raw_queries", cfg.enable_raw_queries);
    }

    if (doc.contains("mysql") && doc["mysql"].is_object()) {
        const auto& m = doc["mysql"];
        cfg.mysql_host = str_or(m, "host", cfg.mysql_host);
        cfg.mysql_port = get_or(m, "port", cfg.mysql_port);
        cfg.mysql_root_user = str_or(m, "root_user", cfg.mysql_root_user);
        cfg.mysql_root_password = str_or(m, "root_password", cfg.mysql_root_password);
    }

    if (doc.contains("postgres") && doc["postgres"].is_object()) {
        const auto& p = doc["postgres"];
        cfg.postgres_host = str_or(p, "host", cfg.postgres_host);
        cfg.postgres_port = get_or(p, "port", cfg.postgres_port);
        cfg.postgres_root_user = str_or(p, "root_user", cfg.postgres_root_user);
        cfg.postgres_root_password = str_or(p, "root_password", cfg.postgres_root_password);
    }

    if (doc.contains("webserver") && doc["webserver"].is_object()) {
        const auto& w = doc["webserver"];
        cfg.nginx_config_dir = str_or(w, "nginx_config_dir", cfg.nginx_config_dir);
        cfg.apache_config_dir = str_or(w, "apache_config_dir", cfg.apache_config_dir);
        cfg.certbot_path = str_or(w, "certbot_path", cfg.certbot_path);
    }

    if (doc.contains("sandbox") && doc["sandbox"].is_object()) {
        const auto& s = doc["sandbox"];
        cfg.sandbox_temp_dir = str_or(s, "temp_dir", cfg.sandbox_temp_dir);
        cfg.sandbox_default_timeout = get_or(s, "default_timeout", cfg.sandbox_default_timeout);
        cfg.sandbox_default_memory_mb = get_or(s, "default_memory_mb", cfg.sandbox_default_memory_mb);
        cfg.sandbox_enable_network = get_or(s, "enable_network", cfg.sandbox_enable_network);
    }

    if (doc.contains("logging") && doc["logging"].is_object()) {
        const auto& l = doc["logging"];
        cfg.log_file = str_or(l, "file", cfg.log_file);
        cfg.log_level = str_or(l, "level", cfg.log_level);
    }

    return cfg;
}
