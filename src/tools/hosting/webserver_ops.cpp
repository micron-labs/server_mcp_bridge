#include "tools/hosting/webserver_ops.hpp"
#include "registry/tool_registry.hpp"
#include "core/server.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

static std::string resolve_server(const json& args) {
    if (args.contains("server")) return args["server"];
    return detect_webserver();
}

static std::string service_name(const std::string& server) {
    if (server == "nginx") return "nginx";
    if (server == "apache") return "apache2";
    return server;
}

static std::string sites_available_dir(const std::string& server) {
    auto& cfg = Server::config();
    if (server == "nginx") return cfg.nginx_config_dir + "/sites-available";
    return cfg.apache_config_dir + "/sites-available";
}

static std::string sites_enabled_dir(const std::string& server) {
    auto& cfg = Server::config();
    if (server == "nginx") return cfg.nginx_config_dir + "/sites-enabled";
    return cfg.apache_config_dir + "/sites-enabled";
}

static std::string nginx_vhost_template(const std::string& domain, const std::string& root, int port, bool ssl) {
    std::ostringstream tpl;
    tpl << "server {\n"
        << "    listen " << port << ";\n";
    if (ssl) {
        tpl << "    listen " << port << " ssl;\n";
    }
    tpl << "    server_name " << domain << ";\n"
        << "    root " << root << ";\n"
        << "    index index.html index.htm;\n\n"
        << "    location / {\n"
        << "        try_files $uri $uri/ =404;\n"
        << "    }\n"
        << "}\n";
    return tpl.str();
}

static std::string apache_vhost_template(const std::string& domain, const std::string& root, int port) {
    std::ostringstream tpl;
    tpl << "<VirtualHost *:" << port << ">\n"
        << "    ServerName " << domain << "\n"
        << "    DocumentRoot " << root << "\n\n"
        << "    <Directory " << root << ">\n"
        << "        Options Indexes FollowSymLinks\n"
        << "        AllowOverride All\n"
        << "        Require all granted\n"
        << "    </Directory>\n"
        << "</VirtualHost>\n";
    return tpl.str();
}

void register_webserver_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("webserver_status", {
        "", "Check if web server is running and get version",
        {}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            auto status = service_action(service_name(server), "status");
            auto version = run_process(server + " -v 2>&1");
            return {
                {"server", server},
                {"running", status.exit_code == 0},
                {"status_output", status.stdout_str},
                {"version", version.stdout_str}
            };
        }
    });

    reg.register_tool("webserver_start", {
        "", "Start the web server",
        {}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            auto result = service_action(service_name(server), "start");
            return {{"server", server}, {"started", result.exit_code == 0}, {"output", result.stdout_str}};
        }
    });

    reg.register_tool("webserver_stop", {
        "", "Stop the web server",
        {}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            auto result = service_action(service_name(server), "stop");
            return {{"server", server}, {"stopped", result.exit_code == 0}, {"output", result.stdout_str}};
        }
    });

    reg.register_tool("webserver_restart", {
        "", "Restart the web server",
        {}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            auto result = service_action(service_name(server), "restart");
            return {{"server", server}, {"restarted", result.exit_code == 0}, {"output", result.stdout_str}};
        }
    });

    reg.register_tool("webserver_reload", {
        "", "Reload web server configuration without restart",
        {}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            auto result = service_action(service_name(server), "reload");
            return {{"server", server}, {"reloaded", result.exit_code == 0}, {"output", result.stdout_str}};
        }
    });

    reg.register_tool("webserver_test_config", {
        "", "Test web server configuration syntax",
        {}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            std::string cmd = (server == "nginx") ? "nginx -t 2>&1" : "apache2ctl configtest 2>&1";
            auto result = run_process(cmd);
            return {{"server", server}, {"valid", result.exit_code == 0}, {"output", result.stdout_str}};
        }
    });

    reg.register_tool("list_vhosts", {
        "", "List virtual host configurations",
        {}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            std::string dir = sites_available_dir(server);
            json vhosts = json::array();
            if (fs::exists(dir)) {
                for (const auto& entry : fs::directory_iterator(dir)) {
                    if (entry.is_regular_file()) {
                        std::string enabled_path = sites_enabled_dir(server) + "/" + entry.path().filename().string();
                        vhosts.push_back({
                            {"name", entry.path().filename().string()},
                            {"path", entry.path().string()},
                            {"enabled", fs::exists(enabled_path)}
                        });
                    }
                }
            }
            return {{"server", server}, {"vhosts", vhosts}};
        }
    });

    reg.register_tool("get_vhost_config", {
        "", "Read a virtual host configuration file",
        {"domain"}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            std::string domain = args["domain"];
            std::string path = sites_available_dir(server) + "/" + domain;
            if (!fs::exists(path)) path += ".conf";
            if (!fs::exists(path)) throw std::runtime_error("Vhost config not found for: " + domain);

            std::ifstream file(path);
            std::string content((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
            return {{"domain", domain}, {"path", path}, {"content", content}};
        }
    });

    reg.register_tool("create_vhost", {
        "", "Create a new virtual host configuration",
        {"domain", "root"}, {"server", "port", "ssl"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            std::string domain = args["domain"];
            std::string root = args["root"];
            int port = args.value("port", 80);
            bool ssl = args.value("ssl", false);

            std::string config;
            if (server == "nginx") {
                config = nginx_vhost_template(domain, root, port, ssl);
            } else {
                config = apache_vhost_template(domain, root, port);
            }

            std::string avail_path = sites_available_dir(server) + "/" + domain;
            fs::create_directories(sites_available_dir(server));
            fs::create_directories(sites_enabled_dir(server));

            std::ofstream file(avail_path);
            if (!file.is_open()) throw std::runtime_error("Cannot write vhost config");
            file << config;
            file.close();

            // Enable by creating symlink
            std::string enabled_path = sites_enabled_dir(server) + "/" + domain;
            if (!fs::exists(enabled_path)) {
                fs::create_symlink(avail_path, enabled_path);
            }

            return {{"domain", domain}, {"server", server}, {"path", avail_path}, {"created", true}};
        }
    });

    reg.register_tool("delete_vhost", {
        "", "Remove a virtual host configuration",
        {"domain"}, {"server"},
        [](const json& args) -> json {
            std::string server = resolve_server(args);
            std::string domain = args["domain"];

            std::string avail = sites_available_dir(server) + "/" + domain;
            std::string enabled = sites_enabled_dir(server) + "/" + domain;

            if (fs::exists(enabled)) fs::remove(enabled);
            if (fs::exists(avail)) fs::remove(avail);

            return {{"domain", domain}, {"server", server}, {"deleted", true}};
        }
    });

    reg.register_tool("enable_ssl", {
        "", "Enable SSL for a virtual host (certbot or manual)",
        {"domain"}, {"cert_path", "key_path"},
        [](const json& args) -> json {
            std::string domain = args["domain"];
            auto& cfg = Server::config();

            if (args.contains("cert_path") && args.contains("key_path")) {
                // Manual SSL config — would need to edit the vhost
                return {{"domain", domain}, {"ssl", "manual"},
                        {"note", "Cert paths set. Edit vhost config to reference them."},
                        {"cert_path", args["cert_path"]}, {"key_path", args["key_path"]}};
            }

            // Use certbot
            std::string server = detect_webserver();
            std::string plugin = (server == "nginx") ? "--nginx" : "--apache";
            auto result = run_process(cfg.certbot_path + " " + plugin + " -d " + domain + " --non-interactive --agree-tos 2>&1");
            return {
                {"domain", domain},
                {"certbot", result.exit_code == 0},
                {"output", result.stdout_str}
            };
        }
    });
}
