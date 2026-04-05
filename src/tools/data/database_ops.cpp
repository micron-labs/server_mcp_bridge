#include "tools/data/database_ops.hpp"
#include "registry/tool_registry.hpp"
#include "core/server.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <regex>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

static void validate_name(const std::string& name) {
    std::regex valid("^[a-zA-Z0-9_]+$");
    if (!std::regex_match(name, valid)) {
        throw std::runtime_error("Invalid name (only alphanumeric and underscore allowed): " + name);
    }
}

static std::string mysql_cmd(const Config& cfg, const std::string& sql, const std::string& db = "") {
    std::string cmd = "mysql -h " + cfg.mysql_host + " -P " + std::to_string(cfg.mysql_port)
                    + " -u " + cfg.mysql_root_user;
    if (!cfg.mysql_root_password.empty()) {
        cmd += " -p'" + cfg.mysql_root_password + "'";
    }
    if (!db.empty()) cmd += " " + db;
    cmd += " -e \"" + sql + "\" --batch --skip-column-names 2>&1";
    return cmd;
}

static std::string psql_cmd(const Config& cfg, const std::string& sql, const std::string& db = "postgres") {
    std::string cmd = "PGPASSWORD='" + cfg.postgres_root_password + "' psql"
                    + " -h " + cfg.postgres_host + " -p " + std::to_string(cfg.postgres_port)
                    + " -U " + cfg.postgres_root_user + " -d " + db
                    + " -t -A -c \"" + sql + "\" 2>&1";
    return cmd;
}

static bool is_mysql(const json& args) {
    return args.value("engine", "mysql") == "mysql";
}

void register_database_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("list_databases", {
        "", "List all databases",
        {}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "SHOW DATABASES;"));
            } else {
                result = run_process(psql_cmd(cfg, "SELECT datname FROM pg_database WHERE datistemplate = false;"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);

            json dbs = json::array();
            std::istringstream stream(result.stdout_str);
            std::string line;
            while (std::getline(stream, line)) {
                line.erase(line.find_last_not_of(" \t\r\n") + 1);
                if (!line.empty()) dbs.push_back(line);
            }
            Server::context().set("databases", dbs);
            return {{"databases", dbs}, {"engine", args.value("engine", "mysql")}};
        }
    });

    reg.register_tool("create_database", {
        "", "Create a new database",
        {"name"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string name = args["name"];
            validate_name(name);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "CREATE DATABASE " + name + ";"));
            } else {
                result = run_process(psql_cmd(cfg, "CREATE DATABASE " + name + ";"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"name", name}, {"created", true}};
        }
    });

    reg.register_tool("delete_database", {
        "", "Drop a database",
        {"name"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string name = args["name"];
            validate_name(name);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "DROP DATABASE " + name + ";"));
            } else {
                result = run_process(psql_cmd(cfg, "DROP DATABASE " + name + ";"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"name", name}, {"deleted", true}};
        }
    });

    reg.register_tool("list_db_users", {
        "", "List database users",
        {}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "SELECT User, Host FROM mysql.user;"));
            } else {
                result = run_process(psql_cmd(cfg, "SELECT usename FROM pg_user;"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            json users = json::array();
            std::istringstream stream(result.stdout_str);
            std::string line;
            while (std::getline(stream, line)) {
                line.erase(line.find_last_not_of(" \t\r\n") + 1);
                if (!line.empty()) users.push_back(line);
            }
            return {{"users", users}};
        }
    });

    reg.register_tool("create_db_user", {
        "", "Create a database user",
        {"username", "password"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string user = args["username"];
            std::string pass = args["password"];
            validate_name(user);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg,
                    "CREATE USER '" + user + "'@'localhost' IDENTIFIED BY '" + pass + "';"));
            } else {
                result = run_process(psql_cmd(cfg,
                    "CREATE USER " + user + " WITH PASSWORD '" + pass + "';"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"username", user}, {"created", true}};
        }
    });

    reg.register_tool("delete_db_user", {
        "", "Drop a database user",
        {"username"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string user = args["username"];
            validate_name(user);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "DROP USER '" + user + "'@'localhost';"));
            } else {
                result = run_process(psql_cmd(cfg, "DROP USER " + user + ";"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"username", user}, {"deleted", true}};
        }
    });

    reg.register_tool("grant_privileges", {
        "", "Grant privileges to a user on a database",
        {"username", "database"}, {"privileges", "engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string user = args["username"];
            std::string db = args["database"];
            std::string privs = args.value("privileges", "ALL PRIVILEGES");
            validate_name(user);
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg,
                    "GRANT " + privs + " ON " + db + ".* TO '" + user + "'@'localhost'; FLUSH PRIVILEGES;"));
            } else {
                result = run_process(psql_cmd(cfg,
                    "GRANT " + privs + " ON DATABASE " + db + " TO " + user + ";"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"username", user}, {"database", db}, {"granted", true}};
        }
    });

    reg.register_tool("revoke_privileges", {
        "", "Revoke all privileges from a user on a database",
        {"username", "database"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string user = args["username"];
            std::string db = args["database"];
            validate_name(user);
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg,
                    "REVOKE ALL PRIVILEGES ON " + db + ".* FROM '" + user + "'@'localhost'; FLUSH PRIVILEGES;"));
            } else {
                result = run_process(psql_cmd(cfg,
                    "REVOKE ALL ON DATABASE " + db + " FROM " + user + ";"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"username", user}, {"database", db}, {"revoked", true}};
        }
    });

    reg.register_tool("run_query", {
        "", "Execute a SQL query and return results",
        {"database", "query"}, {"engine"},
        [](const json& args) -> json {
            if (!Server::config().enable_raw_queries) {
                throw std::runtime_error("Raw queries are disabled. Set ENABLE_RAW_QUERIES=true in .env");
            }
            auto& cfg = Server::config();
            std::string db = args["database"];
            std::string query = args["query"];
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                std::string cmd = "mysql -h " + cfg.mysql_host + " -P " + std::to_string(cfg.mysql_port)
                    + " -u " + cfg.mysql_root_user;
                if (!cfg.mysql_root_password.empty()) cmd += " -p'" + cfg.mysql_root_password + "'";
                cmd += " " + db + " -e \"" + query + "\" --batch 2>&1";
                result = run_process(cmd);
            } else {
                result = run_process(psql_cmd(cfg, query, db));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"output", result.stdout_str}, {"exit_code", result.exit_code}};
        }
    });

    reg.register_tool("run_query_file", {
        "", "Execute a SQL file against a database",
        {"database", "path"}, {"engine"},
        [](const json& args) -> json {
            if (!Server::config().enable_raw_queries) {
                throw std::runtime_error("Raw queries are disabled. Set ENABLE_RAW_QUERIES=true in .env");
            }
            auto& cfg = Server::config();
            std::string db = args["database"];
            std::string path = args["path"];
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                std::string cmd = "mysql -h " + cfg.mysql_host + " -P " + std::to_string(cfg.mysql_port)
                    + " -u " + cfg.mysql_root_user;
                if (!cfg.mysql_root_password.empty()) cmd += " -p'" + cfg.mysql_root_password + "'";
                cmd += " " + db + " < " + path + " 2>&1";
                result = run_process(cmd);
            } else {
                std::string cmd = "PGPASSWORD='" + cfg.postgres_root_password + "' psql"
                    + " -h " + cfg.postgres_host + " -p " + std::to_string(cfg.postgres_port)
                    + " -U " + cfg.postgres_root_user + " -d " + db + " -f " + path + " 2>&1";
                result = run_process(cmd);
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"output", result.stdout_str}, {"exit_code", result.exit_code}};
        }
    });

    reg.register_tool("backup_database", {
        "", "Backup a database to a dump file",
        {"database"}, {"path", "engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string db = args["database"];
            std::string path = args.value("path", db + "_backup.sql");
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                std::string cmd = "mysqldump -h " + cfg.mysql_host + " -P " + std::to_string(cfg.mysql_port)
                    + " -u " + cfg.mysql_root_user;
                if (!cfg.mysql_root_password.empty()) cmd += " -p'" + cfg.mysql_root_password + "'";
                cmd += " " + db + " > " + path + " 2>&1";
                result = run_process(cmd);
            } else {
                std::string cmd = "PGPASSWORD='" + cfg.postgres_root_password + "' pg_dump"
                    + " -h " + cfg.postgres_host + " -p " + std::to_string(cfg.postgres_port)
                    + " -U " + cfg.postgres_root_user + " " + db + " > " + path + " 2>&1";
                result = run_process(cmd);
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"database", db}, {"path", path}, {"backed_up", true}};
        }
    });

    reg.register_tool("restore_database", {
        "", "Restore a database from a dump file",
        {"database", "path"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string db = args["database"];
            std::string path = args["path"];
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                std::string cmd = "mysql -h " + cfg.mysql_host + " -P " + std::to_string(cfg.mysql_port)
                    + " -u " + cfg.mysql_root_user;
                if (!cfg.mysql_root_password.empty()) cmd += " -p'" + cfg.mysql_root_password + "'";
                cmd += " " + db + " < " + path + " 2>&1";
                result = run_process(cmd);
            } else {
                std::string cmd = "PGPASSWORD='" + cfg.postgres_root_password + "' psql"
                    + " -h " + cfg.postgres_host + " -p " + std::to_string(cfg.postgres_port)
                    + " -U " + cfg.postgres_root_user + " -d " + db + " -f " + path + " 2>&1";
                result = run_process(cmd);
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"database", db}, {"path", path}, {"restored", true}};
        }
    });

    reg.register_tool("list_tables", {
        "", "List tables in a database",
        {"database"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string db = args["database"];
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "SHOW TABLES;", db));
            } else {
                result = run_process(psql_cmd(cfg,
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public';", db));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            json tables = json::array();
            std::istringstream stream(result.stdout_str);
            std::string line;
            while (std::getline(stream, line)) {
                line.erase(line.find_last_not_of(" \t\r\n") + 1);
                if (!line.empty()) tables.push_back(line);
            }
            return {{"database", db}, {"tables", tables}};
        }
    });

    reg.register_tool("describe_table", {
        "", "Show table schema/structure",
        {"database", "table"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string db = args["database"];
            std::string table = args["table"];
            validate_name(db);
            validate_name(table);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "DESCRIBE " + table + ";", db));
            } else {
                result = run_process(psql_cmd(cfg,
                    "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_name = '" + table + "';", db));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"database", db}, {"table", table}, {"schema", result.stdout_str}};
        }
    });

    reg.register_tool("db_server_info", {
        "", "Get database server version and status",
        {}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process(mysql_cmd(cfg, "SELECT VERSION(); SHOW STATUS LIKE 'Uptime';"));
            } else {
                result = run_process(psql_cmd(cfg, "SELECT version();"));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"info", result.stdout_str}, {"engine", args.value("engine", "mysql")}};
        }
    });

    reg.register_tool("check_database", {
        "", "Check/repair database integrity",
        {"database"}, {"engine"},
        [](const json& args) -> json {
            auto& cfg = Server::config();
            std::string db = args["database"];
            validate_name(db);
            ProcessResult result;
            if (is_mysql(args)) {
                result = run_process("mysqlcheck -h " + cfg.mysql_host + " -P " + std::to_string(cfg.mysql_port)
                    + " -u " + cfg.mysql_root_user
                    + (cfg.mysql_root_password.empty() ? "" : " -p'" + cfg.mysql_root_password + "'")
                    + " --check " + db + " 2>&1");
            } else {
                result = run_process(psql_cmd(cfg, "SELECT pg_database_size('" + db + "');", db));
            }
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"database", db}, {"result", result.stdout_str}};
        }
    });
}
