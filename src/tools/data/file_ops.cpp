#include "tools/data/file_ops.hpp"
#include "registry/tool_registry.hpp"
#include "core/server.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <spdlog/spdlog.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

static bool is_path_allowed(const std::string& path) {
    try {
        auto canonical = fs::weakly_canonical(path).string();
        auto root = fs::weakly_canonical(Server::config().allowed_root).string();
        return canonical.find(root) == 0;
    } catch (...) {
        return false;
    }
}

static json file_entry(const fs::directory_entry& entry) {
    json f;
    f["name"] = entry.path().filename().string();
    f["path"] = entry.path().string();
    f["is_directory"] = entry.is_directory();
    try {
        if (!entry.is_directory()) {
            f["size"] = entry.file_size();
        }
        auto ftime = entry.last_write_time();
        auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
        f["modified"] = std::chrono::system_clock::to_time_t(sctp);
    } catch (...) {}
    return f;
}

void register_file_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("list_files", {
        "", "List directory contents with metadata",
        {}, {"path"},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args.value("path", "/");
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");
            json files = json::array();
            for (const auto& entry : fs::directory_iterator(path)) {
                files.push_back(file_entry(entry));
            }
            return files;
        }
    });

    reg.register_tool("read_file", {
        "", "Read file contents",
        {"path"}, {"offset", "limit"},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args["path"];
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");
            std::ifstream file(path);
            if (!file.is_open()) throw std::runtime_error("Cannot open file: " + path);

            int offset = args.value("offset", 0);
            int limit = args.value("limit", -1);

            std::string content;
            std::string line;
            int line_num = 0;
            while (std::getline(file, line)) {
                if (line_num >= offset) {
                    content += line + "\n";
                    if (limit > 0 && static_cast<int>(content.size()) >= limit) break;
                }
                line_num++;
            }
            return {{"content", content}, {"path", path}, {"lines_read", line_num}};
        }
    });

    reg.register_tool("write_file", {
        "", "Write content to a file",
        {"path", "content"}, {"create_dirs"},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args["path"];
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");

            if (args.value("create_dirs", false)) {
                fs::create_directories(fs::path(path).parent_path());
            }

            std::ofstream file(path);
            if (!file.is_open()) throw std::runtime_error("Cannot write to: " + path);
            file << args["content"].get<std::string>();
            return {{"path", path}, {"written", true}};
        }
    });

    reg.register_tool("delete_file", {
        "", "Delete a file or directory",
        {"path"}, {"recursive"},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args["path"];
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");

            bool recursive = args.value("recursive", false);
            uintmax_t removed = 0;
            if (recursive) {
                removed = fs::remove_all(path);
            } else {
                removed = fs::remove(path) ? 1 : 0;
            }
            return {{"path", path}, {"removed", removed}};
        }
    });

    reg.register_tool("move_file", {
        "", "Move or rename a file/directory",
        {"source", "destination"}, {},
        [](const RequestContext&, const json& args) -> json {
            std::string src = args["source"];
            std::string dst = args["destination"];
            if (!is_path_allowed(src) || !is_path_allowed(dst))
                throw std::runtime_error("Path not allowed");
            fs::rename(src, dst);
            return {{"source", src}, {"destination", dst}, {"moved", true}};
        }
    });

    reg.register_tool("copy_file", {
        "", "Copy a file or directory",
        {"source", "destination"}, {"recursive"},
        [](const RequestContext&, const json& args) -> json {
            std::string src = args["source"];
            std::string dst = args["destination"];
            if (!is_path_allowed(src) || !is_path_allowed(dst))
                throw std::runtime_error("Path not allowed");

            if (args.value("recursive", false) || fs::is_directory(src)) {
                fs::copy(src, dst, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
            } else {
                fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
            }
            return {{"source", src}, {"destination", dst}, {"copied", true}};
        }
    });

    reg.register_tool("search_files", {
        "", "Search for files by name pattern or content",
        {"pattern"}, {"path", "type", "recursive"},
        [](const RequestContext&, const json& args) -> json {
            std::string pattern = args["pattern"];
            std::string base_path = args.value("path", "/");
            std::string type = args.value("type", "name"); // "name" or "content"
            bool recursive = args.value("recursive", true);
            if (!is_path_allowed(base_path)) throw std::runtime_error("Path not allowed");

            json matches = json::array();
            std::regex re(pattern, std::regex::icase);

            auto search = [&](const fs::path& dir) {
                auto it = recursive ? fs::recursive_directory_iterator(dir) : fs::recursive_directory_iterator();
                if (recursive) {
                    for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                        if (matches.size() >= 100) break;
                        if (type == "name") {
                            if (std::regex_search(entry.path().filename().string(), re)) {
                                matches.push_back(file_entry(entry));
                            }
                        } else if (type == "content" && entry.is_regular_file()) {
                            std::ifstream f(entry.path());
                            std::string line;
                            int ln = 0;
                            while (std::getline(f, line)) {
                                ln++;
                                if (std::regex_search(line, re)) {
                                    matches.push_back({
                                        {"path", entry.path().string()},
                                        {"line", ln},
                                        {"content", line}
                                    });
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    for (const auto& entry : fs::directory_iterator(dir)) {
                        if (matches.size() >= 100) break;
                        if (type == "name" && std::regex_search(entry.path().filename().string(), re)) {
                            matches.push_back(file_entry(entry));
                        }
                    }
                }
            };
            search(base_path);
            return {{"pattern", pattern}, {"matches", matches}, {"count", matches.size()}};
        }
    });

    reg.register_tool("file_info", {
        "", "Get detailed file/directory information",
        {"path"}, {},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args["path"];
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");
            auto status = fs::status(path);
            json info;
            info["path"] = fs::canonical(path).string();
            info["exists"] = fs::exists(status);
            info["is_directory"] = fs::is_directory(status);
            info["is_file"] = fs::is_regular_file(status);
            info["is_symlink"] = fs::is_symlink(fs::symlink_status(path));
            if (fs::is_regular_file(status)) {
                info["size"] = fs::file_size(path);
            }
            auto perms = status.permissions();
            info["permissions"] = {
                {"owner_read", (perms & fs::perms::owner_read) != fs::perms::none},
                {"owner_write", (perms & fs::perms::owner_write) != fs::perms::none},
                {"owner_exec", (perms & fs::perms::owner_exec) != fs::perms::none},
                {"group_read", (perms & fs::perms::group_read) != fs::perms::none},
                {"group_write", (perms & fs::perms::group_write) != fs::perms::none},
                {"group_exec", (perms & fs::perms::group_exec) != fs::perms::none},
                {"others_read", (perms & fs::perms::others_read) != fs::perms::none},
                {"others_write", (perms & fs::perms::others_write) != fs::perms::none},
                {"others_exec", (perms & fs::perms::others_exec) != fs::perms::none}
            };
            return info;
        }
    });

    reg.register_tool("set_permissions", {
        "", "Set file/directory permissions (chmod)",
        {"path", "mode"}, {"recursive"},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args["path"];
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");
            std::string mode = args["mode"];

            // Convert octal string to perms
            unsigned int mode_val = std::stoul(mode, nullptr, 8);
            auto perms = static_cast<fs::perms>(mode_val);
            fs::permissions(path, perms, fs::perm_options::replace);

            if (args.value("recursive", false) && fs::is_directory(path)) {
                for (const auto& entry : fs::recursive_directory_iterator(path)) {
                    fs::permissions(entry.path(), perms, fs::perm_options::replace);
                }
            }
            return {{"path", path}, {"mode", mode}, {"set", true}};
        }
    });

    reg.register_tool("set_owner", {
        "", "Set file owner (Linux only, uses chown)",
        {"path", "owner"}, {"group", "recursive"},
        [](const RequestContext&, const json& args) -> json {
#ifdef _WIN32
            return {{"error", "set_owner not supported on Windows"}};
#else
            std::string path = args["path"];
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");
            std::string owner = args["owner"];
            std::string group = args.value("group", "");
            std::string target = owner;
            if (!group.empty()) target += ":" + group;

            std::string cmd = "chown ";
            if (args.value("recursive", false)) cmd += "-R ";
            cmd += target + " " + path;

            auto result = run_process(cmd);
            if (result.exit_code != 0) throw std::runtime_error(result.stdout_str);
            return {{"path", path}, {"owner", owner}, {"group", group}, {"set", true}};
#endif
        }
    });

    reg.register_tool("create_directory", {
        "", "Create a directory",
        {"path"}, {"recursive"},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args["path"];
            if (!is_path_allowed(path)) throw std::runtime_error("Path not allowed");
            bool recursive = args.value("recursive", true);
            bool created = recursive ? fs::create_directories(path) : fs::create_directory(path);
            return {{"path", path}, {"created", created}};
        }
    });

    reg.register_tool("disk_usage", {
        "", "Get disk space information",
        {}, {"path"},
        [](const RequestContext&, const json& args) -> json {
            std::string path = args.value("path", "/");
            auto space = fs::space(path);
            return {
                {"path", path},
                {"capacity_bytes", space.capacity},
                {"free_bytes", space.free},
                {"available_bytes", space.available},
                {"used_bytes", space.capacity - space.free},
                {"capacity_gb", space.capacity / (1024.0 * 1024.0 * 1024.0)},
                {"free_gb", space.free / (1024.0 * 1024.0 * 1024.0)}
            };
        }
    });
}
