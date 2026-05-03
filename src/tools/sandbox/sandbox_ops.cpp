#include "tools/sandbox/sandbox_ops.hpp"
#include "registry/tool_registry.hpp"
#include "core/server.hpp"
#include "platform/platform.hpp"
#include <json.hpp>
#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

static const std::map<std::string, std::string> LANG_INTERPRETERS = {
    {"python",     "python3"},
    {"python3",    "python3"},
    {"node",       "node"},
    {"javascript", "node"},
    {"bash",       "bash"},
    {"sh",         "sh"},
    {"ruby",       "ruby"},
    {"perl",       "perl"},
    {"php",        "php"},
};

static const std::map<std::string, std::string> LANG_EXTENSIONS = {
    {"python",     ".py"},
    {"python3",    ".py"},
    {"node",       ".js"},
    {"javascript", ".js"},
    {"bash",       ".sh"},
    {"sh",         ".sh"},
    {"ruby",       ".rb"},
    {"perl",       ".pl"},
    {"php",        ".php"},
    {"c",          ".c"},
    {"cpp",        ".cpp"},
    {"go",         ".go"},
    {"rust",       ".rs"},
};

static std::string get_interpreter(const std::string& lang) {
    auto it = LANG_INTERPRETERS.find(lang);
    if (it != LANG_INTERPRETERS.end()) return it->second;
    return "";
}

static std::string get_extension(const std::string& lang) {
    auto it = LANG_EXTENSIONS.find(lang);
    if (it != LANG_EXTENSIONS.end()) return it->second;
    return ".txt";
}

void register_sandbox_tools() {
    auto& reg = ToolRegistry::instance();

    reg.register_tool("sandbox_run", {
        "", "Execute code in a sandboxed environment",
        {"language", "code"}, {"timeout", "memory_mb", "stdin"},
        [](const RequestContext&, const json& args) -> json {
            auto& cfg = Server::config();
            std::string lang = args["language"];
            std::string code = args["code"];
            int timeout = args.value("timeout", cfg.sandbox_default_timeout);
            int memory = args.value("memory_mb", cfg.sandbox_default_memory_mb);

            // Create temp directory
            std::string sandbox_dir = cfg.sandbox_temp_dir + "/run_" + std::to_string(
                std::chrono::system_clock::now().time_since_epoch().count());
            fs::create_directories(sandbox_dir);

            std::string ext = get_extension(lang);
            std::string file_path = sandbox_dir + "/code" + ext;

            // Write code to temp file
            std::ofstream file(file_path);
            file << code;
            file.close();

            ProcessResult result;

            // Compiled languages need special handling
            if (lang == "c") {
                std::string binary = sandbox_dir + "/a.out";
                auto compile = run_process("gcc -o " + binary + " " + file_path + " 2>&1");
                if (compile.exit_code != 0) {
                    fs::remove_all(sandbox_dir);
                    return {{"language", lang}, {"exit_code", compile.exit_code},
                            {"stdout", ""}, {"stderr", compile.stdout_str}, {"error", "compilation_failed"}};
                }
                result = sandbox_execute(binary, "", timeout, memory, cfg.sandbox_enable_network);
            } else if (lang == "cpp") {
                std::string binary = sandbox_dir + "/a.out";
                auto compile = run_process("g++ -o " + binary + " " + file_path + " 2>&1");
                if (compile.exit_code != 0) {
                    fs::remove_all(sandbox_dir);
                    return {{"language", lang}, {"exit_code", compile.exit_code},
                            {"stdout", ""}, {"stderr", compile.stdout_str}, {"error", "compilation_failed"}};
                }
                result = sandbox_execute(binary, "", timeout, memory, cfg.sandbox_enable_network);
            } else if (lang == "go") {
                result = sandbox_execute("go run", file_path, timeout, memory, cfg.sandbox_enable_network);
            } else if (lang == "rust") {
                std::string binary = sandbox_dir + "/a.out";
                auto compile = run_process("rustc -o " + binary + " " + file_path + " 2>&1");
                if (compile.exit_code != 0) {
                    fs::remove_all(sandbox_dir);
                    return {{"language", lang}, {"exit_code", compile.exit_code},
                            {"stdout", ""}, {"stderr", compile.stdout_str}, {"error", "compilation_failed"}};
                }
                result = sandbox_execute(binary, "", timeout, memory, cfg.sandbox_enable_network);
            } else {
                std::string interpreter = get_interpreter(lang);
                if (interpreter.empty()) {
                    fs::remove_all(sandbox_dir);
                    throw std::runtime_error("Unsupported language: " + lang);
                }
                result = sandbox_execute(interpreter, file_path, timeout, memory, cfg.sandbox_enable_network);
            }

            // Cleanup
            fs::remove_all(sandbox_dir);

            return {
                {"language", lang},
                {"exit_code", result.exit_code},
                {"stdout", result.stdout_str},
                {"stderr", result.stderr_str}
            };
        }
    });

    reg.register_tool("sandbox_run_file", {
        "", "Execute a file in a sandboxed environment",
        {"language", "path"}, {"timeout", "memory_mb", "stdin", "args"},
        [](const RequestContext&, const json& args) -> json {
            auto& cfg = Server::config();
            std::string lang = args["language"];
            std::string path = args["path"];
            int timeout = args.value("timeout", cfg.sandbox_default_timeout);
            int memory = args.value("memory_mb", cfg.sandbox_default_memory_mb);

            if (!fs::exists(path)) throw std::runtime_error("File not found: " + path);

            std::string interpreter = get_interpreter(lang);
            if (interpreter.empty()) throw std::runtime_error("Unsupported language: " + lang);

            auto result = sandbox_execute(interpreter, path, timeout, memory, cfg.sandbox_enable_network);

            return {
                {"language", lang},
                {"path", path},
                {"exit_code", result.exit_code},
                {"stdout", result.stdout_str},
                {"stderr", result.stderr_str}
            };
        }
    });

    reg.register_tool("sandbox_languages", {
        "", "List available sandboxed languages and their runtime status",
        {}, {},
        [](const RequestContext&, const json&) -> json {
            json langs = json::array();
            for (const auto& [lang, interp] : LANG_INTERPRETERS) {
                auto check = run_process("which " + interp + " 2>/dev/null");
                langs.push_back({
                    {"language", lang},
                    {"interpreter", interp},
                    {"available", check.exit_code == 0}
                });
            }
            // Add compiled languages
            for (const char* lang : {"c", "cpp", "go", "rust"}) {
                std::string l(lang);
                std::string compiler = (l == "c") ? "gcc" : (l == "cpp") ? "g++" : (l == "go") ? "go" : "rustc";
                auto check = run_process("which " + compiler + " 2>/dev/null");
                langs.push_back({
                    {"language", lang},
                    {"compiler", compiler},
                    {"available", check.exit_code == 0}
                });
            }
            return {{"languages", langs}};
        }
    });

    reg.register_tool("sandbox_status", {
        "", "Show sandbox capability and isolation status",
        {}, {},
        [](const RequestContext&, const json&) -> json {
            auto caps = get_sandbox_capabilities();
            return {
                {"namespaces", caps.namespaces},
                {"cgroups", caps.cgroups},
                {"seccomp", caps.seccomp},
                {"bubblewrap", caps.bubblewrap},
                {"job_objects", caps.job_objects},
                {"isolation_level", caps.bubblewrap ? "high" : caps.namespaces ? "medium" : "basic"}
            };
        }
    });
}
