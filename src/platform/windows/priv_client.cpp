#ifdef _WIN32

#include "platform/windows/priv_client.hpp"
#include "priv_win/protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <windows.h>

#include <chrono>
#include <thread>

namespace priv_client {

namespace {

bool wait_for_pipe(DWORD timeout_ms) {
    return WaitNamedPipeA(priv_win::kPipePath, timeout_ms) != 0;
}

bool write_all(HANDLE pipe, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        DWORD w;
        if (!WriteFile(pipe, data.data() + off,
                       static_cast<DWORD>(data.size() - off), &w, nullptr)) return false;
        if (w == 0) return false;
        off += w;
    }
    return true;
}

bool read_line(HANDLE pipe, std::string& out) {
    out.clear();
    char ch;
    DWORD n;
    while (out.size() < priv_win::kMaxResponseBytes) {
        if (!ReadFile(pipe, &ch, 1, &n, nullptr) || n == 0) return false;
        if (ch == '\n') return true;
        out.push_back(ch);
    }
    return false;
}

}  // namespace

json call(const json& request) {
    // Wait briefly for an instance to be available; the service may be
    // bouncing during a re-install. 5s is enough headroom for SCM.
    if (!wait_for_pipe(5000)) {
        return {{"ok", false},
                {"error", "priv pipe unavailable (service not running?)"}};
    }
    HANDLE pipe = CreateFileA(priv_win::kPipePath,
                              GENERIC_READ | GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return {{"ok", false},
                {"error", "open priv pipe failed: " +
                              std::to_string(GetLastError())}};
    }

    std::string body = request.dump();
    if (body.size() > priv_win::kMaxRequestBytes) {
        CloseHandle(pipe);
        return {{"ok", false}, {"error", "request too large"}};
    }
    body.push_back('\n');

    if (!write_all(pipe, body)) {
        CloseHandle(pipe);
        return {{"ok", false}, {"error", "write to priv pipe failed"}};
    }

    std::string line;
    if (!read_line(pipe, line)) {
        CloseHandle(pipe);
        return {{"ok", false}, {"error", "read from priv pipe failed"}};
    }
    CloseHandle(pipe);

    try {
        return json::parse(line);
    } catch (const std::exception& e) {
        return {{"ok", false},
                {"error", std::string("priv response parse: ") + e.what()}};
    }
}

std::string shortid_from_username(const std::string& os_username) {
    static const std::string prefix = "mcp_user_";
    if (os_username.size() != prefix.size() + 8) return "";
    if (os_username.compare(0, prefix.size(), prefix) != 0) return "";
    std::string id = os_username.substr(prefix.size());
    for (char c : id) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return "";
    }
    return id;
}

ProcessResult run_as(const std::string& shortid,
                     const std::string& command,
                     const std::string& cwd,
                     int timeout_secs,
                     const std::map<std::string, std::string>& env) {
    ProcessResult r;
    json env_obj = json::object();
    for (const auto& [k, v] : env) env_obj[k] = v;

    json req = {
        {"op", priv_win::op::kRunAs},
        {"shortid", shortid},
        {"command", command},
        {"cwd", cwd},
        {"timeout_secs", timeout_secs},
        {"env", env_obj}
    };
    json resp = call(req);
    if (!resp.value("ok", false)) {
        r.exit_code = -1;
        r.stderr_str = resp.value("error", "priv call failed");
        return r;
    }
    r.exit_code = resp.value("exit_code", -1);
    r.stdout_str = resp.value("stdout", "");
    r.stderr_str = resp.value("stderr", "");
    return r;
}

int spawn_background_as(const std::string& shortid,
                        const std::string& command,
                        const std::string& cwd) {
    json req = {
        {"op", priv_win::op::kSpawnBackgroundAs},
        {"shortid", shortid},
        {"command", command},
        {"cwd", cwd}
    };
    json resp = call(req);
    if (!resp.value("ok", false)) return -1;
    return resp.value("pid", -1);
}

}  // namespace priv_client

#endif
