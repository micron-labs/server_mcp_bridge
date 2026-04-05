#ifdef _WIN32
#include "platform/platform.hpp"
#include <windows.h>
#include <array>
#include <sstream>

ProcessResult run_process(const std::string& command, const std::string& cwd,
                          int timeout_secs, const std::map<std::string,std::string>& env) {
    ProcessResult result;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE read_pipe, write_pipe;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
        result.exit_code = -1;
        result.stderr_str = "Failed to create pipe";
        return result;
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;
    si.dwFlags = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi = {};
    std::string cmd_line = "cmd /c " + command;

    BOOL success = CreateProcessA(
        nullptr, const_cast<char*>(cmd_line.c_str()),
        nullptr, nullptr, TRUE, 0, nullptr,
        cwd.empty() ? nullptr : cwd.c_str(),
        &si, &pi);

    CloseHandle(write_pipe);

    if (!success) {
        CloseHandle(read_pipe);
        result.exit_code = -1;
        result.stderr_str = "Failed to create process";
        return result;
    }

    DWORD timeout_ms = timeout_secs > 0 ? timeout_secs * 1000 : INFINITE;
    DWORD wait = WaitForSingleObject(pi.hProcess, timeout_ms);

    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        result.stderr_str = "Process timed out";
    }

    // Read output
    std::array<char, 4096> buffer;
    DWORD bytes_read;
    while (ReadFile(read_pipe, buffer.data(), buffer.size() - 1, &bytes_read, nullptr) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        result.stdout_str += buffer.data();
    }

    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    result.exit_code = static_cast<int>(exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(read_pipe);
    return result;
}

int spawn_background(const std::string& command, const std::string& cwd) {
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    std::string cmd_line = "cmd /c " + command;

    BOOL success = CreateProcessA(
        nullptr, const_cast<char*>(cmd_line.c_str()),
        nullptr, nullptr, FALSE,
        CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
        nullptr, cwd.empty() ? nullptr : cwd.c_str(),
        &si, &pi);

    if (!success) return -1;
    int pid = static_cast<int>(pi.dwProcessId);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return pid;
}

bool kill_process_by_pid(int pid, int /*signal*/) {
    HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!proc) return false;
    BOOL ok = TerminateProcess(proc, 1);
    CloseHandle(proc);
    return ok != 0;
}

std::vector<ProcessInfo> list_processes(const std::string& filter) {
    std::vector<ProcessInfo> procs;
    std::string cmd = "tasklist /FO CSV /NH";
    auto result = run_process(cmd);
    std::istringstream stream(result.stdout_str);
    std::string line;
    while (std::getline(stream, line)) {
        // CSV: "name","pid","session","session#","mem"
        if (line.size() < 5) continue;
        if (!filter.empty() && line.find(filter) == std::string::npos) continue;
        ProcessInfo pi{};
        // Simple CSV parse
        size_t pos = 0;
        auto next_field = [&]() -> std::string {
            if (pos >= line.size()) return "";
            if (line[pos] == '"') {
                auto end = line.find('"', pos + 1);
                auto val = line.substr(pos + 1, end - pos - 1);
                pos = end + 2; // skip closing quote and comma
                return val;
            }
            auto end = line.find(',', pos);
            auto val = line.substr(pos, end - pos);
            pos = end + 1;
            return val;
        };
        pi.name = next_field();
        try { pi.pid = std::stoi(next_field()); } catch (...) { continue; }
        pi.command = pi.name;
        pi.user = "N/A";
        procs.push_back(pi);
    }
    return procs;
}

ProcessInfo get_process_info(int pid) {
    auto procs = list_processes(std::to_string(pid));
    for (const auto& p : procs) {
        if (p.pid == pid) return p;
    }
    return ProcessInfo{-1, "", "", 0, 0, ""};
}
#endif
