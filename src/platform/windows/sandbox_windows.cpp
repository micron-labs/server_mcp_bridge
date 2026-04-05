#ifdef _WIN32
#include "platform/platform.hpp"
#include <windows.h>
#include <sstream>

SandboxCapabilities get_sandbox_capabilities() {
    SandboxCapabilities caps;
    caps.job_objects = true; // Always available on Windows
    return caps;
}

ProcessResult sandbox_execute(const std::string& interpreter, const std::string& file_path,
                              int timeout_secs, int memory_mb, bool /*allow_network*/) {
    ProcessResult result;

    // Create Job Object with limits
    HANDLE job = CreateJobObjectA(nullptr, nullptr);
    if (!job) {
        result.exit_code = -1;
        result.stderr_str = "Failed to create job object";
        return result;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_PROCESS_MEMORY |
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(memory_mb) * 1024 * 1024;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));

    // Create process
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe, write_pipe;
    CreatePipe(&read_pipe, &write_pipe, &sa, 0);
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.hStdOutput = write_pipe;
    si.hStdError = write_pipe;
    si.dwFlags = STARTF_USESTDHANDLES;

    PROCESS_INFORMATION pi = {};
    std::string cmd = interpreter + " " + file_path;

    BOOL success = CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()),
        nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi);
    CloseHandle(write_pipe);

    if (!success) {
        CloseHandle(read_pipe);
        CloseHandle(job);
        result.exit_code = -1;
        result.stderr_str = "Failed to create sandboxed process";
        return result;
    }

    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);

    DWORD timeout_ms = timeout_secs > 0 ? timeout_secs * 1000 : 30000;
    DWORD wait = WaitForSingleObject(pi.hProcess, timeout_ms);

    if (wait == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        result.stderr_str = "Sandbox execution timed out";
    }

    // Read output
    char buffer[4096];
    DWORD bytes_read;
    while (ReadFile(read_pipe, buffer, sizeof(buffer) - 1, &bytes_read, nullptr) && bytes_read > 0) {
        buffer[bytes_read] = '\0';
        result.stdout_str += buffer;
    }

    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    result.exit_code = static_cast<int>(exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(read_pipe);
    CloseHandle(job);
    return result;
}
#endif
