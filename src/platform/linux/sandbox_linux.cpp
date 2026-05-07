#include "platform/platform.hpp"
#include <sstream>
#include <filesystem>
#include <fstream>
#include <string>

namespace {

// The bridge daemon often runs under systemd with AmbientCapabilities=CAP_SETUID
// CAP_SETGID so it can drop privileges in run_process_as(). Bubblewrap started
// from that process inherits those ambient bits; when bwrap is not setuid root
// it aborts with "Unexpected capabilities but not setuid".
bool process_has_ambient_capabilities() {
    std::ifstream f("/proc/self/status");
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("CapAmb:", 0) != 0) continue;
        std::string hex;
        for (size_t i = 7; i < line.size(); ++i) {
            char c = line[i];
            if (c == ' ' || c == '\t') continue;
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                hex.push_back(c);
            }
        }
        if (hex.empty()) return false;
        unsigned long long v = 0;
        try {
            v = std::stoull(hex, nullptr, 16);
        } catch (...) {
            return false;
        }
        return v != 0;
    }
    return false;
}

} // namespace

SandboxCapabilities get_sandbox_capabilities() {
    SandboxCapabilities caps;
    caps.namespaces = (run_process("unshare --help 2>&1").exit_code == 0);
    caps.bubblewrap = (run_process("which bwrap 2>/dev/null").exit_code == 0);
    if (caps.bubblewrap && process_has_ambient_capabilities()) {
        caps.bubblewrap = false;
    }
    caps.cgroups = std::filesystem::exists("/sys/fs/cgroup/cgroup.controllers");
    caps.seccomp = std::filesystem::exists("/proc/sys/kernel/seccomp");
    return caps;
}

ProcessResult sandbox_execute(const std::string& interpreter, const std::string& file_path,
                              int timeout_secs, int memory_mb, bool allow_network) {
    auto caps = get_sandbox_capabilities();
    std::ostringstream cmd;

    if (caps.bubblewrap) {
        // Best isolation: bubblewrap
        cmd << "bwrap"
            << " --ro-bind /usr /usr"
            << " --ro-bind /lib /lib";

        // Bind /lib64 if exists
        if (std::filesystem::exists("/lib64")) {
            cmd << " --ro-bind /lib64 /lib64";
        }

        cmd << " --ro-bind /bin /bin"
            << " --ro-bind /sbin /sbin"
            << " --proc /proc"
            << " --dev /dev"
            << " --tmpfs /tmp"
            << " --bind " << std::filesystem::path(file_path).parent_path().string()
            << " /sandbox"
            << " --chdir /sandbox";

        if (!allow_network) {
            cmd << " --unshare-net";
        }
        cmd << " --unshare-pid"
            << " --die-with-parent";

        // Memory limit via ulimit
        long mem_kb = static_cast<long>(memory_mb) * 1024;
        cmd << " /bin/sh -c 'ulimit -v " << mem_kb << " && "
            << "timeout " << timeout_secs << " "
            << interpreter << " /sandbox/" << std::filesystem::path(file_path).filename().string()
            << "'";
    } else {
        // Fallback: ulimit + timeout
        long mem_kb = static_cast<long>(memory_mb) * 1024;
        cmd << "/bin/sh -c 'ulimit -v " << mem_kb << " && "
            << "timeout " << timeout_secs << " "
            << interpreter << " " << file_path << "'";
    }

    return run_process(cmd.str(), "", timeout_secs + 5);
}
