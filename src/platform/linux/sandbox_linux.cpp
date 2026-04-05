#include "platform/platform.hpp"
#include <sstream>
#include <filesystem>
#include <fstream>

SandboxCapabilities get_sandbox_capabilities() {
    SandboxCapabilities caps;
    caps.namespaces = (run_process("unshare --help 2>&1").exit_code == 0);
    caps.bubblewrap = (run_process("which bwrap 2>/dev/null").exit_code == 0);
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
