#include "platform/platform.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>

ProcessResult run_process(const std::string& command, const std::string& cwd,
                          int timeout_secs, const std::map<std::string,std::string>& env) {
    ProcessResult result;
    std::string full_cmd = command;

    if (timeout_secs > 0) {
        full_cmd = "timeout " + std::to_string(timeout_secs) + " " + full_cmd;
    }
    if (!cwd.empty()) {
        full_cmd = "cd " + cwd + " && " + full_cmd;
    }

    // Build env prefix
    std::string env_prefix;
    for (const auto& [k, v] : env) {
        env_prefix += k + "=" + v + " ";
    }
    if (!env_prefix.empty()) {
        full_cmd = env_prefix + full_cmd;
    }

    // Redirect stderr to stdout
    full_cmd += " 2>&1";

    FILE* pipe = popen(full_cmd.c_str(), "r");
    if (!pipe) {
        result.exit_code = -1;
        result.stderr_str = "Failed to execute command";
        return result;
    }

    std::array<char, 4096> buffer;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result.stdout_str += buffer.data();
    }

    int status = pclose(pipe);
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

int spawn_background(const std::string& command, const std::string& cwd) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        // Child
        setsid();
        if (!cwd.empty()) {
            if (chdir(cwd.c_str()) != 0) _exit(1);
        }
        // Redirect to /dev/null
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
        _exit(1);
    }
    return pid;
}

bool kill_process_by_pid(int pid, int sig) {
    return kill(pid, sig) == 0;
}

std::vector<ProcessInfo> list_processes(const std::string& filter) {
    std::vector<ProcessInfo> procs;
    std::string cmd = "ps aux";
    if (!filter.empty()) {
        cmd += " | grep -i '" + filter + "' | grep -v grep";
    }

    auto result = run_process(cmd);
    std::istringstream stream(result.stdout_str);
    std::string line;
    bool first = true;
    while (std::getline(stream, line)) {
        if (first) { first = false; continue; } // Skip header
        std::istringstream ls(line);
        ProcessInfo pi{};
        std::string user, pid_s, cpu_s, mem_s, vsz, rss, tty, stat, start, time;
        ls >> user >> pid_s >> cpu_s >> mem_s >> vsz >> rss >> tty >> stat >> start >> time;
        std::getline(ls, pi.command);
        if (!pi.command.empty() && pi.command[0] == ' ') pi.command = pi.command.substr(1);
        try {
            pi.pid = std::stoi(pid_s);
            pi.cpu_percent = std::stod(cpu_s);
            pi.mem_percent = std::stod(mem_s);
        } catch (...) { continue; }
        pi.user = user;
        pi.name = pi.command.substr(0, pi.command.find(' '));
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
