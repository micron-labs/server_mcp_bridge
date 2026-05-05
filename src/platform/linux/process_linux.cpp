#include "platform/platform.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>
#include <grp.h>
#include <pwd.h>
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

ProcessResult run_process_as(const std::string& os_username,
                             const std::string& command,
                             const std::string& cwd,
                             int timeout_secs,
                             const std::map<std::string,std::string>& env) {
    ProcessResult result;
    if (os_username.empty()) {
        result.exit_code = -1;
        result.stderr_str = "run_process_as: os_username is required";
        return result;
    }

    // Resolve target user. getpwnam_r is reentrant; safer than getpwnam in
    // a process that may be multithreaded.
    struct passwd pwd_buf;
    struct passwd* pwd = nullptr;
    std::vector<char> pwbuf(4096);
    int gp_err;
    while ((gp_err = getpwnam_r(os_username.c_str(), &pwd_buf,
                                pwbuf.data(), pwbuf.size(), &pwd)) == ERANGE) {
        pwbuf.resize(pwbuf.size() * 2);
    }
    if (gp_err != 0 || pwd == nullptr) {
        result.exit_code = -1;
        result.stderr_str = "run_process_as: user '" + os_username + "' not found";
        return result;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        result.exit_code = -1;
        result.stderr_str = "run_process_as: pipe() failed";
        return result;
    }

    // Cache target uid/gid + a copy of the username for initgroups in child.
    uid_t target_uid = pwd->pw_uid;
    gid_t target_gid = pwd->pw_gid;
    std::string username_copy = os_username;

    pid_t pid = fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        result.exit_code = -1;
        result.stderr_str = "run_process_as: fork() failed";
        return result;
    }

    if (pid == 0) {
        // Child: wire stdout/stderr to the pipe, drop privileges, exec.
        ::close(pipefd[0]);
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[1]);

        // Order matters: initgroups + setgid before setuid, because setuid
        // is the operation that drops CAP_SETGID.
        if (initgroups(username_copy.c_str(), target_gid) != 0) _exit(126);
        if (setgid(target_gid) != 0) _exit(126);
        if (setuid(target_uid) != 0) _exit(126);

        // Build env. Inherit nothing — we set HOME, USER, PATH explicitly so
        // the bound user gets a sane shell environment, plus any caller env.
        std::vector<std::string> env_strings;
        env_strings.push_back("HOME=" + std::string(pwd_buf.pw_dir ? pwd_buf.pw_dir : "/"));
        env_strings.push_back("USER=" + username_copy);
        env_strings.push_back("LOGNAME=" + username_copy);
        env_strings.push_back("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        for (const auto& [k, v] : env) {
            env_strings.push_back(k + "=" + v);
        }
        std::vector<char*> envp;
        for (auto& s : env_strings) envp.push_back(s.data());
        envp.push_back(nullptr);

        std::string full_cmd = command;
        if (timeout_secs > 0) {
            full_cmd = "timeout " + std::to_string(timeout_secs) + " " + full_cmd;
        }
        if (!cwd.empty()) {
            // chdir as the target user; if it fails, surface via shell exit.
            full_cmd = "cd " + cwd + " && " + full_cmd;
        }

        char shell[] = "/bin/sh";
        char dashc[] = "-c";
        std::vector<char> cmd_buf(full_cmd.begin(), full_cmd.end());
        cmd_buf.push_back('\0');
        char* argv[] = {shell, dashc, cmd_buf.data(), nullptr};

        execve(shell, argv, envp.data());
        _exit(127);  // exec failed
    }

    // Parent: read stdout, wait, return.
    ::close(pipefd[1]);

    std::array<char, 4096> buffer;
    ssize_t n;
    while ((n = ::read(pipefd[0], buffer.data(), buffer.size())) > 0) {
        result.stdout_str.append(buffer.data(), static_cast<size_t>(n));
    }
    ::close(pipefd[0]);

    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) {
        result.exit_code = -1;
        result.stderr_str = "run_process_as: waitpid failed";
        return result;
    }
    if (WIFEXITED(status)) {
        int rc = WEXITSTATUS(status);
        result.exit_code = rc;
        if (rc == 126) {
            result.stderr_str = "run_process_as: privilege drop to '" +
                                os_username + "' failed (need CAP_SETUID/CAP_SETGID?)";
        } else if (rc == 127) {
            result.stderr_str = "run_process_as: execve(/bin/sh) failed";
        }
    } else {
        result.exit_code = -1;
        result.stderr_str = "run_process_as: child terminated abnormally";
    }
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

int spawn_background_as(const std::string& os_username,
                        const std::string& command,
                        const std::string& cwd) {
    if (os_username.empty()) return -1;

    struct passwd pwd_buf;
    struct passwd* pwd = nullptr;
    std::vector<char> pwbuf(4096);
    int gp_err;
    while ((gp_err = getpwnam_r(os_username.c_str(), &pwd_buf,
                                pwbuf.data(), pwbuf.size(), &pwd)) == ERANGE) {
        pwbuf.resize(pwbuf.size() * 2);
    }
    if (gp_err != 0 || pwd == nullptr) return -1;

    uid_t target_uid = pwd->pw_uid;
    gid_t target_gid = pwd->pw_gid;
    std::string username_copy = os_username;

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        setsid();
        if (!cwd.empty() && chdir(cwd.c_str()) != 0) _exit(1);

        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        if (initgroups(username_copy.c_str(), target_gid) != 0) _exit(126);
        if (setgid(target_gid) != 0) _exit(126);
        if (setuid(target_uid) != 0) _exit(126);

        execl("/bin/sh", "sh", "-c", command.c_str(), nullptr);
        _exit(127);
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
