#pragma once
#include <string>
#include <vector>
#include <map>

struct ProcessResult {
    int exit_code = -1;
    std::string stdout_str;
    std::string stderr_str;
};

struct ProcessInfo {
    int pid;
    std::string name;
    std::string user;
    double cpu_percent;
    double mem_percent;
    std::string command;
};

struct FirewallRule {
    int port;
    std::string action;       // "allow" or "deny"
    std::string protocol;     // "tcp" or "udp"
    std::string source_ip;
    std::string direction;    // "in" or "out"
};

struct SandboxCapabilities {
    bool namespaces = false;
    bool cgroups = false;
    bool seccomp = false;
    bool bubblewrap = false;
    bool job_objects = false;  // Windows
};

// Process management
ProcessResult run_process(const std::string& command, const std::string& cwd = "",
                          int timeout_secs = 0, const std::map<std::string,std::string>& env = {});

// Same as run_process but executes the command as `os_username` (must exist
// in /etc/passwd). The daemon needs CAP_SETUID and CAP_SETGID to drop into
// the target uid/gid. On Linux: forks, looks up the target via getpwnam,
// initgroups + setgid + setuid in the child, then execve's /bin/sh -c.
// Returns ProcessResult.exit_code = -1 with an error in stderr_str if the
// privilege drop fails. On Windows this is currently equivalent to
// run_process (privilege model differs).
ProcessResult run_process_as(const std::string& os_username,
                             const std::string& command,
                             const std::string& cwd = "",
                             int timeout_secs = 0,
                             const std::map<std::string,std::string>& env = {});

int spawn_background(const std::string& command, const std::string& cwd = "");

// Same as spawn_background but the child is reparented and exec'd as
// `os_username`. Returns pid on success, -1 on fork/lookup failure.
int spawn_background_as(const std::string& os_username,
                        const std::string& command,
                        const std::string& cwd = "");
bool kill_process_by_pid(int pid, int signal = 15);
std::vector<ProcessInfo> list_processes(const std::string& filter = "");
ProcessInfo get_process_info(int pid);

// Firewall
std::string list_firewall_rules_raw();
bool add_firewall_rule(const FirewallRule& rule);
bool delete_firewall_rule(const std::string& rule_id);
bool add_port_forward(int source_port, const std::string& dest_host, int dest_port, const std::string& protocol);
bool delete_port_forward(int source_port);

// Service management
ProcessResult service_action(const std::string& service, const std::string& action);
std::string detect_webserver();

// Sandbox
ProcessResult sandbox_execute(const std::string& interpreter, const std::string& file_path,
                              int timeout_secs, int memory_mb, bool allow_network = false);
SandboxCapabilities get_sandbox_capabilities();

// Networking
std::string list_listening_ports_raw();
bool check_port(int port, const std::string& host = "localhost");
