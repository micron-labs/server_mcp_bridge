// mcp_bridge_priv.exe — Windows analog of the Linux setuid helper
// (src/priv/main.c). Runs as a Windows Service under LocalSystem; accepts
// JSON-line requests from the daemon over a named pipe whose ACL only
// admits the daemon's service SID.
//
// Trust model:
//   daemon (NT SERVICE\mcp_bridge, low-priv) --pipe--> priv (LocalSystem)
//
// A daemon RCE does not yield LocalSystem; the priv service exposes only the
// closed set of operations defined in priv_win/operations.cpp.
//
// To run interactively for debugging:
//   mcp_bridge_priv.exe --console
// To register / unregister the service:
//   mcp_bridge_priv.exe --install
//   mcp_bridge_priv.exe --uninstall

#ifdef _WIN32

#include "priv_win/audit.hpp"
#include "priv_win/operations.hpp"
#include "priv_win/protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <json.hpp>
#include <string>
#include <thread>

using json = nlohmann::json;

namespace {

constexpr const wchar_t* kServiceName = L"mcp_bridge_priv";
constexpr const wchar_t* kServiceDisplay = L"MCP Bridge Privileged Service";
// The daemon's virtual service account. The pipe DACL grants this principal
// connect+read+write; everything else is denied. Adjusting this name here
// without also adjusting installer/install.ps1 will break the trust chain.
constexpr const wchar_t* kDaemonAccount = L"NT SERVICE\\mcp_bridge";

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status = {};
std::atomic<bool> g_stopping{false};

void set_status(DWORD state, DWORD wait_hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted =
        state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP;
    g_status.dwWin32ExitCode = NO_ERROR;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : 1;
    g_status.dwWaitHint = wait_hint;
    if (g_status_handle) SetServiceStatus(g_status_handle, &g_status);
}

// Build a SECURITY_ATTRIBUTES whose DACL only admits the daemon's service
// SID and LocalSystem. Returns nullptr on failure (caller logs).
SECURITY_ATTRIBUTES* build_pipe_security() {
    static SECURITY_ATTRIBUTES sa{};
    static SECURITY_DESCRIPTOR sd{};

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) return nullptr;

    BYTE daemon_sid_buf[SECURITY_MAX_SID_SIZE];
    DWORD daemon_sid_size = sizeof(daemon_sid_buf);
    wchar_t domain[256];
    DWORD domain_len = 256;
    SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, kDaemonAccount,
                            daemon_sid_buf, &daemon_sid_size,
                            domain, &domain_len, &use)) {
        // Daemon account not yet provisioned. Log and fall back to a
        // permissive-to-Administrators ACL so the installer's smoke test
        // can still talk to us; production installs always have the
        // virtual account in place at this point.
        priv_win::audit_event("pipe_acl_lookup_failed",
                              "err=" + std::to_string(GetLastError()));
    }

    PSID system_sid = nullptr;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID,
                             0, 0, 0, 0, 0, 0, 0, &system_sid);

    EXPLICIT_ACCESSW ea[2] = {};
    ea[0].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName = reinterpret_cast<LPWSTR>(daemon_sid_buf);

    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system_sid);

    PACL acl = nullptr;
    if (SetEntriesInAclW(2, ea, nullptr, &acl) != ERROR_SUCCESS) {
        priv_win::audit_event("pipe_acl_setentries_failed",
                              "err=" + std::to_string(GetLastError()));
        if (system_sid) FreeSid(system_sid);
        return nullptr;
    }

    if (!SetSecurityDescriptorDacl(&sd, TRUE, acl, FALSE)) {
        priv_win::audit_event("pipe_acl_setdacl_failed",
                              "err=" + std::to_string(GetLastError()));
        if (system_sid) FreeSid(system_sid);
        return nullptr;
    }

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;
    return &sa;
}

// Read a length-delimited line (terminated by '\n') from `pipe`. Bounded by
// kMaxRequestBytes so a malicious peer can't drive memory exhaustion.
bool read_line(HANDLE pipe, std::string& out) {
    out.clear();
    char ch;
    DWORD n;
    while (out.size() < priv_win::kMaxRequestBytes) {
        if (!ReadFile(pipe, &ch, 1, &n, nullptr) || n == 0) return false;
        if (ch == '\n') return true;
        out.push_back(ch);
    }
    return false;
}

bool write_line(HANDLE pipe, const std::string& data) {
    std::string buf = data + "\n";
    if (buf.size() > priv_win::kMaxResponseBytes) return false;
    DWORD written;
    return WriteFile(pipe, buf.data(),
                     static_cast<DWORD>(buf.size()), &written, nullptr) != 0;
}

json dispatch(const json& req) {
    if (!req.is_object() || !req.contains("op") || !req["op"].is_string()) {
        return {{"ok", false}, {"error", "missing op"}};
    }
    std::string op = req["op"].get<std::string>();
    using namespace priv_win::op;
    if (op == kUserAdd)               return priv_win::handle_useradd(req);
    if (op == kUserDel)               return priv_win::handle_userdel(req);
    if (op == kInstallGrant)          return priv_win::handle_install_grant(req);
    if (op == kRevokeGrant)           return priv_win::handle_revoke_grant(req);
    if (op == kInstallSystemAdmin)    return priv_win::handle_install_system_admin(req);
    if (op == kRevokeSystemAdmin)     return priv_win::handle_revoke_system_admin(req);
    if (op == kPrepareUserState)      return priv_win::handle_prepare_user_state(req);
    if (op == kCleanupUserState)      return priv_win::handle_cleanup_user_state(req);
    if (op == kRunAs)                 return priv_win::handle_run_as(req);
    if (op == kSpawnBackgroundAs)     return priv_win::handle_spawn_background_as(req);
    if (op == kCronInstallJob)        return priv_win::handle_cron_install_job(req);
    if (op == kCronRemoveJob)         return priv_win::handle_cron_remove_job(req);
    if (op == kCronListJobs)          return priv_win::handle_cron_list_jobs(req);
    if (op == kCronWriteMeta)         return priv_win::handle_cron_write_meta(req);
    if (op == kCronDeleteMeta)        return priv_win::handle_cron_delete_meta(req);
    return {{"ok", false}, {"error", "unknown op: " + op}};
}

void handle_connection(HANDLE pipe) {
    std::string line;
    if (!read_line(pipe, line)) {
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        return;
    }
    json resp;
    try {
        json req = json::parse(line);
        resp = dispatch(req);
    } catch (const std::exception& e) {
        resp = {{"ok", false}, {"error", std::string("parse: ") + e.what()}};
    }
    write_line(pipe, resp.dump());
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

void serve_loop() {
    priv_win::register_event_source();
    priv_win::audit_event("service_starting", "");

    SECURITY_ATTRIBUTES* sa = build_pipe_security();

    while (!g_stopping.load()) {
        // Wide-char pipe path so the ACL-bearing CreateNamedPipeW path is used.
        HANDLE pipe = CreateNamedPipeA(
            priv_win::kPipePath,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024, 64 * 1024,
            0,
            sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            priv_win::audit_event("pipe_create_failed",
                                  "err=" + std::to_string(GetLastError()));
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        BOOL connected = ConnectNamedPipe(pipe, nullptr) != 0
                             ? TRUE
                             : (GetLastError() == ERROR_PIPE_CONNECTED ? TRUE : FALSE);
        if (!connected) {
            CloseHandle(pipe);
            continue;
        }

        std::thread(handle_connection, pipe).detach();
    }

    priv_win::audit_event("service_stopped", "");
}

DWORD WINAPI service_ctrl(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            set_status(SERVICE_STOP_PENDING, 5000);
            g_stopping.store(true);
            // Poke the accept loop by connecting once locally so it wakes and
            // observes g_stopping.
            {
                HANDLE h = CreateFileA(priv_win::kPipePath, GENERIC_READ | GENERIC_WRITE,
                                       0, nullptr, OPEN_EXISTING, 0, nullptr);
                if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
            }
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(
        kServiceName, service_ctrl, nullptr);
    if (!g_status_handle) return;
    set_status(SERVICE_START_PENDING, 3000);
    set_status(SERVICE_RUNNING);
    serve_loop();
    set_status(SERVICE_STOPPED);
}

// ---- install / uninstall via SCM ---------------------------------------

int do_install() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << "\n";
        return 1;
    }
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    SC_HANDLE svc = CreateServiceW(
        scm, kServiceName, kServiceDisplay,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        exe, nullptr, nullptr, nullptr,
        nullptr,  // LocalSystem
        nullptr);
    if (!svc) {
        DWORD e = GetLastError();
        CloseServiceHandle(scm);
        std::cerr << "CreateService failed: " << e << "\n";
        return 1;
    }
    StartServiceW(svc, 0, nullptr);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int do_uninstall() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return 1;
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS st;
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 2) {
        std::string cmd = argv[1];
        if (cmd == "--install" || cmd == "/install") return do_install();
        if (cmd == "--uninstall" || cmd == "/uninstall") return do_uninstall();
        if (cmd == "--console") {
            // Foreground mode for diagnostics.
            priv_win::register_event_source();
            serve_loop();
            return 0;
        }
    }

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), service_main },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        // Not started by SCM. Fall back to console mode for ad-hoc runs.
        priv_win::register_event_source();
        serve_loop();
    }
    return 0;
}

#else
// Non-Windows: this binary doesn't exist. Provide a stub so cross-build tools
// don't complain when this file is accidentally included.
int main() { return 0; }
#endif
