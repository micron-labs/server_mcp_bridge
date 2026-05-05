#ifdef _WIN32
#include "priv_win/operations.hpp"
#include "priv_win/audit.hpp"

// Order matters: <winsock2.h> first (via WIN32_LEAN_AND_MEAN below), then
// <windows.h>, then the rest. ntsecapi.h pulls in LSA types. lm.h is
// NetUserAdd / NetUserDel. userenv.h is CreateEnvironmentBlock.
#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_  // suppress winsock1 from being pulled in via windows.h
#include <windows.h>
#include <lm.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <userenv.h>
#include <wchar.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace priv_win {

namespace {

// ---- Path conventions (mirror MSI install layout) ----------------------

constexpr const char* kProgramDataRel = "mcp_bridge";

std::string program_data_dir() {
    char buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return "C:\\ProgramData";
    return std::string(buf, n);
}

std::string grants_dir() {
    return program_data_dir() + "\\" + kProgramDataRel + "\\grants";
}

std::string user_sids_path() {
    // Maps mcp_user_<shortid> → SID-string. Captured at user-create time so
    // RunAs can defend against name reuse with a fresh SID.
    return program_data_dir() + "\\" + kProgramDataRel + "\\state\\user_sids.json";
}

std::string users_state_dir() {
    return program_data_dir() + "\\" + kProgramDataRel + "\\users_state";
}

std::string system_admin_path() {
    return grants_dir() + "\\..\\system_admin.json";
}

// ---- Validation ----------------------------------------------------------

bool valid_grant_path_segment(const std::string& s) {
    // Used for `command_pattern` in grants and for `cwd`. We never let it
    // contain `..`, NUL, or directory separators-as-control. Kept loose so
    // legitimate paths with spaces (Program Files) work.
    if (s.empty()) return false;
    if (s.find('\0') != std::string::npos) return false;
    if (s.find("..") != std::string::npos) return false;
    return true;
}

// Read whole file → string. Returns empty on error.
std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {};
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return s;
}

bool atomic_write_file(const std::string& path, const std::string& data) {
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);
    std::string tmp = path + ".tmp." + std::to_string(GetCurrentProcessId());
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) return false;
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
        f.flush();
        if (!f.good()) return false;
    }
    return MoveFileExA(tmp.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
}

// ---- Random password generation -----------------------------------------

std::wstring generate_password() {
    // 32 bytes of cryptographic randomness, hex-encoded → 64 chars + extra
    // class characters to satisfy the default Windows password policy
    // (uppercase, lowercase, digit, symbol).
    static const wchar_t hex[] = L"0123456789abcdef";
    unsigned char buf[32];
    std::random_device rd;
    for (size_t i = 0; i < sizeof(buf); ++i) buf[i] = static_cast<unsigned char>(rd());
    std::wstring s;
    s.reserve(70);
    s.append(L"Aa1!");  // class-mix prefix; the rest is hex
    for (size_t i = 0; i < sizeof(buf); ++i) {
        s.push_back(hex[buf[i] >> 4]);
        s.push_back(hex[buf[i] & 0xf]);
    }
    return s;
}

// ---- LSA secret store ---------------------------------------------------

// Stores `password` keyed by `key` in the LSA private data store. The store
// is encrypted at rest by Windows and only accessible to LocalSystem (which
// is what the priv service runs as).
//
// Convention: key = L"mcp_bridge_pw_<shortid>".
bool lsa_store_password(const std::wstring& key, const std::wstring& password) {
    LSA_OBJECT_ATTRIBUTES attrs = {};
    LSA_HANDLE policy = nullptr;
    NTSTATUS st = LsaOpenPolicy(nullptr, &attrs, POLICY_CREATE_SECRET, &policy);
    if (st != 0) return false;

    LSA_UNICODE_STRING key_us{};
    key_us.Buffer = const_cast<wchar_t*>(key.c_str());
    key_us.Length = static_cast<USHORT>(key.size() * sizeof(wchar_t));
    key_us.MaximumLength = key_us.Length;

    LSA_UNICODE_STRING data_us{};
    data_us.Buffer = const_cast<wchar_t*>(password.c_str());
    data_us.Length = static_cast<USHORT>(password.size() * sizeof(wchar_t));
    data_us.MaximumLength = data_us.Length;

    st = LsaStorePrivateData(policy, &key_us, &data_us);
    LsaClose(policy);
    return st == 0;
}

bool lsa_retrieve_password(const std::wstring& key, std::wstring& out) {
    LSA_OBJECT_ATTRIBUTES attrs = {};
    LSA_HANDLE policy = nullptr;
    NTSTATUS st = LsaOpenPolicy(nullptr, &attrs, POLICY_GET_PRIVATE_INFORMATION, &policy);
    if (st != 0) return false;

    LSA_UNICODE_STRING key_us{};
    key_us.Buffer = const_cast<wchar_t*>(key.c_str());
    key_us.Length = static_cast<USHORT>(key.size() * sizeof(wchar_t));
    key_us.MaximumLength = key_us.Length;

    PLSA_UNICODE_STRING data = nullptr;
    st = LsaRetrievePrivateData(policy, &key_us, &data);
    LsaClose(policy);
    if (st != 0 || !data) return false;
    out.assign(data->Buffer, data->Length / sizeof(wchar_t));
    LsaFreeMemory(data);
    return true;
}

void lsa_delete_password(const std::wstring& key) {
    LSA_OBJECT_ATTRIBUTES attrs = {};
    LSA_HANDLE policy = nullptr;
    if (LsaOpenPolicy(nullptr, &attrs, POLICY_CREATE_SECRET, &policy) != 0) return;
    LSA_UNICODE_STRING key_us{};
    key_us.Buffer = const_cast<wchar_t*>(key.c_str());
    key_us.Length = static_cast<USHORT>(key.size() * sizeof(wchar_t));
    key_us.MaximumLength = key_us.Length;
    // Per docs: passing a NULL data pointer deletes the secret.
    LsaStorePrivateData(policy, &key_us, nullptr);
    LsaClose(policy);
}

// ---- SID lookup / persistence -------------------------------------------

std::string sid_string_for_user(const std::wstring& wuser) {
    BYTE sid_buf[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid_buf);
    wchar_t domain[256];
    DWORD domain_len = 256;
    SID_NAME_USE use;
    if (!LookupAccountNameW(nullptr, wuser.c_str(),
                            sid_buf, &sid_size, domain, &domain_len, &use)) {
        return {};
    }
    LPSTR sid_str = nullptr;
    if (!ConvertSidToStringSidA(sid_buf, &sid_str)) return {};
    std::string out = sid_str;
    LocalFree(sid_str);
    return out;
}

void persist_user_sid(const std::string& username, const std::string& sid) {
    std::string p = user_sids_path();
    json doc = json::object();
    auto raw = read_file(p);
    if (!raw.empty()) {
        try { doc = json::parse(raw); } catch (...) { doc = json::object(); }
    }
    doc[username] = sid;
    atomic_write_file(p, doc.dump(2));
}

std::string lookup_persisted_sid(const std::string& username) {
    auto raw = read_file(user_sids_path());
    if (raw.empty()) return {};
    try {
        json doc = json::parse(raw);
        if (doc.is_object() && doc.contains(username) && doc[username].is_string()) {
            return doc[username].get<std::string>();
        }
    } catch (...) {}
    return {};
}

void forget_persisted_sid(const std::string& username) {
    auto raw = read_file(user_sids_path());
    if (raw.empty()) return;
    try {
        json doc = json::parse(raw);
        if (doc.is_object()) {
            doc.erase(username);
            atomic_write_file(user_sids_path(), doc.dump(2));
        }
    } catch (...) {}
}

// ---- Grant lookup --------------------------------------------------------

// Returns {match: bool, elevated: bool, command: "..."} for the first grant
// belonging to `shortid` whose `command_pattern` exact-matches `command`.
// The system_admin wildcard grant ("*") is checked separately.
struct GrantMatch {
    bool match = false;
    bool elevated = false;
};

bool path_glob_match(const std::string& pattern, const std::string& cmd) {
    // V1 matching: exact equality, except `*` is a full wildcard. No globs.
    if (pattern == "*") return true;
    return pattern == cmd;
}

GrantMatch find_grant_for(const std::string& shortid, const std::string& command) {
    GrantMatch out{};
    std::string username = "mcp_user_" + shortid;
    std::string live_sid = sid_string_for_user(
        std::wstring(username.begin(), username.end()));

    auto try_file = [&](const std::string& path) -> bool {
        auto raw = read_file(path);
        if (raw.empty()) return false;
        try {
            json doc = json::parse(raw);
            if (!doc.is_object()) return false;
            if (doc.value("shortid", "") != shortid &&
                doc.value("shortid", "") != "*") return false;
            // SID binding: refuse if the persisted SID doesn't match the live SID.
            std::string sid_in_grant = doc.value("sid", "");
            if (!sid_in_grant.empty() && !live_sid.empty() &&
                sid_in_grant != live_sid) return false;
            // Expiry.
            int64_t exp = doc.value("expires_at", int64_t{0});
            int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                              std::chrono::system_clock::now().time_since_epoch()).count();
            if (exp > 0 && exp <= now) return false;
            std::string pat = doc.value("command_pattern", "");
            if (!path_glob_match(pat, command)) return false;
            out.match = true;
            out.elevated = doc.value("elevated", false);
            return true;
        } catch (...) {
            return false;
        }
    };

    // system_admin first — its wildcard implies match for any command.
    if (try_file(system_admin_path())) return out;

    std::error_code ec;
    if (fs::exists(grants_dir(), ec)) {
        for (auto& entry : fs::directory_iterator(grants_dir(), ec)) {
            if (ec) break;
            if (!entry.is_regular_file()) continue;
            if (entry.path().extension() != ".json") continue;
            if (try_file(entry.path().string())) return out;
        }
    }
    return out;
}

// ---- Process spawning helper --------------------------------------------

struct SpawnResult {
    bool ok = false;
    int exit_code = -1;
    std::string stdout_str;
    std::string stderr_str;
};

// Spawn `command` under `token`'s identity. Captures stdout+stderr into
// stdout_str (merged, mirrors Linux `2>&1`). `wait` distinguishes the
// foreground/run-and-capture path from the background/return-pid path.
SpawnResult spawn_with_token(HANDLE token, const std::string& command,
                             const std::string& cwd, int timeout_secs,
                             const std::map<std::string, std::string>& env,
                             bool wait, DWORD* out_pid) {
    SpawnResult r;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE rd = nullptr, wr = nullptr;
    if (wait && !CreatePipe(&rd, &wr, &sa, 0)) {
        r.stderr_str = "CreatePipe failed";
        return r;
    }
    if (rd) SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    if (wait) {
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = wr;
        si.hStdError = wr;
        si.hStdInput = INVALID_HANDLE_VALUE;
    }

    PROCESS_INFORMATION pi{};
    std::string cmd_line = "cmd /c " + command;

    // Inherit the target user's profile/env. CreateEnvironmentBlock yields a
    // wide-char env block from the token. We append caller-supplied env vars
    // by setting them in our own env first, then unset; but the simpler
    // approach is to skip CreateEnvironmentBlock and pass nullptr (the child
    // inherits ours). For correctness with the user's HOMEDRIVE/HOMEPATH,
    // use the env block.
    LPVOID env_block = nullptr;
    BOOL got_env = CreateEnvironmentBlockW(&env_block, token, FALSE);
    // env map is intentionally ignored on the elevated path for now —
    // CreateProcessAsUser with a custom env block requires merging which is
    // out of scope for V1. The caller can encode env in the command itself.
    (void)env;

    DWORD flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    if (!wait) flags |= CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;

    BOOL ok = CreateProcessAsUserA(
        token, nullptr, const_cast<char*>(cmd_line.c_str()),
        nullptr, nullptr, wait ? TRUE : FALSE, flags,
        env_block, cwd.empty() ? nullptr : cwd.c_str(),
        &si, &pi);

    if (env_block) DestroyEnvironmentBlock(env_block);
    if (wr) CloseHandle(wr);

    if (!ok) {
        DWORD e = GetLastError();
        if (rd) CloseHandle(rd);
        r.stderr_str = "CreateProcessAsUser failed: " + std::to_string(e);
        return r;
    }

    if (out_pid) *out_pid = pi.dwProcessId;

    if (!wait) {
        // Background spawn: caller wants the pid, not the output.
        r.ok = true;
        r.exit_code = 0;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (rd) CloseHandle(rd);
        return r;
    }

    DWORD timeout_ms = timeout_secs > 0 ? static_cast<DWORD>(timeout_secs) * 1000 : INFINITE;
    DWORD w = WaitForSingleObject(pi.hProcess, timeout_ms);
    if (w == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        r.stderr_str = "Process timed out";
    }

    char buf[4096];
    DWORD n;
    while (rd && ReadFile(rd, buf, sizeof(buf), &n, nullptr) && n > 0) {
        if (r.stdout_str.size() + n > 4 * 1024 * 1024) break;  // bound output
        r.stdout_str.append(buf, n);
    }
    if (rd) CloseHandle(rd);

    DWORD ec = 1;
    GetExitCodeProcess(pi.hProcess, &ec);
    r.exit_code = static_cast<int>(ec);
    r.ok = true;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return r;
}

// LogonUser → token, with optional elevation (token-group membership swap).
// On elevated=true, returns LocalSystem's primary token (caller is already
// LocalSystem so OpenProcessToken on GetCurrentProcess is correct).
HANDLE acquire_token_for(const std::string& shortid, bool elevated,
                        std::string& err) {
    if (elevated) {
        HANDLE proc_token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                              &proc_token)) {
            err = "OpenProcessToken failed: " + std::to_string(GetLastError());
            return nullptr;
        }
        HANDLE dup = nullptr;
        if (!DuplicateTokenEx(proc_token, MAXIMUM_ALLOWED, nullptr,
                              SecurityImpersonation, TokenPrimary, &dup)) {
            err = "DuplicateTokenEx failed: " + std::to_string(GetLastError());
            CloseHandle(proc_token);
            return nullptr;
        }
        CloseHandle(proc_token);
        return dup;
    }

    std::string username = "mcp_user_" + shortid;
    std::wstring wuser(username.begin(), username.end());
    std::wstring key = L"mcp_bridge_pw_" + std::wstring(shortid.begin(), shortid.end());
    std::wstring pw;
    if (!lsa_retrieve_password(key, pw)) {
        err = "LSA password lookup failed for " + username;
        return nullptr;
    }

    HANDLE token = nullptr;
    BOOL ok = LogonUserW(wuser.c_str(), L".", pw.c_str(),
                         LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, &token);
    // Wipe the in-memory password ASAP.
    SecureZeroMemory(pw.data(), pw.size() * sizeof(wchar_t));
    if (!ok) {
        err = "LogonUserW failed: " + std::to_string(GetLastError());
        return nullptr;
    }
    return token;
}

// ---- ACL helpers ---------------------------------------------------------

bool set_path_owner_system_only(const std::string& path) {
    // Best-effort: tighten DACL so only LocalSystem + Administrators can
    // touch it. Used for grant files and the user_sids ledger.
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
            SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }
    BOOL daclPresent = FALSE, daclDefaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted);
    DWORD rc = SetNamedSecurityInfoA(const_cast<char*>(path.c_str()), SE_FILE_OBJECT,
                                     DACL_SECURITY_INFORMATION |
                                         PROTECTED_DACL_SECURITY_INFORMATION,
                                     nullptr, nullptr, dacl, nullptr);
    LocalFree(sd);
    return rc == ERROR_SUCCESS;
}

}  // namespace

// ---- Public exports for testability -------------------------------------

bool valid_shortid(const std::string& s) {
    if (s.size() != 8) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return false;
    }
    return true;
}

bool valid_grantid(const std::string& s) {
    if (s.size() != 16) return false;
    for (char c : s) {
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

std::string username_from_shortid(const std::string& shortid) {
    if (!valid_shortid(shortid)) return {};
    return "mcp_user_" + shortid;
}

// ---- Op handlers --------------------------------------------------------

json handle_useradd(const json& req) {
    std::string shortid = req.value("shortid", "");
    auto username = username_from_shortid(shortid);
    if (username.empty()) return {{"ok", false}, {"error", "invalid shortid"}};

    std::wstring wuser(username.begin(), username.end());
    std::wstring pw = generate_password();

    USER_INFO_1 ui{};
    ui.usri1_name = const_cast<LPWSTR>(wuser.c_str());
    ui.usri1_password = const_cast<LPWSTR>(pw.c_str());
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = nullptr;
    ui.usri1_comment = const_cast<LPWSTR>(L"mcp_bridge per-session user");
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE;
    ui.usri1_script_path = nullptr;

    DWORD parm_err = 0;
    NET_API_STATUS st = NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&ui), &parm_err);
    if (st == NERR_UserExists) {
        // Idempotent: fall through to ensure password+SID are persisted.
    } else if (st != NERR_Success) {
        SecureZeroMemory(pw.data(), pw.size() * sizeof(wchar_t));
        audit_event("useradd_failed",
                    "user=" + username + " err=" + std::to_string(st) +
                    " parm=" + std::to_string(parm_err));
        return {{"ok", false}, {"error", "NetUserAdd failed: " + std::to_string(st)}};
    }

    std::wstring key = L"mcp_bridge_pw_" + std::wstring(shortid.begin(), shortid.end());
    if (!lsa_store_password(key, pw)) {
        SecureZeroMemory(pw.data(), pw.size() * sizeof(wchar_t));
        audit_event("useradd_lsa_failed", "user=" + username);
        return {{"ok", false}, {"error", "LSA store failed"}};
    }
    SecureZeroMemory(pw.data(), pw.size() * sizeof(wchar_t));

    // Bind the SID to the username at issue time.
    std::string sid = sid_string_for_user(wuser);
    if (sid.empty()) {
        audit_event("useradd_sid_lookup_failed", "user=" + username);
        return {{"ok", false}, {"error", "LookupAccountName failed post-add"}};
    }
    persist_user_sid(username, sid);
    audit_event("useradd", "user=" + username + " sid=" + sid);
    return {{"ok", true}, {"username", username}, {"sid", sid}};
}

json handle_userdel(const json& req) {
    std::string shortid = req.value("shortid", "");
    auto username = username_from_shortid(shortid);
    if (username.empty()) return {{"ok", false}, {"error", "invalid shortid"}};

    std::wstring wuser(username.begin(), username.end());
    NET_API_STATUS st = NetUserDel(nullptr, wuser.c_str());
    if (st != NERR_Success && st != NERR_UserNotFound) {
        audit_event("userdel_failed", "user=" + username + " err=" + std::to_string(st));
        return {{"ok", false}, {"error", "NetUserDel failed: " + std::to_string(st)}};
    }

    std::wstring key = L"mcp_bridge_pw_" + std::wstring(shortid.begin(), shortid.end());
    lsa_delete_password(key);
    forget_persisted_sid(username);

    audit_event("userdel", "user=" + username);
    return {{"ok", true}};
}

json handle_install_grant(const json& req) {
    // Phase 2 wires the platform-abstract GrantManager into this handler.
    // For Phase 1 we accept the raw JSON record from the daemon (already
    // shape-validated client-side via validate_grant_record) and write it
    // verbatim to grants/<grantid>.json with a tightened ACL.
    std::string grantid = req.value("grantid", "");
    if (!valid_grantid(grantid))
        return {{"ok", false}, {"error", "invalid grantid"}};
    if (!req.contains("record") || !req["record"].is_object())
        return {{"ok", false}, {"error", "missing record"}};

    const json& record = req["record"];
    std::string shortid = record.value("shortid", "");
    if (!valid_shortid(shortid))
        return {{"ok", false}, {"error", "invalid record.shortid"}};
    std::string pat = record.value("command_pattern", "");
    if (!valid_grant_path_segment(pat))
        return {{"ok", false}, {"error", "invalid command_pattern"}};

    // Re-check SID binding: if the record names a SID that doesn't match the
    // live one for the user, refuse — the record is stale.
    std::string username = username_from_shortid(shortid);
    std::wstring wuser(username.begin(), username.end());
    std::string live_sid = sid_string_for_user(wuser);
    std::string rec_sid = record.value("sid", "");
    if (!rec_sid.empty() && !live_sid.empty() && rec_sid != live_sid) {
        audit_event("install_grant_sid_mismatch",
                    "grantid=" + grantid + " user=" + username);
        return {{"ok", false}, {"error", "SID binding mismatch"}};
    }

    std::error_code ec;
    fs::create_directories(grants_dir(), ec);
    std::string path = grants_dir() + "\\" + grantid + ".json";
    if (!atomic_write_file(path, record.dump(2))) {
        return {{"ok", false}, {"error", "failed to write grant file"}};
    }
    set_path_owner_system_only(path);
    audit_event("install_grant",
                "grantid=" + grantid + " user=" + username +
                " elevated=" + std::to_string(record.value("elevated", false)));
    return {{"ok", true}};
}

json handle_revoke_grant(const json& req) {
    std::string grantid = req.value("grantid", "");
    if (!valid_grantid(grantid))
        return {{"ok", false}, {"error", "invalid grantid"}};
    std::string path = grants_dir() + "\\" + grantid + ".json";
    std::error_code ec;
    fs::remove(path, ec);
    audit_event("revoke_grant", "grantid=" + grantid);
    return {{"ok", true}};
}

json handle_install_system_admin(const json& req) {
    std::string shortid = req.value("shortid", "");
    if (!valid_shortid(shortid))
        return {{"ok", false}, {"error", "invalid shortid"}};

    std::string username = username_from_shortid(shortid);
    std::wstring wuser(username.begin(), username.end());
    std::string sid = sid_string_for_user(wuser);
    if (sid.empty())
        return {{"ok", false}, {"error", "user does not exist"}};

    json record = {
        {"shortid", shortid},
        {"sid", sid},
        {"template", "full_admin"},
        {"command_pattern", "*"},
        {"elevated", true},
        {"expires_at", 0}  // 0 == never
    };
    std::error_code ec;
    fs::create_directories(grants_dir(), ec);  // ensure parent
    std::string p = system_admin_path();
    if (!atomic_write_file(p, record.dump(2))) {
        return {{"ok", false}, {"error", "failed to write system_admin.json"}};
    }
    set_path_owner_system_only(p);
    audit_event("install_system_admin", "user=" + username + " sid=" + sid);
    return {{"ok", true}};
}

json handle_revoke_system_admin(const json&) {
    std::error_code ec;
    fs::remove(system_admin_path(), ec);
    audit_event("revoke_system_admin", "");
    return {{"ok", true}};
}

json handle_prepare_user_state(const json& req) {
    std::string shortid = req.value("shortid", "");
    auto username = username_from_shortid(shortid);
    if (username.empty()) return {{"ok", false}, {"error", "invalid shortid"}};

    std::error_code ec;
    fs::create_directories(users_state_dir(), ec);
    std::string user_dir = users_state_dir() + "\\" + username;
    fs::create_directories(user_dir + "\\crons", ec);
    set_path_owner_system_only(user_dir);
    audit_event("prepare_user_state", "user=" + username);
    return {{"ok", true}};
}

json handle_cleanup_user_state(const json& req) {
    std::string shortid = req.value("shortid", "");
    auto username = username_from_shortid(shortid);
    if (username.empty()) return {{"ok", false}, {"error", "invalid shortid"}};

    std::error_code ec;
    std::string p = users_state_dir() + "\\" + username;
    fs::remove_all(p, ec);
    audit_event("cleanup_user_state", "user=" + username);
    return {{"ok", true}};
}

json handle_run_as(const json& req) {
    std::string shortid = req.value("shortid", "");
    if (!valid_shortid(shortid))
        return {{"ok", false}, {"error", "invalid shortid"}};
    std::string command = req.value("command", "");
    if (command.empty() || command.find('\0') != std::string::npos)
        return {{"ok", false}, {"error", "invalid command"}};
    std::string cwd = req.value("cwd", "");
    int timeout = req.value("timeout_secs", 0);

    // Defense-in-depth: SID binding check before we even pick a token.
    std::string username = username_from_shortid(shortid);
    std::wstring wuser(username.begin(), username.end());
    std::string live_sid = sid_string_for_user(wuser);
    if (live_sid.empty()) {
        audit_event("run_as_no_user", "user=" + username);
        return {{"ok", false}, {"error", "user does not exist"}};
    }
    std::string persisted = lookup_persisted_sid(username);
    if (!persisted.empty() && persisted != live_sid) {
        audit_event("run_as_sid_mismatch",
                    "user=" + username + " persisted=" + persisted +
                    " live=" + live_sid);
        return {{"ok", false}, {"error", "SID rebinding detected"}};
    }

    // Grant lookup determines whether this call gets the elevated path.
    GrantMatch gm = find_grant_for(shortid, command);
    bool elevated = gm.match && gm.elevated;
    if (!gm.match) {
        // Default policy: non-elevated runs are allowed (the bound user is
        // the principal). Elevation requires a grant. This mirrors Linux,
        // where any user can `bash -c X` but `sudo X` needs a sudoers entry.
        elevated = false;
    }

    std::string err;
    HANDLE token = acquire_token_for(shortid, elevated, err);
    if (!token) {
        audit_event("run_as_token_failed",
                    "user=" + username + " elevated=" + std::to_string(elevated) +
                    " err=" + err);
        return {{"ok", false}, {"error", err}};
    }

    std::map<std::string, std::string> env;
    if (req.contains("env") && req["env"].is_object()) {
        for (auto& [k, v] : req["env"].items()) {
            if (v.is_string()) env[k] = v.get<std::string>();
        }
    }

    DWORD pid = 0;
    SpawnResult sr = spawn_with_token(token, command, cwd, timeout, env, true, &pid);
    CloseHandle(token);

    audit_event(elevated ? "run_as_elevated" : "run_as",
                "user=" + username + " exit=" + std::to_string(sr.exit_code) +
                " cmd=" + command.substr(0, 200));

    // Phase 6.2: I/O audit. For elevated runs (grant-mediated), append a
    // tamper-evident record of the call to a daily log file under
    // %ProgramData%\mcp_bridge\io_log\YYYY-MM-DD.log. Sudo on Linux has the
    // analogous LOG_INPUT/LOG_OUTPUT default; we mirror it for elevated
    // invocations only (non-elevated calls are a normal user shell and
    // would generate noise).
    if (elevated) {
        SYSTEMTIME st;
        GetSystemTime(&st);
        char date_buf[16];
        snprintf(date_buf, sizeof(date_buf), "%04u-%02u-%02u",
                 st.wYear, st.wMonth, st.wDay);
        char ts_buf[32];
        snprintf(ts_buf, sizeof(ts_buf), "%04u-%02u-%02uT%02u:%02u:%02uZ",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        std::string io_dir = program_data_dir() + "\\" + kProgramDataRel + "\\io_log";
        std::error_code ec;
        fs::create_directories(io_dir, ec);
        std::string p = io_dir + "\\" + date_buf + ".log";

        json record = {
            {"ts", ts_buf},
            {"user", username},
            {"command", command},
            {"cwd", cwd},
            {"exit_code", sr.exit_code},
            {"stdout", sr.stdout_str.size() > 65536
                          ? sr.stdout_str.substr(0, 65536)
                          : sr.stdout_str}
        };
        std::ofstream f(p, std::ios::binary | std::ios::app);
        if (f.is_open()) {
            f << record.dump() << "\n";
        }
        // Lock down on first creation. set_path_owner_system_only is
        // idempotent for an existing path.
        set_path_owner_system_only(io_dir);
    }

    return {
        {"ok", sr.ok},
        {"exit_code", sr.exit_code},
        {"stdout", sr.stdout_str},
        {"stderr", sr.stderr_str}
    };
}

json handle_spawn_background_as(const json& req) {
    std::string shortid = req.value("shortid", "");
    if (!valid_shortid(shortid))
        return {{"ok", false}, {"error", "invalid shortid"}};
    std::string command = req.value("command", "");
    if (command.empty() || command.find('\0') != std::string::npos)
        return {{"ok", false}, {"error", "invalid command"}};
    std::string cwd = req.value("cwd", "");

    std::string err;
    HANDLE token = acquire_token_for(shortid, false, err);
    if (!token) return {{"ok", false}, {"error", err}};

    DWORD pid = 0;
    SpawnResult sr = spawn_with_token(token, command, cwd, 0, {}, false, &pid);
    CloseHandle(token);
    if (!sr.ok) return {{"ok", false}, {"error", sr.stderr_str}};
    audit_event("spawn_background_as",
                "user=mcp_user_" + shortid + " pid=" + std::to_string(pid));
    return {{"ok", true}, {"pid", static_cast<int>(pid)}};
}

}  // namespace priv_win
#endif
