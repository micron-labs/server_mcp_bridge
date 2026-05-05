#ifdef _WIN32
#include "priv_win/audit.hpp"
#include <windows.h>
#include <string>

namespace priv_win {

namespace {

constexpr const char* kSourceName = "MCP-Bridge-Priv";
constexpr const char* kRegPath =
    "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\MCP-Bridge-Priv";

std::string strip_newlines(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out += (c == '\r' || c == '\n') ? ' ' : c;
    return out;
}

}  // namespace

bool register_event_source() {
    HKEY key;
    LONG rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, kRegPath, 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr,
                              &key, nullptr);
    if (rc != ERROR_SUCCESS) return false;

    // No custom .mc file — point at the system message DLL so ReportEventA
    // text lands in the event description verbatim instead of as an unknown
    // message id. This is the convention for service event sources that
    // don't ship a message resource.
    char dll_path[MAX_PATH];
    UINT len = GetSystemDirectoryA(dll_path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH - 32) {
        RegCloseKey(key);
        return false;
    }
    std::string dll = std::string(dll_path) + "\\EventCreate.exe";
    DWORD types = EVENTLOG_INFORMATION_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_ERROR_TYPE;

    RegSetValueExA(key, "EventMessageFile", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(dll.c_str()),
                   static_cast<DWORD>(dll.size() + 1));
    RegSetValueExA(key, "TypesSupported", 0, REG_DWORD,
                   reinterpret_cast<const BYTE*>(&types), sizeof(types));
    RegCloseKey(key);
    return true;
}

void audit_event(const std::string& event, const std::string& detail) {
    HANDLE h = RegisterEventSourceA(nullptr, kSourceName);
    std::string line = "event=" + event + " " + strip_newlines(detail);
    if (!h) {
        OutputDebugStringA(line.c_str());
        return;
    }
    const char* strs[1] = { line.c_str() };
    ReportEventA(h, EVENTLOG_INFORMATION_TYPE, 0, 1000, nullptr,
                 1, 0, strs, nullptr);
    DeregisterEventSource(h);
}

}  // namespace priv_win
#endif
