#pragma once
#ifdef _WIN32

#include "platform/platform.hpp"
#include <json.hpp>
#include <map>
#include <string>

// Marker used by the build-time guard in process_windows.cpp to assert that
// the production Windows build links against the priv-pipe client. Including
// this header from process_windows.cpp is what flips the guard off.
#define MCP_BRIDGE_PRIV_PIPE_CLIENT 1

using json = nlohmann::json;

namespace priv_client {

// Connects to \\.\pipe\mcp_bridge_priv, sends one JSON line, reads one JSON
// line response, closes. Synchronous. Returns the parsed response on success.
// On wire-level failure (cannot connect, malformed response), returns a
// stand-in {"ok": false, "error": "..."} so callers don't need to distinguish.
//
// Connection failure should be visible — the priv service must be running for
// the daemon to be useful. The error string includes the Win32 error code.
json call(const json& request);

// Convenience wrappers used by process_windows.cpp.
ProcessResult run_as(const std::string& shortid,
                     const std::string& command,
                     const std::string& cwd,
                     int timeout_secs,
                     const std::map<std::string, std::string>& env);

int spawn_background_as(const std::string& shortid,
                        const std::string& command,
                        const std::string& cwd);

// Translate the Windows OS-username form (`mcp_user_<shortid>`) used by the
// auth layer into the bare `<shortid>` the priv service expects. Returns "" if
// the username doesn't match the expected shape.
std::string shortid_from_username(const std::string& os_username);

}  // namespace priv_client

#endif
