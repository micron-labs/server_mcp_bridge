#pragma once

// Wire protocol shared between mcp_bridge.exe (client) and mcp_bridge_priv.exe
// (server). The server is a separate Windows Service running as LocalSystem;
// the client is the daemon, running as the virtual service account
// `NT SERVICE\mcp_bridge`. They speak line-delimited JSON over a named pipe.
//
// The pipe ACL only admits connections from the daemon's service SID; see
// src/priv_win/main.cpp.
//
// This header is intentionally Win32-free so it can be included from anywhere
// without dragging windows.h into the build.

namespace priv_win {

// Pipe path. UNC form `\\.\pipe\mcp_bridge_priv` is the only one Windows
// accepts for local named pipes.
inline constexpr const char* kPipePath = "\\\\.\\pipe\\mcp_bridge_priv";

// Op names. Mirror the Linux helper subcommands one-to-one where possible.
namespace op {
inline constexpr const char* kUserAdd               = "useradd";
inline constexpr const char* kUserDel               = "userdel";
inline constexpr const char* kInstallGrant          = "install_grant";
inline constexpr const char* kRevokeGrant           = "revoke_grant";
inline constexpr const char* kInstallSystemAdmin    = "install_system_admin";
inline constexpr const char* kRevokeSystemAdmin     = "revoke_system_admin";
inline constexpr const char* kPrepareUserState      = "prepare_user_state";
inline constexpr const char* kCleanupUserState      = "cleanup_user_state";
inline constexpr const char* kRunAs                 = "run_as";
inline constexpr const char* kSpawnBackgroundAs     = "spawn_background_as";
}  // namespace op

// Single read/write message size cap. Keeps the parser bounded; commands the
// daemon issues are short. Captured stdout in responses is bounded by
// kMaxResponseBytes.
inline constexpr unsigned kMaxRequestBytes  = 64 * 1024;
inline constexpr unsigned kMaxResponseBytes = 4 * 1024 * 1024;

}  // namespace priv_win
