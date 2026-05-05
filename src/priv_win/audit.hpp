#pragma once
#ifdef _WIN32
#include <string>

namespace priv_win {

// Writes a structured audit line to the Windows Event Log under source
// `MCP-Bridge-Priv`. Best-effort — if the source isn't registered, falls back
// to OutputDebugStringA so events still surface in DebugView during dev. Every
// privileged operation handled by the priv service should call this.
//
// `event` is a short tag (e.g. "useradd", "run_as_denied"); `detail` is a
// free-form one-liner. Newlines in `detail` are stripped to keep the event
// log tidy.
void audit_event(const std::string& event, const std::string& detail);

// Registers the event source. Called from the service's installer / on first
// run; safe to call repeatedly. Requires admin (registry HKLM write).
bool register_event_source();

}  // namespace priv_win
#endif
