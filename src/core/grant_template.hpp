#pragma once
#include <json.hpp>
#include <map>
#include <string>
#include <vector>

using json = nlohmann::json;

// A `sudo_grant_templates` entry from mcp.json. Defines a fixed binary plus
// an argv pattern with `{placeholder}` slots; each placeholder names a
// `params` regex that captured input must match exactly.
struct GrantTemplate {
    std::string name;
    std::string description;
    std::string binary;                          // absolute path
    std::vector<std::string> argv;               // argv pieces (post-binary), may contain {ph}
    std::map<std::string, std::string> params;  // placeholder name -> POSIX ERE
};

std::vector<GrantTemplate> parse_templates(const json& doc);

// Returns "" on success, an error message on failure.
std::string validate_captured_args(const GrantTemplate& tmpl, const json& captured_args);

// Build the Cmnd_Spec body for a grant: `<binary> <arg1> <arg2> ...`.
// Throws std::runtime_error if validation fails.
std::string render_command(const GrantTemplate& tmpl, const json& captured_args);

// Build the full sudoers line: `mcp_user_<shortid> ALL=(root) NOPASSWD: <command>`.
// Throws std::runtime_error if shortid charset is invalid.
std::string render_sudoers_spec(const std::string& shortid,
                                const GrantTemplate& tmpl,
                                const json& captured_args);

// Reserved template name. Bypasses the per-command argv/params machinery and
// emits an unrestricted sudoers line. Issuance must be gated by an admin role
// check at the call site (see tools/admin/grant_ops.cpp).
constexpr const char* kFullAdminTemplate = "full_admin";

// Build `mcp_user_<shortid> ALL=(ALL) NOPASSWD: ALL\n`. The bound user can
// then sudo any command for the grant's TTL.
std::string render_full_admin_spec(const std::string& shortid);

// Charset / shape check on the spec the helper will install. Accepts either
// the per-command form or the full_admin wildcard form. Defense in depth:
// the helper re-runs an equivalent check before writing to /etc/sudoers.d.
bool spec_is_well_formed(const std::string& spec);

// ---- Windows grant record ----------------------------------------------
//
// Windows has no sudoers; grants are JSON files under
// %ProgramData%\mcp_bridge\grants\<grantid>.json that the priv service
// consults at RunAs time. Same TTL/template/wildcard semantics as Linux.
// `sid` is bound at issue time so a deleted-and-recreated mcp_user_<X>
// (which would receive a fresh SID) cannot inherit old grants.
//
// Returns the JSON body the priv service expects; throws on bad inputs.
//
// Per-command record:
//   {
//     "grantid": "<16hex>",
//     "shortid": "<8base32>",
//     "sid":     "S-1-5-21-...",
//     "template": "<template_name>",
//     "command_pattern": "<binary> <arg> ...",
//     "elevated": true,
//     "expires_at": <unix-seconds>
//   }
//
// full_admin record uses command_pattern="*" and elevated=true.
json render_windows_grant_record(const std::string& grantid,
                                 const std::string& shortid,
                                 const std::string& sid,
                                 const GrantTemplate& tmpl,
                                 const json& captured_args,
                                 int64_t expires_at);

json render_windows_full_admin_record(const std::string& grantid,
                                      const std::string& shortid,
                                      const std::string& sid,
                                      int64_t expires_at);

// Validates the shape of a Windows grant record (the same check the priv
// service applies before installing). Returns "" on success, an error
// message on failure. Cross-platform — testable from Linux.
std::string validate_grant_record(const json& record);
