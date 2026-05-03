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

// Charset / shape check on the spec the helper will install. Defense in
// depth: the helper re-runs this before writing to /etc/sudoers.d.
bool spec_is_well_formed(const std::string& spec);
