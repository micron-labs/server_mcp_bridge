#include "core/grant_template.hpp"
#include <regex>
#include <stdexcept>

namespace {

bool valid_shortid(const std::string& s) {
    if (s.size() != 8) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return false;
    }
    return true;
}

bool valid_template_name(const std::string& s) {
    if (s.empty() || s.size() > 32) return false;
    if (!(s[0] >= 'a' && s[0] <= 'z')) return false;
    for (size_t i = 1; i < s.size(); ++i) {
        char c = s[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

// Extract a {placeholder} name if `piece` is exactly that, else empty string.
std::string placeholder_of(const std::string& piece) {
    if (piece.size() < 3) return "";
    if (piece.front() != '{' || piece.back() != '}') return "";
    return piece.substr(1, piece.size() - 2);
}

// Conservative whitelist for arg values that get embedded in the sudoers
// command spec. Sudoers parses Cmnd_Spec by whitespace, so disallow
// anything that could change command shape.
bool arg_value_charset_ok(const std::string& v) {
    if (v.empty()) return false;
    for (char c : v) {
        bool ok = std::isalnum(static_cast<unsigned char>(c)) ||
                  c == '_' || c == '.' || c == '+' || c == '/' ||
                  c == '=' || c == ':' || c == '@' || c == ',' || c == '-';
        if (!ok) return false;
    }
    return true;
}

}

std::vector<GrantTemplate> parse_templates(const json& doc) {
    std::vector<GrantTemplate> out;
    if (!doc.is_array()) return out;

    for (const auto& entry : doc) {
        if (!entry.is_object()) continue;
        GrantTemplate t;
        t.name = entry.value("name", "");
        t.description = entry.value("description", "");
        t.binary = entry.value("binary", "");

        if (!valid_template_name(t.name)) {
            throw std::runtime_error("grant_template: invalid name '" + t.name + "'");
        }
        if (t.binary.empty() || t.binary[0] != '/') {
            throw std::runtime_error("grant_template '" + t.name +
                                     "': binary must be an absolute path");
        }

        if (entry.contains("argv") && entry["argv"].is_array()) {
            for (const auto& piece : entry["argv"]) {
                if (piece.is_string()) t.argv.push_back(piece.get<std::string>());
            }
        }
        if (entry.contains("params") && entry["params"].is_object()) {
            for (auto it = entry["params"].begin(); it != entry["params"].end(); ++it) {
                if (it->is_string()) t.params[it.key()] = it->get<std::string>();
            }
        }

        out.push_back(std::move(t));
    }
    return out;
}

std::string validate_captured_args(const GrantTemplate& tmpl, const json& captured_args) {
    if (!captured_args.is_object()) return "captured_args must be a JSON object";

    // Every {placeholder} in argv must have a matching captured value;
    // every captured value must charset-match its param regex.
    for (const auto& piece : tmpl.argv) {
        auto ph = placeholder_of(piece);
        if (ph.empty()) continue;
        auto p_it = tmpl.params.find(ph);
        if (p_it == tmpl.params.end()) {
            return "template missing 'params." + ph + "' regex";
        }
        if (!captured_args.contains(ph)) {
            return "missing captured arg '" + ph + "'";
        }
        if (!captured_args[ph].is_string()) {
            return "captured arg '" + ph + "' must be a string";
        }
        const auto& v = captured_args[ph].get_ref<const std::string&>();
        if (!arg_value_charset_ok(v)) {
            return "captured arg '" + ph + "' contains disallowed characters";
        }
        try {
            std::regex re(p_it->second);
            if (!std::regex_match(v, re)) {
                return "captured arg '" + ph + "' does not match template regex";
            }
        } catch (const std::regex_error&) {
            return "template regex for '" + ph + "' is malformed";
        }
    }
    return "";
}

std::string render_command(const GrantTemplate& tmpl, const json& captured_args) {
    auto err = validate_captured_args(tmpl, captured_args);
    if (!err.empty()) throw std::runtime_error("grant_template: " + err);

    std::string cmd = tmpl.binary;
    for (const auto& piece : tmpl.argv) {
        cmd.push_back(' ');
        auto ph = placeholder_of(piece);
        if (ph.empty()) {
            // Literal piece — also charset-checked so the template author
            // can't slip in metacharacters.
            if (!arg_value_charset_ok(piece)) {
                throw std::runtime_error("grant_template '" + tmpl.name +
                                         "': literal argv piece has disallowed chars");
            }
            cmd += piece;
        } else {
            cmd += captured_args[ph].get_ref<const std::string&>();
        }
    }
    return cmd;
}

std::string render_sudoers_spec(const std::string& shortid,
                                const GrantTemplate& tmpl,
                                const json& captured_args) {
    if (!valid_shortid(shortid)) {
        throw std::runtime_error("grant_template: invalid shortid '" + shortid + "'");
    }
    return "mcp_user_" + shortid + " ALL=(root) NOPASSWD: " +
           render_command(tmpl, captured_args) + "\n";
}

std::string render_full_admin_spec(const std::string& shortid) {
    if (!valid_shortid(shortid)) {
        throw std::runtime_error("grant_template: invalid shortid '" + shortid + "'");
    }
    return "mcp_user_" + shortid + " ALL=(ALL) NOPASSWD: ALL\n";
}

namespace {

bool valid_grantid_hex(const std::string& s) {
    if (s.size() != 16) return false;
    for (char c : s) {
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!ok) return false;
    }
    return true;
}

// Lightweight sanity check on a SID string. We don't try to parse the
// full SDDL grammar — just that it looks like `S-1-5-...`.
bool plausible_sid(const std::string& s) {
    if (s.size() < 6 || s.size() > 256) return false;
    if (s[0] != 'S' && s[0] != 's') return false;
    if (s[1] != '-' || s[2] != '1' || s[3] != '-') return false;
    for (char c : s) {
        bool ok = (c >= '0' && c <= '9') || c == 'S' || c == 's' || c == '-';
        if (!ok) return false;
    }
    return true;
}

}  // namespace

json render_windows_grant_record(const std::string& grantid,
                                 const std::string& shortid,
                                 const std::string& sid,
                                 const GrantTemplate& tmpl,
                                 const json& captured_args,
                                 int64_t expires_at) {
    if (!valid_grantid_hex(grantid))
        throw std::runtime_error("grant_template: invalid grantid");
    if (!valid_shortid(shortid))
        throw std::runtime_error("grant_template: invalid shortid");
    if (!sid.empty() && !plausible_sid(sid))
        throw std::runtime_error("grant_template: malformed sid");

    // Reuse the per-command renderer for the command_pattern body — same
    // charset checks apply, so a malicious template author can't slip
    // metacharacters past validate_captured_args.
    std::string command = render_command(tmpl, captured_args);
    json record = {
        {"grantid", grantid},
        {"shortid", shortid},
        {"sid", sid},
        {"template", tmpl.name},
        {"command_pattern", command},
        {"elevated", true},
        {"expires_at", expires_at}
    };
    auto err = validate_grant_record(record);
    if (!err.empty()) throw std::runtime_error("grant_template: " + err);
    return record;
}

json render_windows_full_admin_record(const std::string& grantid,
                                      const std::string& shortid,
                                      const std::string& sid,
                                      int64_t expires_at) {
    if (!valid_grantid_hex(grantid))
        throw std::runtime_error("grant_template: invalid grantid");
    if (!valid_shortid(shortid))
        throw std::runtime_error("grant_template: invalid shortid");
    if (!sid.empty() && !plausible_sid(sid))
        throw std::runtime_error("grant_template: malformed sid");

    json record = {
        {"grantid", grantid},
        {"shortid", shortid},
        {"sid", sid},
        {"template", kFullAdminTemplate},
        {"command_pattern", "*"},
        {"elevated", true},
        {"expires_at", expires_at}
    };
    auto err = validate_grant_record(record);
    if (!err.empty()) throw std::runtime_error("grant_template: " + err);
    return record;
}

std::string validate_grant_record(const json& record) {
    if (!record.is_object()) return "record must be a JSON object";

    auto sval = [&](const char* k) -> std::string {
        if (!record.contains(k)) return "";
        if (!record[k].is_string()) return "";
        return record[k].get<std::string>();
    };

    if (!valid_grantid_hex(sval("grantid"))) return "invalid or missing grantid";
    if (!valid_shortid(sval("shortid"))) return "invalid or missing shortid";

    // SID may be empty in test contexts; if present, sanity-check it.
    std::string sid = sval("sid");
    if (!sid.empty() && !plausible_sid(sid)) return "malformed sid";

    std::string tmpl = sval("template");
    if (tmpl.empty() || tmpl.size() > 32) return "missing template";

    std::string pat = sval("command_pattern");
    if (pat.empty() || pat.size() > 4096) return "missing command_pattern";
    if (pat.find('\0') != std::string::npos) return "command_pattern has NUL";
    if (pat.find('\n') != std::string::npos) return "command_pattern has newline";

    if (!record.contains("elevated") || !record["elevated"].is_boolean())
        return "missing elevated";

    if (record.contains("expires_at") && !record["expires_at"].is_number_integer())
        return "expires_at must be integer";

    // V1 matching: only `*` (wildcard) or an absolute path is allowed.
    if (pat != "*") {
        // First non-space char must be `/` (POSIX abs) or `<letter>:` (Windows abs).
        auto first_non_space = pat.find_first_not_of(' ');
        if (first_non_space == std::string::npos) return "command_pattern empty";
        char c = pat[first_non_space];
        bool posix_abs = (c == '/');
        bool win_abs   = (pat.size() > first_non_space + 2 &&
                          ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) &&
                          pat[first_non_space + 1] == ':' &&
                          (pat[first_non_space + 2] == '\\' ||
                           pat[first_non_space + 2] == '/'));
        if (!posix_abs && !win_abs) return "command_pattern must be absolute or '*'";
    }
    return "";
}

bool spec_is_well_formed(const std::string& spec) {
    // Single line + trailing newline, < 4 KiB.
    if (spec.empty() || spec.size() > 4096) return false;
    if (spec.back() != '\n') return false;
    if (spec.find('\n') != spec.size() - 1) return false;

    // Charset: printable ASCII plus space, plus the trailing newline.
    for (size_t i = 0; i + 1 < spec.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(spec[i]);
        if (c < 0x20 || c > 0x7e) return false;
    }

    // Prefix + shortid: shared between both accepted forms.
    static const std::string prefix_a = "mcp_user_";
    if (spec.compare(0, prefix_a.size(), prefix_a) != 0) return false;
    if (spec.size() < prefix_a.size() + 8) return false;
    for (size_t i = 0; i < 8; ++i) {
        char c = spec[prefix_a.size() + i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return false;
    }

    const size_t after_id = prefix_a.size() + 8;

    // Per-command form: `... NOPASSWD: /<absolute-path>`. visudo -cf is the
    // authoritative validator for the trailing command spec.
    static const std::string path_mid = " ALL=(root) NOPASSWD: /";
    if (spec.size() - after_id >= path_mid.size() &&
        spec.compare(after_id, path_mid.size(), path_mid) == 0) {
        return true;
    }

    // full_admin form: must match exactly, no trailing command path.
    static const std::string wildcard_tail = " ALL=(ALL) NOPASSWD: ALL\n";
    if (spec.size() == after_id + wildcard_tail.size() &&
        spec.compare(after_id, wildcard_tail.size(), wildcard_tail) == 0) {
        return true;
    }

    return false;
}
