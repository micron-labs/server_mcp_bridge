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

    // Shape: must start with `mcp_user_<8 charset chars> ALL=(root) NOPASSWD: /`
    static const std::string prefix_a = "mcp_user_";
    if (spec.compare(0, prefix_a.size(), prefix_a) != 0) return false;
    if (spec.size() < prefix_a.size() + 8) return false;
    for (size_t i = 0; i < 8; ++i) {
        char c = spec[prefix_a.size() + i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return false;
    }
    static const std::string mid = " ALL=(root) NOPASSWD: /";
    if (spec.compare(prefix_a.size() + 8, mid.size(), mid) != 0) return false;

    return true;
}
