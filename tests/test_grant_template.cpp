#include "test_framework.hpp"
#include "core/grant_template.hpp"

namespace {

GrantTemplate make_systemctl_restart() {
    GrantTemplate t;
    t.name = "systemctl_restart";
    t.binary = "/usr/bin/systemctl";
    t.argv = {"restart", "{service}"};
    t.params = {{"service", "^[a-z0-9._-]+$"}};
    return t;
}

}

TEST(parse_valid_template_array) {
    json doc = json::array({
        {{"name","systemctl_restart"},
         {"binary","/usr/bin/systemctl"},
         {"argv", json::array({"restart","{service}"})},
         {"params",{{"service","^[a-z]+$"}}}}
    });
    auto ts = parse_templates(doc);
    ASSERT_EQ(ts.size(), std::size_t{1});
    ASSERT_EQ(ts[0].name, std::string("systemctl_restart"));
    ASSERT_EQ(ts[0].binary, std::string("/usr/bin/systemctl"));
    ASSERT_EQ(ts[0].argv.size(), std::size_t{2});
    ASSERT_EQ(ts[0].params.at("service"), std::string("^[a-z]+$"));
}

TEST(parse_rejects_invalid_template_name) {
    json doc = json::array({
        {{"name","Bad-Name"},{"binary","/x"},
         {"argv",json::array()},{"params",json::object()}}
    });
    ASSERT_THROWS(parse_templates(doc));
}

TEST(parse_rejects_relative_binary_path) {
    json doc = json::array({
        {{"name","x"},{"binary","systemctl"},
         {"argv",json::array()},{"params",json::object()}}
    });
    ASSERT_THROWS(parse_templates(doc));
}

TEST(parse_returns_empty_for_non_array) {
    auto ts = parse_templates(json::object());
    ASSERT_EQ(ts.size(), std::size_t{0});
}

TEST(render_substitutes_placeholders) {
    auto t = make_systemctl_restart();
    auto cmd = render_command(t, {{"service","nginx"}});
    ASSERT_EQ(cmd, std::string("/usr/bin/systemctl restart nginx"));
}

TEST(render_rejects_charset_violation) {
    // `;` is shell-meta; the charset check rejects it even if the regex would allow.
    auto t = make_systemctl_restart();
    t.params["service"] = "^[a-z;]+$";
    ASSERT_THROWS(render_command(t, {{"service","ng;rm"}}));
}

TEST(render_rejects_regex_mismatch) {
    auto t = make_systemctl_restart();
    ASSERT_THROWS(render_command(t, {{"service","HasUppercase"}}));
}

TEST(render_rejects_missing_arg) {
    auto t = make_systemctl_restart();
    ASSERT_THROWS(render_command(t, json::object()));
}

TEST(render_rejects_non_object_args) {
    auto t = make_systemctl_restart();
    ASSERT_THROWS(render_command(t, json::array({"nginx"})));
}

TEST(render_sudoers_spec_full_line) {
    auto t = make_systemctl_restart();
    auto spec = render_sudoers_spec("abc23456", t, {{"service","nginx"}});
    ASSERT_EQ(spec,
              std::string("mcp_user_abc23456 ALL=(root) NOPASSWD: "
                          "/usr/bin/systemctl restart nginx\n"));
}

TEST(render_sudoers_spec_rejects_bad_shortid) {
    auto t = make_systemctl_restart();
    ASSERT_THROWS(render_sudoers_spec("BAD", t, {{"service","nginx"}}));
    ASSERT_THROWS(render_sudoers_spec("abc12def", t, {{"service","nginx"}}));  // '1' invalid
}

TEST(spec_well_formed_accepts_canonical) {
    std::string spec =
        "mcp_user_abcdefgh ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx\n";
    ASSERT(spec_is_well_formed(spec));
}

TEST(spec_well_formed_rejects_embedded_newline) {
    std::string spec =
        "mcp_user_abcdefgh ALL=(root) NOPASSWD: /a\n"
        "mcp_user_evil ALL=(root) NOPASSWD: /b\n";
    ASSERT(!spec_is_well_formed(spec));
}

TEST(spec_well_formed_rejects_no_trailing_newline) {
    std::string spec =
        "mcp_user_abcdefgh ALL=(root) NOPASSWD: /usr/bin/systemctl restart nginx";
    ASSERT(!spec_is_well_formed(spec));
}

TEST(spec_well_formed_rejects_bad_prefix) {
    std::string spec = "root ALL=(ALL:ALL) NOPASSWD: /usr/bin/anything\n";
    ASSERT(!spec_is_well_formed(spec));
}

TEST(spec_well_formed_rejects_uppercase_shortid) {
    std::string spec = "mcp_user_ABCDEFGH ALL=(root) NOPASSWD: /x\n";
    ASSERT(!spec_is_well_formed(spec));
}

TEST(spec_well_formed_rejects_oversized_input) {
    std::string spec(8192, 'x');
    spec.back() = '\n';
    ASSERT(!spec_is_well_formed(spec));
}

TEST(spec_well_formed_rejects_command_not_absolute) {
    std::string spec = "mcp_user_abcdefgh ALL=(root) NOPASSWD: systemctl\n";
    ASSERT(!spec_is_well_formed(spec));
}

TEST(render_full_admin_spec_emits_wildcard_line) {
    auto spec = render_full_admin_spec("abc23456");
    ASSERT_EQ(spec, std::string("mcp_user_abc23456 ALL=(ALL) NOPASSWD: ALL\n"));
}

TEST(render_full_admin_spec_rejects_bad_shortid) {
    ASSERT_THROWS(render_full_admin_spec("BAD"));
    ASSERT_THROWS(render_full_admin_spec("abc12def"));  // '1' invalid
}

TEST(spec_well_formed_accepts_full_admin) {
    ASSERT(spec_is_well_formed(render_full_admin_spec("abc23456")));
}

TEST(spec_well_formed_rejects_full_admin_with_trailing_garbage) {
    std::string spec = "mcp_user_abc23456 ALL=(ALL) NOPASSWD: ALL extra\n";
    ASSERT(!spec_is_well_formed(spec));
}

TEST(spec_well_formed_rejects_wildcard_with_root_runas) {
    // Only ALL=(ALL) is accepted for the wildcard form.
    std::string spec = "mcp_user_abc23456 ALL=(root) NOPASSWD: ALL\n";
    ASSERT(!spec_is_well_formed(spec));
}

// ---- Windows JSON grant record (Phase 2) -------------------------------

TEST(windows_grant_record_full_admin_shape) {
    auto rec = render_windows_full_admin_record(
        "0123456789abcdef", "abc23456", "S-1-5-21-100-200-300-1001",
        /*expires_at=*/0);
    ASSERT_EQ(rec["grantid"].get<std::string>(), std::string("0123456789abcdef"));
    ASSERT_EQ(rec["shortid"].get<std::string>(), std::string("abc23456"));
    ASSERT_EQ(rec["template"].get<std::string>(), std::string(kFullAdminTemplate));
    ASSERT_EQ(rec["command_pattern"].get<std::string>(), std::string("*"));
    ASSERT(rec["elevated"].get<bool>());
}

TEST(windows_grant_record_per_command_shape) {
    auto t = make_systemctl_restart();
    t.binary = "C:\\Windows\\System32\\sc.exe";
    t.argv = {"start","{service}"};
    t.params = {{"service","^[a-z0-9._-]+$"}};
    auto rec = render_windows_grant_record(
        "fedcba9876543210", "abc23456", "S-1-5-21-100-200-300-1001",
        t, {{"service","nginx"}}, /*expires_at=*/1700000000);
    ASSERT_EQ(rec["command_pattern"].get<std::string>(),
              std::string("C:\\Windows\\System32\\sc.exe start nginx"));
    ASSERT(rec["elevated"].get<bool>());
    ASSERT_EQ(rec["expires_at"].get<int64_t>(), int64_t{1700000000});
}

TEST(windows_grant_record_rejects_bad_grantid) {
    auto t = make_systemctl_restart();
    ASSERT_THROWS(render_windows_grant_record(
        "NOTHEX", "abc23456", "", t, {{"service","nginx"}}, 0));
}

TEST(windows_grant_record_rejects_bad_shortid) {
    auto t = make_systemctl_restart();
    ASSERT_THROWS(render_windows_grant_record(
        "0123456789abcdef", "BAD", "", t, {{"service","nginx"}}, 0));
}

TEST(windows_grant_record_rejects_malformed_sid) {
    auto t = make_systemctl_restart();
    ASSERT_THROWS(render_windows_grant_record(
        "0123456789abcdef", "abc23456", "garbage",
        t, {{"service","nginx"}}, 0));
}

TEST(validate_grant_record_accepts_canonical) {
    json r = {
        {"grantid","0123456789abcdef"},
        {"shortid","abc23456"},
        {"sid","S-1-5-21-100-200-300-1001"},
        {"template","systemctl_restart"},
        {"command_pattern","/usr/bin/systemctl restart nginx"},
        {"elevated", true},
        {"expires_at", 1700000000}
    };
    ASSERT_EQ(validate_grant_record(r), std::string(""));
}

TEST(validate_grant_record_accepts_full_admin_wildcard) {
    json r = {
        {"grantid","0123456789abcdef"},
        {"shortid","abc23456"},
        {"sid",""},
        {"template","full_admin"},
        {"command_pattern","*"},
        {"elevated", true},
        {"expires_at", 0}
    };
    ASSERT_EQ(validate_grant_record(r), std::string(""));
}

TEST(validate_grant_record_accepts_windows_path) {
    json r = {
        {"grantid","0123456789abcdef"},
        {"shortid","abc23456"},
        {"sid",""},
        {"template","sc_start"},
        {"command_pattern","C:\\Windows\\System32\\sc.exe start nginx"},
        {"elevated", true},
        {"expires_at", 0}
    };
    ASSERT_EQ(validate_grant_record(r), std::string(""));
}

TEST(validate_grant_record_rejects_relative_command) {
    json r = {
        {"grantid","0123456789abcdef"},
        {"shortid","abc23456"},
        {"sid",""},
        {"template","x"},
        {"command_pattern","systemctl restart nginx"},
        {"elevated", true},
        {"expires_at", 0}
    };
    ASSERT(!validate_grant_record(r).empty());
}

TEST(validate_grant_record_rejects_missing_elevated) {
    json r = {
        {"grantid","0123456789abcdef"},
        {"shortid","abc23456"},
        {"sid",""},
        {"template","x"},
        {"command_pattern","/usr/bin/x"},
        {"expires_at", 0}
    };
    ASSERT(!validate_grant_record(r).empty());
}

TEST(validate_grant_record_rejects_command_with_newline) {
    json r = {
        {"grantid","0123456789abcdef"},
        {"shortid","abc23456"},
        {"sid",""},
        {"template","x"},
        {"command_pattern","/usr/bin/x\nrm -rf /"},
        {"elevated", true},
        {"expires_at", 0}
    };
    ASSERT(!validate_grant_record(r).empty());
}

TEST_MAIN
