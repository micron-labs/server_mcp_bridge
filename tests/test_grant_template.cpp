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

TEST_MAIN
