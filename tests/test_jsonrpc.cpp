#include "test_framework.hpp"
#include "core/jsonrpc.hpp"

TEST(parse_valid_request_with_params) {
    json doc = {{"jsonrpc","2.0"},{"id",7},{"method","tools/list"},
                {"params", {{"foo","bar"}}}};
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(r.has_value());
    ASSERT_EQ(r->method, std::string("tools/list"));
    ASSERT(r->has_id);
    ASSERT_EQ(r->id, 7);
    ASSERT(r->params.is_object());
    ASSERT(!r->is_notification());
}

TEST(parse_notification_no_id) {
    json doc = {{"jsonrpc","2.0"},{"method","notifications/initialized"}};
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(r.has_value());
    ASSERT(r->is_notification());
    ASSERT(!r->has_id);
}

TEST(parse_string_id_ok) {
    json doc = {{"jsonrpc","2.0"},{"id","abc"},{"method","ping"}};
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(r.has_value());
    ASSERT(r->has_id);
}

TEST(reject_batch_request) {
    json doc = json::array();
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(!r.has_value());
    ASSERT_EQ(err["error"]["code"].get<int>(), jsonrpc::kInvalidRequest);
}

TEST(reject_non_object_request) {
    json doc = "not an object";
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(!r.has_value());
    ASSERT_EQ(err["error"]["code"].get<int>(), jsonrpc::kInvalidRequest);
}

TEST(reject_missing_jsonrpc_field) {
    json doc = {{"id",1},{"method","ping"}};
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(!r.has_value());
}

TEST(reject_wrong_jsonrpc_version) {
    json doc = {{"jsonrpc","1.0"},{"id",1},{"method","ping"}};
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(!r.has_value());
}

TEST(reject_missing_method) {
    json doc = {{"jsonrpc","2.0"},{"id",1}};
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(!r.has_value());
}

TEST(reject_non_string_method) {
    json doc = {{"jsonrpc","2.0"},{"id",1},{"method",42}};
    json err;
    auto r = jsonrpc::parse_request(doc, err);
    ASSERT(!r.has_value());
}

TEST(make_response_shape) {
    auto r = jsonrpc::make_response(42, json{{"x",1}});
    ASSERT_EQ(r["jsonrpc"], "2.0");
    ASSERT_EQ(r["id"], 42);
    ASSERT_EQ(r["result"]["x"], 1);
    ASSERT(!r.contains("error"));
}

TEST(make_error_shape) {
    auto e = jsonrpc::make_error(nullptr, jsonrpc::kMethodNotFound, "nope");
    ASSERT_EQ(e["jsonrpc"], "2.0");
    ASSERT(e["id"].is_null());
    ASSERT_EQ(e["error"]["code"].get<int>(), jsonrpc::kMethodNotFound);
    ASSERT_EQ(e["error"]["message"], "nope");
    ASSERT(!e.contains("result"));
}

TEST(error_codes_have_expected_values) {
    // Per JSON-RPC 2.0 spec.
    ASSERT_EQ(jsonrpc::kParseError,     -32700);
    ASSERT_EQ(jsonrpc::kInvalidRequest, -32600);
    ASSERT_EQ(jsonrpc::kMethodNotFound, -32601);
    ASSERT_EQ(jsonrpc::kInvalidParams,  -32602);
    ASSERT_EQ(jsonrpc::kInternalError,  -32603);
}

TEST_MAIN
