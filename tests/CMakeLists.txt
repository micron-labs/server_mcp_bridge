# Each test executable links the static `mcp_bridge_core` so it sees the same
# compiled units as the daemon binary. Tests use the in-tree minimal framework
# in tests/test_framework.hpp — no external test deps.

set(MCP_TESTS
    test_crypto
    test_shortid
    test_jsonrpc
    test_session
    test_grant_template
    test_user_store
    test_cron_store
)

foreach(t IN LISTS MCP_TESTS)
    add_executable(${t} ${t}.cpp)
    target_link_libraries(${t} PRIVATE mcp_bridge_core)
    target_include_directories(${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_options(${t} PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME ${t} COMMAND ${t})
endforeach()
