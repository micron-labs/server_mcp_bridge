cmake_minimum_required(VERSION 3.20)
project(mcp_bridge VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_MYSQL "Enable MySQL/MariaDB support" ON)
option(ENABLE_POSTGRES "Enable PostgreSQL support" ON)
option(ENABLE_SSL "Enable HTTPS support" OFF)
option(BUILD_TESTS "Build tests" OFF)

# Everything except `main.cpp` lands in a static library so both the daemon
# binary and the test executables can link the same compiled units.
set(CORE_SOURCES
    src/core/config.cpp
    src/core/server.cpp
    src/core/auth.cpp
    src/core/crypto.cpp
    src/core/rate_limiter.cpp
    src/core/context.cpp
    src/core/logger.cpp
    src/core/user_store.cpp
    src/core/grant_template.cpp
    src/core/grants.cpp
    src/core/cron_store.cpp
    src/core/runtime_sync.cpp
    src/core/jsonrpc.cpp
    src/core/mcp_router.cpp
    src/core/session.cpp
    src/core/shortid.cpp
    src/cli/cli_main.cpp
    src/cli/auth_create.cpp
    src/cli/auth_rotate.cpp
    src/cli/auth_list.cpp
    src/cli/webhook_set.cpp
    src/cli/welcome_banner.cpp
    src/registry/tool_registry.cpp
)

set(TOOL_SOURCES
    src/tools/data/file_ops.cpp
    src/tools/data/database_ops.cpp
    src/tools/networking/port_ops.cpp
    src/tools/networking/firewall_ops.cpp
    src/tools/hosting/webserver_ops.cpp
    src/tools/hosting/process_mgmt.cpp
    src/tools/exec/command_ops.cpp
    src/tools/sandbox/sandbox_ops.cpp
    src/tools/scheduling/cron_ops.cpp
    src/tools/admin/grant_ops.cpp
    src/tools/admin/user_ops.cpp
)

if(WIN32)
    set(PLATFORM_SOURCES
        src/platform/windows/process_windows.cpp
        src/platform/windows/firewall_windows.cpp
        src/platform/windows/sandbox_windows.cpp
        src/platform/windows/service_windows.cpp
        src/platform/windows/priv_client.cpp
    )
else()
    set(PLATFORM_SOURCES
        src/platform/linux/process_linux.cpp
        src/platform/linux/firewall_linux.cpp
        src/platform/linux/sandbox_linux.cpp
        src/platform/linux/service_linux.cpp
    )
endif()

add_library(mcp_bridge_core STATIC
    ${CORE_SOURCES}
    ${TOOL_SOURCES}
    ${PLATFORM_SOURCES}
)
# PUBLIC so include paths + transitive deps propagate to consumers (the daemon
# binary and the test executables).
target_include_directories(mcp_bridge_core PUBLIC
    ${CMAKE_SOURCE_DIR}/vendor
    ${CMAKE_SOURCE_DIR}/src
)
set_target_properties(mcp_bridge_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(WIN32)
    target_link_libraries(mcp_bridge_core PUBLIC ws2_32 iphlpapi advapi32)
else()
    target_link_libraries(mcp_bridge_core PUBLIC pthread)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(mcp_bridge_core PUBLIC stdc++fs)
endif()

if(ENABLE_SSL)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(mcp_bridge_core PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(mcp_bridge_core PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT)
endif()

if(ENABLE_MYSQL)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(MARIADB QUIET libmariadb)
    endif()
    if(MARIADB_FOUND)
        target_include_directories(mcp_bridge_core PUBLIC ${MARIADB_INCLUDE_DIRS})
        target_link_libraries(mcp_bridge_core PUBLIC ${MARIADB_LIBRARIES})
        target_compile_definitions(mcp_bridge_core PUBLIC HAS_MYSQL)
        message(STATUS "MySQL/MariaDB support: enabled")
    else()
        message(STATUS "MySQL/MariaDB support: CLI fallback only (libmariadb not found)")
    endif()
endif()

if(ENABLE_POSTGRES)
    find_package(PostgreSQL QUIET)
    if(PostgreSQL_FOUND)
        target_link_libraries(mcp_bridge_core PUBLIC PostgreSQL::PostgreSQL)
        target_compile_definitions(mcp_bridge_core PUBLIC HAS_POSTGRES)
        message(STATUS "PostgreSQL support: enabled")
    else()
        message(STATUS "PostgreSQL support: CLI fallback only (libpq not found)")
    endif()
endif()

if(MSVC)
    target_compile_options(mcp_bridge_core PRIVATE /W4)
else()
    target_compile_options(mcp_bridge_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ----- Daemon binary -----
add_executable(mcp_bridge src/main.cpp)
target_link_libraries(mcp_bridge PRIVATE mcp_bridge_core)
if(NOT WIN32)
    target_link_options(mcp_bridge PRIVATE -static-libgcc -static-libstdc++)
endif()

# ----- Privileged helper -----
# Linux: setuid C helper (mcp_bridge-priv).
# Windows: separate Service binary (mcp_bridge_priv.exe) that talks to the
#          daemon over a named pipe with an ACL gated on the daemon's SID.
if(NOT WIN32)
    add_executable(mcp_bridge-priv src/priv/main.c)
    set_target_properties(mcp_bridge-priv PROPERTIES C_STANDARD 11)
    target_compile_options(mcp_bridge-priv PRIVATE -Wall -Wextra -Wpedantic)
else()
    add_executable(mcp_bridge_priv
        src/priv_win/main.cpp
        src/priv_win/operations.cpp
        src/priv_win/audit.cpp
    )
    target_include_directories(mcp_bridge_priv PRIVATE
        ${CMAKE_SOURCE_DIR}/vendor
        ${CMAKE_SOURCE_DIR}/src
    )
    # Win32 libraries the priv service needs:
    #   advapi32 — LSA private data, RegisterEventSource, ACL, SetNamedSecurityInfo
    #   netapi32 — NetUserAdd / NetUserDel
    #   userenv  — CreateEnvironmentBlock / DestroyEnvironmentBlock
    #   secur32  — Lsa* import surface (some toolchains route through here)
    target_link_libraries(mcp_bridge_priv PRIVATE
        advapi32 netapi32 userenv secur32)
    if(MSVC)
        target_compile_options(mcp_bridge_priv PRIVATE /W4)
    else()
        target_compile_options(mcp_bridge_priv PRIVATE -Wall -Wextra)
    endif()
endif()

# ----- Tests -----
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
