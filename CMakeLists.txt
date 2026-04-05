cmake_minimum_required(VERSION 3.20)
project(server_mcp_bridge VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options
option(ENABLE_MYSQL "Enable MySQL/MariaDB support" ON)
option(ENABLE_POSTGRES "Enable PostgreSQL support" ON)
option(ENABLE_SSL "Enable HTTPS support" OFF)
option(BUILD_TESTS "Build tests" OFF)

# Collect sources
set(CORE_SOURCES
    src/main.cpp
    src/core/config.cpp
    src/core/server.cpp
    src/core/auth.cpp
    src/core/rate_limiter.cpp
    src/core/context.cpp
    src/core/logger.cpp
    src/registry/tool_registry.cpp
)

# Tool sources
set(TOOL_SOURCES
    src/tools/data/file_ops.cpp
    src/tools/data/database_ops.cpp
    src/tools/networking/port_ops.cpp
    src/tools/networking/firewall_ops.cpp
    src/tools/hosting/webserver_ops.cpp
    src/tools/hosting/process_mgmt.cpp
    src/tools/exec/command_ops.cpp
    src/tools/sandbox/sandbox_ops.cpp
)

# Platform sources
if(WIN32)
    set(PLATFORM_SOURCES
        src/platform/windows/process_windows.cpp
        src/platform/windows/firewall_windows.cpp
        src/platform/windows/sandbox_windows.cpp
        src/platform/windows/service_windows.cpp
    )
else()
    set(PLATFORM_SOURCES
        src/platform/linux/process_linux.cpp
        src/platform/linux/firewall_linux.cpp
        src/platform/linux/sandbox_linux.cpp
        src/platform/linux/service_linux.cpp
    )
endif()

add_executable(${PROJECT_NAME}
    ${CORE_SOURCES}
    ${TOOL_SOURCES}
    ${PLATFORM_SOURCES}
)

# Include paths
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/vendor
    ${CMAKE_SOURCE_DIR}/src
)

# Platform libraries
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 iphlpapi)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE pthread)
    # Static link libgcc/libstdc++ for portable binary
    target_link_options(${PROJECT_NAME} PRIVATE -static-libgcc -static-libstdc++)
endif()

# Filesystem (some compilers need explicit linkage)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9.0")
    target_link_libraries(${PROJECT_NAME} PRIVATE stdc++fs)
endif()

# Optional: OpenSSL for HTTPS
if(ENABLE_SSL)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(${PROJECT_NAME} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
endif()

# Optional: MySQL/MariaDB
if(ENABLE_MYSQL)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(MARIADB QUIET libmariadb)
    endif()
    if(MARIADB_FOUND)
        target_include_directories(${PROJECT_NAME} PRIVATE ${MARIADB_INCLUDE_DIRS})
        target_link_libraries(${PROJECT_NAME} PRIVATE ${MARIADB_LIBRARIES})
        target_compile_definitions(${PROJECT_NAME} PRIVATE HAS_MYSQL)
        message(STATUS "MySQL/MariaDB support: enabled")
    else()
        message(STATUS "MySQL/MariaDB support: CLI fallback only (libmariadb not found)")
    endif()
endif()

# Optional: PostgreSQL
if(ENABLE_POSTGRES)
    find_package(PostgreSQL QUIET)
    if(PostgreSQL_FOUND)
        target_link_libraries(${PROJECT_NAME} PRIVATE PostgreSQL::PostgreSQL)
        target_compile_definitions(${PROJECT_NAME} PRIVATE HAS_POSTGRES)
        message(STATUS "PostgreSQL support: enabled")
    else()
        message(STATUS "PostgreSQL support: CLI fallback only (libpq not found)")
    endif()
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
